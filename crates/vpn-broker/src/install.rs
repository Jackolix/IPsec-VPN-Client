//! Install / uninstall the broker as a Windows service. Runs elevated once (at
//! app install/uninstall time), so the per-connect flow never needs a UAC
//! prompt again. Registered as auto-start LocalSystem, so charon and the DNS
//! IPC are available from boot.

use crate::protocol::{SERVICE_DISPLAY_NAME, SERVICE_NAME};
use std::ffi::OsString;
use std::time::{Duration, Instant};
use windows_service::service::{
    Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// `StartService` when the service is already up. Registering over a running
/// service is the normal upgrade case, not a failure.
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;

pub fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own exe: {e}"))?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("open SCM: {e}"))?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None, // None == LocalSystem
        account_password: None,
    };

    let access = ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP;

    let (service, existed) = match manager.create_service(&info, access) {
        Ok(svc) => (svc, false),
        // Already installed (e.g. an upgrade over an existing install): reuse it.
        Err(_) => (
            manager
                .open_service(SERVICE_NAME, access)
                .map_err(|e| format!("cannot create or open the service: {e}"))?,
            true,
        ),
    };
    let _ = service
        .set_description("Supervises charon-svc and applies VPN DNS for the IPsec VPN client.");

    // A pre-existing service may still point at a *different* install directory:
    // the service is keyed by name, but the installer keys the install by product
    // name, so the 2026-08 "IPsec VPN Client" -> "VPN Client" rename left machines
    // with the service running the old directory's binary while the app ran from
    // the new one. Repoint it here so registering is idempotent no matter which
    // directory the previous install used (the NSIS hook removes the old install,
    // but the MSI has no such hook, and a half-finished migration lands here too).
    if existed && !points_at(&service, &exe) {
        // The old binary is what is currently running, so stop it before
        // rewriting the config — otherwise the repoint only takes effect at the
        // next reboot, and the old process keeps holding its pipe and charon.
        stop_and_wait(&service, Duration::from_secs(15));
        service
            .change_config(&info)
            .map_err(|e| format!("cannot repoint the existing service at {exe:?}: {e}"))?;
    }

    // Start now so no reboot is needed.
    match service.query_status().map(|s| s.current_state) {
        Ok(ServiceState::Running) | Ok(ServiceState::StartPending) => return Ok(()),
        // Mid-shutdown (ours, above, or someone else's): let it land first.
        Ok(ServiceState::StopPending) => {
            wait_for_stop(&service, Duration::from_secs(15));
        }
        _ => {}
    }
    let empty: [OsString; 0] = [];
    match service.start(&empty) {
        Ok(()) => Ok(()),
        // A benign race: it may already be running.
        Err(e) if is_os_error(&e, ERROR_SERVICE_ALREADY_RUNNING) => Ok(()),
        Err(e) => Err(format!("service installed but failed to start: {e}")),
    }
}

/// Stop the service and wait for it to actually reach Stopped, without removing
/// it. Used by the installer's pre-install hook: an upgrade has to overwrite
/// `vpn-broker.exe` (and the charon files), which the running service holds a
/// lock on, so it must be stopped first — but the service definition is kept, so
/// the post-install `install` just starts it again against the new binary.
///
/// A missing service (fresh install) is success — there is nothing to stop.
pub fn stop() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("open SCM: {e}"))?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(svc) => svc,
        Err(_) => return Ok(()),
    };

    stop_and_wait(&service, Duration::from_secs(15));
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("open SCM: {e}"))?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(svc) => svc,
        // Not installed — nothing to do.
        Err(_) => return Ok(()),
    };

    stop_and_wait(&service, Duration::from_secs(10));
    service.delete().map_err(|e| format!("delete service: {e}"))
}

/// Whether the registered service actually launches `exe`. The configured
/// command line is the raw `lpBinaryPathName` — `"C:\...\vpn-broker.exe" run` —
/// so this is a containment check rather than a path comparison.
fn points_at(service: &Service, exe: &std::path::Path) -> bool {
    match service.query_config() {
        Ok(cfg) => cfg
            .executable_path
            .to_string_lossy()
            .to_lowercase()
            .contains(&exe.to_string_lossy().to_lowercase()),
        // Can't tell: assume it needs repointing, which is a no-op if it didn't.
        Err(_) => false,
    }
}

/// Ask the service to stop and wait so its shutdown (DNS revert, charon kill,
/// SSL teardown) runs and the file locks are released before the caller
/// overwrites or deletes anything.
fn stop_and_wait(service: &Service, timeout: Duration) {
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            wait_for_stop(service, timeout);
        }
    }
}

fn wait_for_stop(service: &Service, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match service.query_status() {
            Ok(s) if s.current_state == ServiceState::Stopped => break,
            _ => std::thread::sleep(Duration::from_millis(300)),
        }
    }
}

fn is_os_error(err: &windows_service::Error, code: i32) -> bool {
    matches!(err, windows_service::Error::Winapi(e) if e.raw_os_error() == Some(code))
}
