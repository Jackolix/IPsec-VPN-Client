//! Install / uninstall the broker as a Windows service. Runs elevated once (at
//! app install/uninstall time), so the per-connect flow never needs a UAC
//! prompt again. Registered as auto-start LocalSystem, so charon and the DNS
//! IPC are available from boot.

use crate::protocol::{SERVICE_DISPLAY_NAME, SERVICE_NAME};
use std::ffi::OsString;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

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
        executable_path: exe,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None, // None == LocalSystem
        account_password: None,
    };

    let service = match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START) {
        Ok(svc) => svc,
        // Already installed (e.g. an upgrade over an existing install): reuse it.
        Err(_) => manager
            .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
            .map_err(|e| format!("service exists but can't be opened: {e}"))?,
    };
    let _ = service.set_description("Supervises charon-svc and applies VPN DNS for the IPsec VPN client.");

    // Start now so no reboot is needed.
    let empty: [OsString; 0] = [];
    if let Err(e) = service.start(&empty) {
        // A benign race: it may already be running.
        return Err(format!("service installed but failed to start: {e}"));
    }
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

    // Ask it to stop and wait briefly so its shutdown (DNS revert, charon kill)
    // actually runs before the service object is deleted.
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                match service.query_status() {
                    Ok(s) if s.current_state == ServiceState::Stopped => break,
                    _ => std::thread::sleep(Duration::from_millis(300)),
                }
            }
        }
    }

    service.delete().map_err(|e| format!("delete service: {e}"))
}
