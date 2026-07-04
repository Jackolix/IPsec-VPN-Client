//! Windows Service Control Manager glue. Registers a control handler, reports
//! state transitions, and drives the [`Broker`] between start and stop.

use crate::protocol::SERVICE_NAME;
use crate::supervisor::{self, Broker};
use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM. Blocks until the service stops; only returns an
/// error if we weren't actually launched by the SCM.
pub fn run() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        supervisor::log(&format!("service exited with error: {e}"));
    }
}

fn run_service() -> Result<(), String> {
    let broker = Broker::new();

    // The control handler runs on an SCM thread; it just signals the main
    // service thread to begin shutdown.
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle =
        service_control_handler::register(SERVICE_NAME, event_handler).map_err(|e| e.to_string())?;

    let set = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        })
    };

    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
    )
    .map_err(|e| e.to_string())?;

    if let Err(e) = broker.start() {
        supervisor::log(&format!("broker start failed: {e}"));
    }

    // Block until the SCM asks us to stop.
    let _ = shutdown_rx.recv();

    set(ServiceState::StopPending, ServiceControlAccept::empty(), Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    broker.shutdown();

    set(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::default())
        .map_err(|e| e.to_string())?;
    Ok(())
}
