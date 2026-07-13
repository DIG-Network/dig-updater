//! The typed broker→worker call: serialize a [`WorkerRequest`], run the worker in the requested
//! [`Sandbox`], and parse its [`WorkerReport`] back. This is the safe surface over
//! [`crate::sandbox`] (which holds the OS `unsafe`).

use std::path::Path;

use dig_updater_worker::{WorkerReport, WorkerRequest};

use crate::error::BrokerError;
use crate::sandbox::{spawn_worker_process, Sandbox};

/// Spawn the worker for `request` under `sandbox`, returning its parsed [`WorkerReport`].
///
/// The worker prints exactly one JSON report on stdout whether it verified or rejected, so a
/// clean exit and a parseable report are the norm; a failure to spawn/parse is a
/// [`BrokerError`]. The broker never trusts the worker to have verified on the install path —
/// re-verification before install is the -E broker's job — but for a dry check the report is the
/// result.
///
/// # Errors
///
/// [`BrokerError::Spawn`] if the worker cannot be run; [`BrokerError::WorkerReportUnparseable`]
/// if its stdout is not a valid report.
pub fn spawn_worker(
    worker_path: &Path,
    request: &WorkerRequest,
    sandbox: Sandbox,
) -> Result<WorkerReport, BrokerError> {
    let input = serde_json::to_vec(request).map_err(|e| BrokerError::Io(e.to_string()))?;
    let (_code, stdout) = spawn_worker_process(worker_path, &input, sandbox)?;
    serde_json::from_slice(&stdout).map_err(|e| {
        BrokerError::WorkerReportUnparseable(format!(
            "{e}; stdout was: {}",
            String::from_utf8_lossy(&stdout).trim()
        ))
    })
}
