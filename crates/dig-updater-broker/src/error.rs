//! [`BrokerError`] — the privileged broker's failure taxonomy.

use dig_updater_trust::TrustError;

/// Everything that can go wrong while the broker orchestrates a pass. Verification rejections
/// pass through [`TrustError`]; the install/health-gate/rollback variants are reserved for the
/// follow-up tickets that land that behavior.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// The operation is intentionally not implemented yet. The payload names the operation and
    /// its follow-up ticket (install/health-gate/rollback = #504-E; scheduler = #504-F).
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
    /// A filesystem error (state dir, staging, current-exe resolution).
    #[error("i/o error: {0}")]
    Io(String),
    /// The persisted trust state was present but malformed. Fails closed rather than resetting
    /// the anti-rollback marks to zero (SPEC §6).
    #[error("persisted trust state is corrupt: {0}")]
    StateCorrupt(String),
    /// The worker process could not be spawned or communicated with.
    #[error("could not run the worker: {0}")]
    Spawn(String),
    /// The worker returned output the broker could not parse as a report.
    #[error("worker returned an unparseable report: {0}")]
    WorkerReportUnparseable(String),
    /// A verification rejection from the trust core (reserved for the install path).
    #[error(transparent)]
    Trust(#[from] TrustError),
}
