#![warn(missing_docs)]

//! # dig-updater-broker — the privileged broker
//!
//! The broker is the **privileged** half of the beacon's two-process split (SPEC §8.3). It holds
//! the rights to persist the Admin/SYSTEM-only trust state and (in follow-ups) to replace on-disk
//! binaries, but it does NOT touch the network. Instead it spawns the **unprivileged**
//! [`dig_updater_worker`] to fetch + verify, receives only a verified plan back, and — in the
//! install path (#504-E) — applies installs behind a health gate and rolls back on failure.
//!
//! This crate implements the -D surface: loading the persisted trust state, spawning the worker
//! with dropped privileges ([`sandbox`]), and a **dry check** ([`Broker::dry_check`]) that
//! verifies without installing and NEVER advances the trust state. The install / health-gate /
//! rollback pipeline (#504-E) and the scheduler / self-update (#504-F) are separate tickets;
//! their entry points remain explicit `Unimplemented` stubs.
//!
//! ## The one `unsafe` in the workspace
//!
//! Privilege-dropping needs OS primitives, so [`sandbox`] is the single module that uses
//! `unsafe` (Unix `setuid`/`setgid`; Windows restricted-token spawn). Every other module — and
//! every other crate — is safe.

mod error;
pub mod paths;
pub mod sandbox;
pub mod secure;
mod spawn;
pub mod state;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dig_updater_worker::{FeedSource, Platform, WorkerReport, WorkerRequest};

pub use error::BrokerError;
pub use sandbox::Sandbox;
pub use spawn::spawn_worker;
pub use state::{LoadedState, TrustStateStore};

/// The privileged orchestrator. Constructed once per beacon pass.
#[derive(Debug, Clone)]
pub struct Broker {
    state_dir: PathBuf,
    worker_path: PathBuf,
}

impl Broker {
    /// A broker using the default OS state directory and the sibling worker binary.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the worker binary path cannot be resolved.
    pub fn new() -> Result<Self, BrokerError> {
        Ok(Self {
            state_dir: paths::default_state_dir(),
            worker_path: paths::sibling_worker_binary()?,
        })
    }

    /// A broker with explicit paths — used by tests and custom deployments.
    #[must_use]
    pub fn with_paths(state_dir: PathBuf, worker_path: PathBuf) -> Self {
        Self {
            state_dir,
            worker_path,
        }
    }

    /// The state directory this broker reads/writes.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Run a **dry** update check: load the persisted trust state, spawn the unprivileged worker
    /// to fetch + verify the feed and stage the artifacts, and return its report. This performs
    /// NO install and NEVER advances the trust state (SPEC §9 step 7 gates advancement on a
    /// health-checked install, which is #504-E).
    ///
    /// # Errors
    ///
    /// [`BrokerError`] if the state cannot be loaded or the worker cannot be run.
    pub fn dry_check(&self, feed_sources: Vec<FeedSource>) -> Result<WorkerReport, BrokerError> {
        let loaded = TrustStateStore::at(&self.state_dir).load()?;
        let staging_dir = self.staging_dir();
        let request = WorkerRequest {
            feed_sources,
            trust_state: loaded.state,
            now: now_unix_secs(),
            staging_dir: staging_dir.to_string_lossy().into_owned(),
            platform: Platform::current(),
        };
        spawn_worker(&self.worker_path, &request, Sandbox::Restricted)
    }

    /// A per-invocation staging directory under the system temp dir. The unprivileged worker
    /// creates + writes it (the system temp is writable by the dropped identity); the broker
    /// reads verified artifacts from it in the install path.
    fn staging_dir(&self) -> PathBuf {
        std::env::temp_dir().join(format!("dig-updater-staging-{}", std::process::id()))
    }

    /// Run exactly one FULL update pass (verify → install → health-gate → advance state).
    ///
    /// Stub — the install/health-gate/rollback pipeline lands in #504-E.
    ///
    /// # Errors
    ///
    /// Always [`BrokerError::Unimplemented`] until #504-E.
    pub fn run_once(&self) -> Result<(), BrokerError> {
        Err(BrokerError::Unimplemented(
            "broker.run_once (#504-E/#504-F)",
        ))
    }

    /// Roll the fleet back to the last known-good, re-verified build after a failed health gate.
    ///
    /// Stub — health-gated rollback lands in #504-E.
    ///
    /// # Errors
    ///
    /// Always [`BrokerError::Unimplemented`] until #504-E.
    pub fn rollback(&self) -> Result<(), BrokerError> {
        Err(BrokerError::Unimplemented("broker.rollback (#504-E)"))
    }
}

/// The current wall-clock time as unix seconds (0 if the clock is before the epoch).
#[must_use]
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_once_is_unimplemented_stub() {
        let broker = Broker::with_paths(PathBuf::from("."), PathBuf::from("x"));
        assert!(matches!(
            broker.run_once(),
            Err(BrokerError::Unimplemented(_))
        ));
    }

    #[test]
    fn rollback_is_unimplemented_stub() {
        let broker = Broker::with_paths(PathBuf::from("."), PathBuf::from("x"));
        assert!(matches!(
            broker.rollback(),
            Err(BrokerError::Unimplemented(_))
        ));
    }

    #[test]
    fn trust_error_converts_into_broker_error() {
        use dig_updater_trust::TrustError;
        let e: BrokerError = TrustError::DelegationSignatureInvalid.into();
        assert!(matches!(e, BrokerError::Trust(_)));
        assert!(e.to_string().contains("delegation"));
    }

    #[test]
    fn now_is_after_2020() {
        assert!(now_unix_secs() > 1_577_836_800); // 2020-01-01
    }
}
