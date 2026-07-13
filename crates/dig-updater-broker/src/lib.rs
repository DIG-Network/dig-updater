#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # dig-updater-broker — the privileged broker (scaffold stub)
//!
//! The broker is the **privileged** half of the beacon's two-process split. It runs with
//! the rights needed to replace on-disk binaries and (re)configure OS services, but it does
//! NOT touch the network: it spawns the unprivileged [worker](../dig_updater_worker/) to
//! fetch and verify, receives only verified artifacts + a verified plan back, then applies
//! installs behind a health gate and rolls back on failure.
//!
//! This crate is currently a **stub**: the trust types it will orchestrate live in
//! [`dig_updater_trust`], but the enumerate → install → health-gate → rollback pipeline and
//! the scheduler/lock/self-update are separate tickets (#504-E, #504-F). Every operation
//! returns [`BrokerError::Unimplemented`] so the surface is wired and callable now while the
//! behavior lands later.

use dig_updater_trust::TrustError;

/// Errors the broker can surface. During the scaffold phase the only variants are the
/// documented [`BrokerError::Unimplemented`] stubs and a pass-through of a
/// [`TrustError`] from the trust core.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// The operation is intentionally not implemented yet in the scaffold. The payload
    /// names the operation (e.g. `"broker.run_once"`) and its follow-up ticket.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
    /// An update failed the trust core's verification. (Reserved for the real pipeline.)
    #[error(transparent)]
    Trust(#[from] TrustError),
}

/// The privileged orchestrator. Constructed once per beacon pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct Broker;

impl Broker {
    /// Create a new broker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Run exactly one update pass: acquire the single-instance lock, load trust state,
    /// drive the worker to fetch+verify the feed, apply verified installs behind a health
    /// gate, roll back on failure, persist advanced trust state, and exit.
    ///
    /// Stub — the pipeline lands in #504-E / #504-F.
    pub fn run_once(&self) -> Result<(), BrokerError> {
        Err(BrokerError::Unimplemented(
            "broker.run_once (#504-E/#504-F)",
        ))
    }

    /// Roll the fleet back to the last known-good, re-verified build after a failed
    /// health gate.
    ///
    /// Stub — health-gated rollback lands in #504-E.
    pub fn rollback(&self) -> Result<(), BrokerError> {
        Err(BrokerError::Unimplemented("broker.rollback (#504-E)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_once_is_unimplemented_stub() {
        assert!(matches!(
            Broker::new().run_once(),
            Err(BrokerError::Unimplemented(_))
        ));
    }

    #[test]
    fn rollback_is_unimplemented_stub() {
        assert!(matches!(
            Broker::new().rollback(),
            Err(BrokerError::Unimplemented(_))
        ));
    }

    #[test]
    fn trust_error_converts_into_broker_error() {
        let e: BrokerError = TrustError::DelegationSignatureInvalid.into();
        assert!(matches!(e, BrokerError::Trust(_)));
        assert!(e.to_string().contains("delegation"));
    }
}
