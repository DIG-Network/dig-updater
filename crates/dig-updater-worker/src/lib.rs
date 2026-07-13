#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # dig-updater-worker — the unprivileged fetch/verify worker (scaffold stub)
//!
//! The worker is the **unprivileged, sandboxed** half of the beacon. It is the only part
//! that touches the network: it downloads the signed delegation + manifest from
//! `updates.dig.net` and the per-artifact bytes from their (untrusted) URLs, and verifies
//! every one of them against [`dig_updater_trust`] before handing a verified plan back to
//! the privileged [broker](../dig_updater_broker/). It holds NO privilege to install or
//! replace anything, so a compromise of this network-facing code cannot escalate.
//!
//! This crate is a **stub**: the fetch/verify pipeline lands in #504-D. Operations return
//! [`WorkerError::Unimplemented`] so the surface is callable now.

use dig_updater_trust::TrustError;

/// Errors the worker can surface. During the scaffold phase the only variants are the
/// documented [`WorkerError::Unimplemented`] stubs and a pass-through of a [`TrustError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkerError {
    /// The operation is intentionally not implemented yet in the scaffold. The payload
    /// names the operation and its follow-up ticket.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
    /// A fetched artifact failed the trust core's verification. (Reserved for the real
    /// pipeline; the worker rejects and reports rather than passing it to the broker.)
    #[error(transparent)]
    Trust(#[from] TrustError),
}

/// The unprivileged fetch/verify worker.
#[derive(Debug, Default, Clone, Copy)]
pub struct Worker;

impl Worker {
    /// Create a new worker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Fetch the signed delegation + manifest, verify the trust chain, download each
    /// artifact, and verify its digest — returning a verified plan the broker can install.
    ///
    /// Stub — the fetch/verify pipeline lands in #504-D.
    pub fn fetch_and_verify(&self) -> Result<(), WorkerError> {
        Err(WorkerError::Unimplemented(
            "worker.fetch_and_verify (#504-D)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_and_verify_is_unimplemented_stub() {
        assert!(matches!(
            Worker::new().fetch_and_verify(),
            Err(WorkerError::Unimplemented(_))
        ));
    }

    #[test]
    fn trust_error_converts_into_worker_error() {
        let e: WorkerError = TrustError::ManifestSignatureInvalid.into();
        assert!(matches!(e, WorkerError::Trust(_)));
    }

    #[test]
    fn worker_constructs() {
        let _ = Worker;
    }
}
