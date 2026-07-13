//! [`WorkerError`] — the worker's failure taxonomy. Verification rejections pass through the
//! trust core's [`TrustError`] (so the whole catalogue of security rejections stays defined in
//! one place); the worker adds the failures unique to touching the network and the disk.

use dig_updater_trust::TrustError;

/// Everything that can stop the worker from returning a verified plan.
///
/// [`WorkerError::code`] yields a stable machine-classifiable string for each — delegating to
/// [`TrustError::code`] for security rejections — so the broker and logs branch on the reason
/// without parsing prose (§6.2).
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// No feed source in the ladder returned both a delegation and a manifest. This is a
    /// TRANSIENT failure (a frozen/unreachable feed), not a security rejection — the beacon
    /// retries on its next pass rather than acting.
    #[error("no feed source responded: {0}")]
    FeedUnavailable(String),
    /// A network error fetching a specific URL (also transient).
    #[error("network error fetching {url}: {detail}")]
    Fetch {
        /// The URL that failed.
        url: String,
        /// The underlying transport error.
        detail: String,
    },
    /// A download exceeded the hard size cap (`min(4 × advisory_size, 2 GiB)`) before its digest
    /// could be checked — a disk-fill DoS guard against a hostile CDN streaming unbounded bytes.
    #[error("artifact at {url} exceeded the {limit}-byte size cap")]
    ArtifactTooLarge {
        /// The offending artifact URL.
        url: String,
        /// The byte cap that was exceeded.
        limit: u64,
    },
    /// A staging-directory I/O error (create/write/remove).
    #[error("staging I/O error: {0}")]
    Io(String),
    /// A verification rejection from the trust core (bad signature, expired, replayed,
    /// downgraded, digest mismatch, malformed encoding, …). Fails closed.
    #[error(transparent)]
    Trust(#[from] TrustError),
}

impl WorkerError {
    /// A stable, machine-classifiable code for this failure. Security rejections reuse the trust
    /// core's codes so there is one authoritative catalogue.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::FeedUnavailable(_) => "feed_unavailable",
            Self::Fetch { .. } => "fetch_error",
            Self::ArtifactTooLarge { .. } => "artifact_too_large",
            Self::Io(_) => "staging_io_error",
            Self::Trust(e) => e.code(),
        }
    }

    /// Whether this failure is transient (a network/feed problem worth retrying next pass) as
    /// opposed to a hard security rejection or local error. The beacon never *acts* on either,
    /// but the distinction drives exit codes and retry policy.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::FeedUnavailable(_) | Self::Fetch { .. })
    }
}
