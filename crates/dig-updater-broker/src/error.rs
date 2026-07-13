//! [`BrokerError`] — the privileged broker's failure taxonomy.

use dig_updater_trust::TrustError;

/// Everything that can go wrong while the broker orchestrates a pass. Verification rejections
/// pass through [`TrustError`]; the install/health-gate/rollback variants are reserved for the
/// follow-up tickets that land that behavior.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// The operation is intentionally not implemented yet. The payload names the operation and
    /// its follow-up ticket (scheduler = #504-F).
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
    /// A guarded path (the beacon binary, the state dir, the staging dir, …) is writable by a
    /// non-privileged identity and could not be repaired. The pass ABORTS fail-closed rather than
    /// installing while an unprivileged process could tamper with what is installed (SPEC §8.3,
    /// §9.3).
    #[error("ACL self-check failed for {path}: {detail}")]
    AclViolation {
        /// The offending path.
        path: String,
        /// Why it is not acceptably locked down (and could not be repaired).
        detail: String,
    },
    /// The plan the worker returned did NOT survive the broker's INDEPENDENT re-verification under
    /// its own pinned root key. A well-behaved worker never triggers this; it means the worker is
    /// compromised or buggy, so the pass aborts and installs nothing (SPEC §8.3).
    #[error("worker plan failed the broker's independent re-verification: {0}")]
    ReverifyFailed(String),
    /// A staged artifact's bytes did not match the digest in the RE-VERIFIED manifest at install
    /// time — a TOCTOU swap since the worker staged it, or a lying worker. Nothing is installed
    /// (SPEC §8.3 staging re-verify).
    #[error("staged artifact for {component} failed re-verification: {detail}")]
    StagingReverifyFailed {
        /// The component whose staged bytes failed.
        component: String,
        /// The digest-mismatch detail.
        detail: String,
    },
    /// The worker reported a staged path that does NOT resolve strictly inside the broker-owned
    /// staging directory (an absolute path elsewhere like `/tmp/evil`, or a `..` escape). The
    /// worker is untrusted (SPEC §8.3), so the broker refuses to hash or install a path it does
    /// not control, and the pass aborts fail-closed BEFORE the bytes are ever read.
    #[error("staged path for {component} escapes the staging directory: {detail}")]
    StagedPathEscapesStaging {
        /// The component whose staged path was rejected.
        component: String,
        /// Why the path was rejected (outside staging, un-canonicalizable, …).
        detail: String,
    },
    /// The re-verified manifest names a platform artifact the worker did not stage — the plan is
    /// structurally incomplete, so the pass aborts rather than installing a partial update.
    #[error("no staged artifact for {component} ({os}-{arch})")]
    StagedArtifactMissing {
        /// The component missing a staged artifact.
        component: String,
        /// The requested OS token.
        os: String,
        /// The requested arch token.
        arch: String,
    },
    /// A rollback itself failed — the worst case: the component may be left in a broken state and
    /// needs operator attention. Distinct from a *health* failure (which a rollback recovers).
    #[error("rollback failed for {component}: {detail}")]
    RollbackFailed {
        /// The component whose rollback failed.
        component: String,
        /// Why the rollback could not complete (e.g. the cached bytes failed re-verification, or
        /// the only rollback target is below the current floor).
        detail: String,
    },
    /// A verification rejection from the trust core.
    #[error(transparent)]
    Trust(#[from] TrustError),
}
