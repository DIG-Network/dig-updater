//! The feed-signer's failure taxonomy. Every variant fails the CI run CLOSED — a feed is never
//! published on a partial or ambiguous result, so a signing/resolution problem stalls the feed
//! (which merely expires, per SPEC §7) rather than shipping a wrong one.

/// Everything that can stop the feed signer from producing a valid, byte-exact signed feed.
#[derive(Debug, thiserror::Error)]
pub enum FeedsignError {
    /// The feed configuration file was missing, unreadable, or not valid JSON.
    #[error("feed config: {0}")]
    Config(String),

    /// A component's version tag could not be parsed into `major.minor.patch`.
    #[error("version parse: {0}")]
    Version(String),

    /// The signing key material (the `BEACON_SIGNING_KEY` secret) could not be decoded into a
    /// 32-byte Ed25519 seed.
    #[error("signing key: {0}")]
    SigningKey(String),

    /// The signing key does NOT derive the pinned root public key, so signing would produce a feed
    /// no shipped beacon could verify. Fails closed rather than silently signing under a stray key.
    #[error("signing key does not match the pinned beacon root key (expected {expected})")]
    KeyNotPinned {
        /// The pinned root public key the derived key was checked against.
        expected: String,
    },

    /// A configured component resolved to a release with none of the expected per-OS/arch assets.
    #[error("component {component}: no matching release assets (looked for {expected})")]
    NoArtifacts {
        /// The component name from the config.
        component: String,
        /// The asset-name shape that was searched for.
        expected: String,
    },

    /// A network/transport error talking to GitHub (release metadata or an asset download).
    #[error("fetch {url}: {detail}")]
    Fetch {
        /// The URL being fetched.
        url: String,
        /// The underlying transport/HTTP error.
        detail: String,
    },

    /// A GitHub API response could not be parsed into the expected release shape.
    #[error("github response ({url}): {detail}")]
    Github {
        /// The URL whose response failed to parse.
        url: String,
        /// The parse error.
        detail: String,
    },

    /// A filesystem error writing the produced feed objects.
    #[error("io: {0}")]
    Io(String),

    /// A just-produced feed could not be reduced to its transparency-log inputs (§10, #533). This
    /// cannot happen for a feed this signer produced — it fails closed rather than panicking.
    #[error("transparency: {0}")]
    Transparency(String),

    /// A required input (the generated timestamp, output dir, or signing secret) was absent.
    #[error("missing input: {0}")]
    MissingInput(String),
}
