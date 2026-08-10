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

    /// A component resolved SOME but not all of its default platforms, and at least one missing
    /// `(os, arch)` pair was not declared exempt (dig_ecosystem#2343). Fails the feed closed so a
    /// partial release never publishes a GREEN feed that silently drops the missing-platform hosts —
    /// the generalization of the #2290 zero-asset outage, worse because nothing else goes red. The
    /// message names each undeclared-missing pair, derived from the same platform set the selector
    /// matched against.
    #[error(
        "component {component}: incomplete platform coverage — missing {missing} \
         with no exemption declared (dig_ecosystem#2343)"
    )]
    IncompleteArtifacts {
        /// The component name from the config.
        component: String,
        /// The `os/arch` pairs that were missing and not exempted, comma-joined.
        missing: String,
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
