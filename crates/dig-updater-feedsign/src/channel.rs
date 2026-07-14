//! The update CHANNEL a feed run targets.
//!
//! The beacon publishes TWO fully independent signed feeds, one per channel, at distinct paths —
//! `updates.dig.net/v1/stable/` and `updates.dig.net/v1/nightly/` (SPEC §10.1). Both are signed
//! under the SAME root/targets key, but each carries its OWN freshness (`generated`/`expires`) and
//! anti-rollback (`sequence`/floor) marks, so a channel's monotonic trust state can never rewind
//! the other's (#591 D1/D5). This module is the single place that names a channel and decides the
//! three — and only three — things a channel changes:
//!
//! 1. **which GitHub release** supplies each component's build ([`Channel::release_path`]),
//! 2. **how the component `build` number is scaled** (packed semver vs the UTC build date), and
//! 3. **which per-channel anti-rollback floor** applies ([`crate::FeedConfig::floor_for`]).
//!
//! Everything else about a feed — the schema, root version, the component set, the freshness
//! windows, the signing key — is channel-agnostic and shared.

use crate::error::FeedsignError;

/// One of the beacon's two update channels. Each is a fully independent signed feed (SPEC §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Tested `vX.Y.Z` releases: the newest NON-prerelease GitHub release (`releases/latest`). A
    /// component's `build` is the packed monotonic semver `major·10⁶ + minor·10³ + patch`.
    Stable,
    /// Bleeding-edge builds from `main` HEAD: the rolling `nightly` GitHub release
    /// (`releases/tags/nightly`, #590). A component's version is the prerelease string
    /// `X.Y.Z-nightly.YYYYMMDD.<sha>` and its `build` is the UTC build date `YYYYMMDD` — strictly
    /// increasing day-over-day, exactly the "never install an older nightly" semantic (#591 D5).
    Nightly,
}

impl Channel {
    /// The channel token as it appears on the feed path (`/v1/{token}/`), in `feed-config.json`,
    /// and as the `--channel` argument value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Nightly => "nightly",
        }
    }

    /// The `owner/repo`-relative GitHub REST path whose release supplies a component's build for
    /// this channel: `releases/latest` for stable, `releases/tags/nightly` for nightly.
    #[must_use]
    pub fn release_path(self) -> &'static str {
        match self {
            Channel::Stable => "releases/latest",
            Channel::Nightly => "releases/tags/nightly",
        }
    }

    /// Parse the `--channel` token. Only `stable` and `nightly` are valid — the two feeds this
    /// signer produces; the beacon-side `alpha` alias is a separate concern (#604).
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Config`] if the token is neither `stable` nor `nightly`.
    pub fn from_token(token: &str) -> Result<Self, FeedsignError> {
        match token.trim().to_ascii_lowercase().as_str() {
            "stable" => Ok(Channel::Stable),
            "nightly" => Ok(Channel::Nightly),
            other => Err(FeedsignError::Config(format!(
                "unknown channel {other:?} (expected `stable` or `nightly`)"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip() {
        assert_eq!(Channel::from_token("stable").unwrap(), Channel::Stable);
        assert_eq!(Channel::from_token("nightly").unwrap(), Channel::Nightly);
        assert_eq!(Channel::Stable.as_str(), "stable");
        assert_eq!(Channel::Nightly.as_str(), "nightly");
    }

    #[test]
    fn token_parse_is_case_and_whitespace_insensitive() {
        assert_eq!(Channel::from_token("  STABLE ").unwrap(), Channel::Stable);
        assert_eq!(Channel::from_token("Nightly").unwrap(), Channel::Nightly);
    }

    #[test]
    fn unknown_token_is_a_config_error() {
        // `alpha` is intentionally NOT a feedsign channel — the two produced feeds are the only
        // valid tokens; the alpha->nightly alias lives on the beacon (#604).
        assert!(matches!(
            Channel::from_token("alpha"),
            Err(FeedsignError::Config(_))
        ));
        assert!(matches!(
            Channel::from_token("beta"),
            Err(FeedsignError::Config(_))
        ));
    }

    #[test]
    fn release_path_selects_the_channel_endpoint() {
        assert_eq!(Channel::Stable.release_path(), "releases/latest");
        assert_eq!(Channel::Nightly.release_path(), "releases/tags/nightly");
    }
}
