//! Where the worker fetches from, and for which platform.
//!
//! A [`FeedSource`] is a base URL under which `delegation.json` and `manifest.json` live. The
//! [`channel_feed_ladder`] is tried in order (primary `updates.dig.net`, then the GitHub releases
//! fallback) — but the ladder is UNTRUSTED transport: whichever source responds, the signature is
//! the only gate (SPEC §1). Tests inject a local base pointing at a throwaway HTTP server,
//! exercising the exact same fetch/verify path.
//!
//! The ladder is derived from the beacon's tracked **channel** (SPEC §10.1): each channel is a
//! fully independent signed feed at `/v1/<channel>`, so a client tracking one channel never sees the
//! other's marks. The channel token (`"nightly"` / `"stable"`) is chosen by the broker from its
//! persisted config; this module only turns that token into the two-rung fetch ladder.

use serde::{Deserialize, Serialize};

/// The primary signed-feed HOST — per-channel feeds live under `{host}/<channel>` (SPEC §10.1).
/// Files: `{base}/delegation.json`, `{base}/manifest.json`.
pub const PRIMARY_FEED_HOST: &str = "https://updates.dig.net/v1";

/// The fallback signed-feed HOST — per-channel rolling GitHub releases `feed-<channel>` (SPEC
/// §10.1). The beacon fetches from the primary first, falling back here; both are untrusted
/// transport, so flipping which is preferred is a deploy detail, never a trust decision.
pub const FALLBACK_FEED_HOST: &str = "https://github.com/DIG-Network/dig-updater/releases/download";

/// One source of the signed feed: a base URL hosting `delegation.json` + `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSource {
    /// The base URL, without a trailing slash.
    pub base: String,
}

impl FeedSource {
    /// A feed source from a base URL, normalizing away any trailing slashes.
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        let mut base = base.into();
        while base.ends_with('/') {
            base.pop();
        }
        Self { base }
    }

    /// The signed-delegation URL for this source.
    #[must_use]
    pub fn delegation_url(&self) -> String {
        format!("{}/delegation.json", self.base)
    }

    /// The signed-manifest URL for this source.
    #[must_use]
    pub fn manifest_url(&self) -> String {
        format!("{}/manifest.json", self.base)
    }
}

/// The feed ladder for a tracked `channel` (SPEC §10.1, #591 D4): the primary
/// `updates.dig.net/v1/<channel>` first, the GitHub `feed-<channel>` release fallback second.
///
/// `channel` is the wire token (`"nightly"` / `"stable"`) — the broker passes its
/// [`Channel::as_str`](../../dig_updater_broker/config/enum.Channel.html) here, so the ladder always
/// points at the channel the beacon is configured to track. Both rungs are untrusted transport (the
/// signature is the gate, SPEC §1), so which one answers is a resilience detail.
#[must_use]
pub fn channel_feed_ladder(channel: &str) -> Vec<FeedSource> {
    vec![
        FeedSource::new(format!("{PRIMARY_FEED_HOST}/{channel}")),
        FeedSource::new(format!("{FALLBACK_FEED_HOST}/feed-{channel}")),
    ]
}

/// The OS/arch tokens (matching the manifest's `artifact.os` / `artifact.arch`) identifying the
/// artifacts relevant to this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// `windows` | `linux` | `macos`.
    pub os: String,
    /// `x64` | `arm64`.
    pub arch: String,
}

impl Platform {
    /// The platform this binary is running on, mapped to the manifest's token vocabulary.
    #[must_use]
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: normalize_arch(std::env::consts::ARCH),
        }
    }
}

/// Map Rust's `std::env::consts::ARCH` values to the manifest's arch tokens.
fn normalize_arch(arch: &str) -> String {
    match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_urls_derive_from_base() {
        let s = FeedSource::new("https://example.test/feed/");
        assert_eq!(s.base, "https://example.test/feed");
        assert_eq!(
            s.delegation_url(),
            "https://example.test/feed/delegation.json"
        );
        assert_eq!(s.manifest_url(), "https://example.test/feed/manifest.json");
    }

    #[test]
    fn channel_ladder_is_primary_then_fallback_at_the_channel_path() {
        // The nightly ladder points at /v1/nightly + the feed-nightly release; the stable ladder at
        // /v1/stable + feed-stable. This is what makes the tracked channel MEAN something (#591 D4).
        let nightly = channel_feed_ladder("nightly");
        assert_eq!(nightly[0].base, "https://updates.dig.net/v1/nightly");
        assert_eq!(
            nightly[1].base,
            "https://github.com/DIG-Network/dig-updater/releases/download/feed-nightly"
        );

        let stable = channel_feed_ladder("stable");
        assert_eq!(stable[0].base, "https://updates.dig.net/v1/stable");
        assert_eq!(
            stable[1].base,
            "https://github.com/DIG-Network/dig-updater/releases/download/feed-stable"
        );
    }

    #[test]
    fn arch_tokens_map_to_manifest_vocabulary() {
        assert_eq!(normalize_arch("x86_64"), "x64");
        assert_eq!(normalize_arch("aarch64"), "arm64");
        assert_eq!(normalize_arch("riscv64"), "riscv64");
    }

    #[test]
    fn current_platform_uses_known_os_token() {
        let p = Platform::current();
        assert!(matches!(p.os.as_str(), "windows" | "linux" | "macos"));
    }
}
