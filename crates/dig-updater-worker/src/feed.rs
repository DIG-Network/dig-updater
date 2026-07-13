//! Where the worker fetches from, and for which platform.
//!
//! A [`FeedSource`] is a base URL under which `delegation.json` and `manifest.json` live. The
//! [`production_feed_ladder`] is tried in order (primary `updates.dig.net`, then the GitHub
//! releases fallback) — but the ladder is UNTRUSTED transport: whichever source responds, the
//! signature is the only gate (SPEC §1). Tests inject a local base pointing at a throwaway HTTP
//! server, exercising the exact same fetch/verify path.

use serde::{Deserialize, Serialize};

/// The primary signed-feed base. Files: `{base}/delegation.json`, `{base}/manifest.json`.
pub const PRIMARY_FEED_BASE: &str = "https://updates.dig.net/v1/alpha";

/// The fallback signed-feed base — a rolling GitHub release. The beacon ships pointing here
/// until `updates.dig.net` is stood up (per the #504 build plan); flipping the primary is a
/// deploy-time change, not a code change, because both are untrusted transport.
pub const FALLBACK_FEED_BASE: &str =
    "https://github.com/DIG-Network/dig-updater/releases/download/feed";

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

/// The production feed ladder: the primary source first, the GitHub fallback second.
#[must_use]
pub fn production_feed_ladder() -> Vec<FeedSource> {
    vec![
        FeedSource::new(PRIMARY_FEED_BASE),
        FeedSource::new(FALLBACK_FEED_BASE),
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
    fn production_ladder_is_primary_then_fallback() {
        let ladder = production_feed_ladder();
        assert_eq!(ladder[0].base, PRIMARY_FEED_BASE);
        assert_eq!(ladder[1].base, FALLBACK_FEED_BASE);
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
