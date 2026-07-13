//! Mapping a GitHub release to the per-OS/arch artifacts of a component.
//!
//! The DIG release repos name their binary assets `{prefix}-{version}-{platform-token}` — e.g.
//! `dig-node-0.29.0-linux-x64`, `digstore-0.13.1-windows-x64.exe`. This module parses the release
//! JSON (from the GitHub REST API) and, for each platform the beacon supports, picks the asset
//! whose name is EXACTLY that shape. Exactness matters: a `digstore` release also ships
//! `digs-…` and `digstore-…-x86_64-unknown-linux-gnu.tar.gz`, and only the `{prefix}-{ver}-{token}`
//! binary is the artifact the beacon installs.
//!
//! This is all pure — it operates on already-fetched JSON — so it is exhaustively unit-testable.

use serde::Deserialize;

use crate::config::ComponentConfig;
use crate::error::FeedsignError;

/// The platforms the beacon ships to, as `(os, arch, asset-token)` where the OS/arch tokens match
/// the manifest's `artifact.os`/`artifact.arch` vocabulary (SPEC §5.3) and the asset-token is the
/// suffix the release assets use.
const PLATFORMS: &[(&str, &str, &str)] = &[
    ("linux", "x64", "linux-x64"),
    ("macos", "arm64", "macos-arm64"),
    ("macos", "x64", "macos-x64"),
    ("windows", "x64", "windows-x64.exe"),
];

/// A GitHub release, minimally deserialized: just its tag and assets.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubRelease {
    /// The release tag (e.g. `v0.29.0`).
    pub tag_name: String,
    /// The release's uploaded assets.
    #[serde(default)]
    pub assets: Vec<GithubAsset>,
}

/// One uploaded release asset: its file name and public download URL.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubAsset {
    /// The asset file name (e.g. `dig-node-0.29.0-linux-x64`).
    pub name: String,
    /// The public download URL — carried verbatim into the manifest as the (untrusted) artifact
    /// URL; only the SHA-256 authenticates the bytes (SPEC §1).
    pub browser_download_url: String,
}

impl GithubRelease {
    /// Parse a release from a GitHub REST API JSON response.
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Github`] if the JSON does not match the expected release shape.
    pub fn from_json(url: &str, json: &str) -> Result<Self, FeedsignError> {
        serde_json::from_str(json).map_err(|e| FeedsignError::Github {
            url: url.to_string(),
            detail: e.to_string(),
        })
    }

    /// The release version string with any leading `v` stripped, as it appears inside asset names
    /// (assets use `0.29.0`, the tag is `v0.29.0`).
    #[must_use]
    pub fn asset_version(&self) -> &str {
        self.tag_name.strip_prefix('v').unwrap_or(&self.tag_name)
    }
}

/// One resolved artifact before its bytes are fetched: the platform it targets and where to
/// download it. The digest + size are filled in after the bytes are downloaded and hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArtifact {
    /// OS token (`windows` | `linux` | `macos`).
    pub os: String,
    /// Arch token (`x64` | `arm64`).
    pub arch: String,
    /// The public download URL of the matching release asset.
    pub url: String,
}

/// Select the per-platform artifacts for `component` from `release`, matching each platform's
/// asset by its exact `{prefix}-{version}-{token}` name.
///
/// Returns every platform found (a component that dropped, say, `arm64` yields fewer). Missing a
/// specific platform is tolerated; resolving ZERO artifacts is an error (a misconfigured prefix or
/// a release with no binaries), so the feed fails closed rather than silently omitting a component.
///
/// # Errors
///
/// [`FeedsignError::NoArtifacts`] if no asset matches the component's expected name shape.
pub fn select_artifacts(
    release: &GithubRelease,
    component: &ComponentConfig,
) -> Result<Vec<ResolvedArtifact>, FeedsignError> {
    let version = release.asset_version();
    let mut artifacts = Vec::new();
    for (os, arch, token) in PLATFORMS {
        let expected = format!("{}-{}-{}", component.asset_prefix, version, token);
        if let Some(asset) = release.assets.iter().find(|a| a.name == expected) {
            artifacts.push(ResolvedArtifact {
                os: (*os).to_string(),
                arch: (*arch).to_string(),
                url: asset.browser_download_url.clone(),
            });
        }
    }
    if artifacts.is_empty() {
        return Err(FeedsignError::NoArtifacts {
            component: component.name.clone(),
            expected: format!("{}-{}-<platform>", component.asset_prefix, version),
        });
    }
    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component() -> ComponentConfig {
        ComponentConfig {
            name: "dig-node".into(),
            repo: "DIG-Network/dig-node".into(),
            asset_prefix: "dig-node".into(),
        }
    }

    fn asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: format!("https://example.test/{name}"),
        }
    }

    #[test]
    fn asset_version_strips_leading_v() {
        let r = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![],
        };
        assert_eq!(r.asset_version(), "0.29.0");
    }

    #[test]
    fn selects_all_four_platforms() {
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![
                asset("dig-node-0.29.0-linux-x64"),
                asset("dig-node-0.29.0-macos-arm64"),
                asset("dig-node-0.29.0-macos-x64"),
                asset("dig-node-0.29.0-windows-x64.exe"),
            ],
        };
        let arts = select_artifacts(&release, &component()).unwrap();
        assert_eq!(arts.len(), 4);
        assert_eq!(arts[0].os, "linux");
        assert_eq!(arts[0].arch, "x64");
        assert_eq!(
            arts[0].url,
            "https://example.test/dig-node-0.29.0-linux-x64"
        );
        assert!(arts.iter().any(|a| a.os == "windows"));
    }

    #[test]
    fn ignores_sibling_and_source_assets() {
        // A real digstore release: the `digstore-` binary plus a `digs-` companion and a
        // `.tar.gz` source bundle. Only the exact `{prefix}-{ver}-{token}` binaries match.
        let release = GithubRelease {
            tag_name: "v0.13.1".into(),
            assets: vec![
                asset("digstore-0.13.1-linux-x64"),
                asset("digs-0.13.1-linux-x64"),
                asset("digstore-0.13.1-x86_64-unknown-linux-gnu.tar.gz"),
            ],
        };
        let cfg = ComponentConfig {
            name: "digstore".into(),
            repo: "DIG-Network/digstore".into(),
            asset_prefix: "digstore".into(),
        };
        let arts = select_artifacts(&release, &cfg).unwrap();
        assert_eq!(arts.len(), 1);
        assert_eq!(
            arts[0].url,
            "https://example.test/digstore-0.13.1-linux-x64"
        );
    }

    #[test]
    fn tolerates_a_missing_platform() {
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![
                asset("dig-node-0.29.0-linux-x64"),
                asset("dig-node-0.29.0-windows-x64.exe"),
            ],
        };
        let arts = select_artifacts(&release, &component()).unwrap();
        assert_eq!(arts.len(), 2);
    }

    #[test]
    fn zero_matching_assets_is_an_error() {
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![asset("some-unrelated-file.zip")],
        };
        assert!(matches!(
            select_artifacts(&release, &component()),
            Err(FeedsignError::NoArtifacts { .. })
        ));
    }

    #[test]
    fn rejects_malformed_release_json() {
        assert!(matches!(
            GithubRelease::from_json("https://api/x", "{not json"),
            Err(FeedsignError::Github { .. })
        ));
    }
}
