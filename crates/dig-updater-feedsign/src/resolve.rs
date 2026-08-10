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

use crate::config::{AssetKind, ComponentConfig, VariantSpec};
use crate::error::FeedsignError;

/// The `(os, arch)` platforms the beacon ships to, matching the manifest's `artifact.os`/
/// `artifact.arch` vocabulary (SPEC §5.3). The exact asset FILE NAME each platform maps to depends
/// on the component's [`AssetKind`] — see [`expected_asset_name`].
const PLATFORMS: &[(&str, &str)] = &[
    ("linux", "x64"),
    ("linux", "arm64"),
    ("macos", "arm64"),
    ("macos", "x64"),
    ("windows", "x64"),
];

/// The fixed `(head, tail)` that a component of `kind` wraps its version in, for `(os, arch)`: an
/// asset's name is always `{head}{version}{tail}`.
///
/// The DIG release repos name assets by two conventions, and the feed MUST select the one the
/// broker will actually install (#580):
///
/// - **[`AssetKind::RawBinary`]** — `{prefix}-{version}-{os}-{arch}`, with `.exe` on Windows (e.g.
///   `digstore-0.13.1-windows-x64.exe`, `dig-node-0.31.1-linux-x64`).
/// - **[`AssetKind::NativePackage`]** — the platform installer's native name:
///   - Windows `.msi`: `{prefix}-{version}-{os}-{arch}.msi` (`dig-node-0.31.1-windows-x64.msi`);
///   - macOS `.pkg`: `{prefix}-{version}-macos.pkg` — ONE universal package, no arch token, so both
///     `macos/arm64` and `macos/x64` resolve to it;
///   - Linux `.deb`: `{prefix}_{version}_{deb_arch}.deb` — the Debian convention (underscores, the
///     ARCH token not the OS token, no `linux` token), e.g. `dig-node_0.31.1_amd64.deb` for x64 and
///     `dig-node_0.31.1_arm64.deb` for arm64.
///
/// Factoring the name into a `head` before the version and a `tail` after it lets BOTH directions
/// reuse one source of truth: [`expected_asset_name`] builds the name (stable, whose version comes
/// from the release tag), and [`resolve_version_from_assets`] RECOVERS the version (nightly, whose
/// version is not in the `nightly` tag but is embedded in the asset file names, #590).
///
/// Any `(os, arch)` outside the fixed [`PLATFORMS`] set falls back to the raw-binary shape; the set
/// is a compile-time constant, so that arm is unreachable in practice and exists only for totality.
fn asset_name_parts(prefix: &str, os: &str, arch: &str, kind: AssetKind) -> (String, String) {
    match (kind, os) {
        (AssetKind::NativePackage, "windows") => {
            (format!("{prefix}-"), format!("-{os}-{arch}.msi"))
        }
        (AssetKind::NativePackage, "macos") => (format!("{prefix}-"), "-macos.pkg".to_string()),
        (AssetKind::NativePackage, "linux") => {
            // Debian names the arch, not the OS: `amd64` for x64, `arm64` for arm64.
            let deb_arch = if arch == "arm64" { "arm64" } else { "amd64" };
            (format!("{prefix}_"), format!("_{deb_arch}.deb"))
        }
        (_, "windows") => (format!("{prefix}-"), format!("-{os}-{arch}.exe")),
        _ => (format!("{prefix}-"), format!("-{os}-{arch}")),
    }
}

/// The exact release-asset file name a component of `kind` publishes for `(os, arch)` at `version`.
fn expected_asset_name(
    prefix: &str,
    version: &str,
    os: &str,
    arch: &str,
    kind: AssetKind,
) -> String {
    let (head, tail) = asset_name_parts(prefix, os, arch, kind);
    format!("{head}{version}{tail}")
}

/// Every DISTINCT asset file name a component of `kind` publishes at `version`, in [`PLATFORMS`]
/// order — i.e. exactly the set [`select_artifacts`] matches against, and therefore the honest
/// answer to "what did the feed look for?".
///
/// Derived from the matcher itself rather than described by hand, so a diagnostic can never claim a
/// shape the selector does not use: for three weeks the `NoArtifacts` error named the RAW-BINARY
/// shape for a `native_package` component, and triage concluded the assets were misnamed when they
/// were simply absent (dig_ecosystem#618).
///
/// Each platform contributes its DEFAULT asset name followed by one name per declared `variant`
/// (`{default}{suffix}`) — both families, in the order [`select_artifacts`] tries them, so a
/// component that declares a variant never has that half of its search silently omitted.
///
/// Duplicates are collapsed: both macOS arches resolve to ONE universal `.pkg`, and listing it twice
/// would read as two distinct missing assets.
#[must_use]
pub fn expected_asset_names(
    prefix: &str,
    version: &str,
    kind: AssetKind,
    variants: &[VariantSpec],
) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(PLATFORMS.len() * (1 + variants.len()));
    let mut push_unique = |name: String| {
        if !names.contains(&name) {
            names.push(name);
        }
    };
    for (os, arch) in PLATFORMS {
        let default = expected_asset_name(prefix, version, os, arch, kind);
        push_unique(default.clone());
        for spec in variants {
            push_unique(format!("{default}{}", spec.suffix));
        }
    }
    names
}

/// The `expected` field of a [`FeedsignError::NoArtifacts`]: the asset names that were searched for,
/// joined for a one-line error. `version` is the resolved version, or the literal `<version>`
/// placeholder on the nightly path where the version is what could not be recovered.
///
/// `variants` is the component's declared variant list at a site that searches variant names too,
/// and empty at one that does not — the two sites genuinely differ (see
/// [`resolve_version_from_assets`]), and a diagnostic must describe the search its OWN site ran.
fn no_artifacts_expected(
    component: &ComponentConfig,
    version: &str,
    variants: &[VariantSpec],
) -> String {
    expected_asset_names(
        &component.asset_prefix,
        version,
        component.asset_kind,
        variants,
    )
    .join(" | ")
}

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
    /// The build VARIANT within this `(os, arch)` (dig_ecosystem#1912): `None` for the default asset,
    /// `Some("headless")` for a declared alternative. Carried into the manifest artifact's
    /// [`dig_updater_trust::Artifact::variant`].
    pub variant: Option<String>,
    /// The public download URL of the matching release asset.
    pub url: String,
}

/// Select the per-platform artifacts for `component` from `release` at the given `version`,
/// matching each platform's asset by its exact `{prefix}-{version}-{token}` name.
///
/// The `version` is supplied rather than read from the release because it differs per channel
/// (SPEC §10.1): stable passes the release tag's version (`release.asset_version()`), while nightly
/// passes the version recovered from the asset names ([`resolve_version_from_assets`]) since the
/// rolling `nightly` tag carries no version. Selection itself is identical for both — an EXACT
/// name match on that version — so sibling `.tar.gz`/companion assets stay excluded.
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
    version: &str,
) -> Result<Vec<ResolvedArtifact>, FeedsignError> {
    let mut artifacts = Vec::new();
    for (os, arch) in PLATFORMS {
        let expected = expected_asset_name(
            &component.asset_prefix,
            version,
            os,
            arch,
            component.asset_kind,
        );
        if let Some(asset) = release.assets.iter().find(|a| a.name == expected) {
            // The DEFAULT build for this platform (`variant: None`) — emitted FIRST, so the manifest
            // lists the default before any alternative and the beacon's variant selection prefers it.
            artifacts.push(ResolvedArtifact {
                os: (*os).to_string(),
                arch: (*arch).to_string(),
                variant: None,
                url: asset.browser_download_url.clone(),
            });
        }
        // Each declared VARIANT (dig_ecosystem#1912) is an EXTRA asset named `{default}{suffix}` —
        // e.g. `dig-app-3.5.0-linux-x64-headless`. A component that declares none adds nothing here,
        // so its output is unchanged; a variant asset that is absent from the release is simply
        // skipped (the platform may not ship it), never an error.
        for spec in &component.variants {
            let variant_name = format!("{expected}{}", spec.suffix);
            if let Some(asset) = release.assets.iter().find(|a| a.name == variant_name) {
                artifacts.push(ResolvedArtifact {
                    os: (*os).to_string(),
                    arch: (*arch).to_string(),
                    variant: Some(spec.variant.clone()),
                    url: asset.browser_download_url.clone(),
                });
            }
        }
    }
    if artifacts.is_empty() {
        return Err(FeedsignError::NoArtifacts {
            component: component.name.clone(),
            expected: no_artifacts_expected(component, version, &component.variants),
        });
    }
    Ok(artifacts)
}

/// Recover the version string shared by a `component`'s assets in a rolling `nightly` release.
///
/// A stable release names its version in the tag (`v0.29.0`), but the rolling nightly's tag is the
/// literal `nightly` — the version (`X.Y.Z-nightly.YYYYMMDD.<sha>`) lives only in the asset FILE
/// NAMES, which the nightly builder shapes as `{head}{version}{tail}` (#590). This strips the
/// component's `{head}` and each platform's `{tail}` off the first matching asset; whatever remains
/// between them is the version. Every asset in one release carries the SAME version, so the first
/// match is authoritative — and matching on the component's own [`AssetKind`] keeps a native-package
/// component reading its `.msi`/`.pkg`/`.deb` names rather than a stray raw binary.
///
/// # Errors
///
/// [`FeedsignError::NoArtifacts`] if no asset matches any platform's `{head}…{tail}` shape (a
/// component with no nightly assets — the feed fails closed rather than guessing a version).
pub fn resolve_version_from_assets(
    release: &GithubRelease,
    component: &ComponentConfig,
) -> Result<String, FeedsignError> {
    for (os, arch) in PLATFORMS {
        let (head, tail) =
            asset_name_parts(&component.asset_prefix, os, arch, component.asset_kind);
        for asset in &release.assets {
            if let Some(version) = asset
                .name
                .strip_prefix(&head)
                .and_then(|rest| rest.strip_suffix(&tail))
                .filter(|version| !version.is_empty())
            {
                return Ok(version.to_string());
            }
        }
    }
    Err(FeedsignError::NoArtifacts {
        component: component.name.clone(),
        expected: no_artifacts_expected(component, "<version>", &[]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component() -> ComponentConfig {
        ComponentConfig {
            name: "dig-node".into(),
            repo: "DIG-Network/dig-node".into(),
            asset_prefix: "dig-node".into(),
            asset_kind: AssetKind::RawBinary,
            variants: vec![],
        }
    }

    /// dig-node as the feed actually tracks it: a native-package component.
    fn native_package_component() -> ComponentConfig {
        ComponentConfig {
            asset_kind: AssetKind::NativePackage,
            ..component()
        }
    }

    /// A raw-binary component with `name`/`repo`/`asset_prefix` all set to `name`.
    fn component_named(name: &str) -> ComponentConfig {
        ComponentConfig {
            name: name.into(),
            repo: format!("DIG-Network/{name}"),
            asset_prefix: name.into(),
            asset_kind: AssetKind::RawBinary,
            variants: vec![],
        }
    }

    fn asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: format!("https://example.test/{name}"),
        }
    }

    #[test]
    fn expected_asset_name_encodes_both_conventions() {
        // Raw binaries: `{prefix}-{version}-{os}-{arch}`, `.exe` on Windows.
        assert_eq!(
            expected_asset_name("digstore", "0.13.1", "linux", "x64", AssetKind::RawBinary),
            "digstore-0.13.1-linux-x64"
        );
        assert_eq!(
            expected_asset_name("digstore", "0.13.1", "windows", "x64", AssetKind::RawBinary),
            "digstore-0.13.1-windows-x64.exe"
        );
        // Native packages: the platform installer's own name.
        assert_eq!(
            expected_asset_name(
                "dig-node",
                "0.31.1",
                "windows",
                "x64",
                AssetKind::NativePackage
            ),
            "dig-node-0.31.1-windows-x64.msi"
        );
        assert_eq!(
            expected_asset_name(
                "dig-node",
                "0.31.1",
                "macos",
                "arm64",
                AssetKind::NativePackage
            ),
            "dig-node-0.31.1-macos.pkg"
        );
        assert_eq!(
            expected_asset_name(
                "dig-node",
                "0.31.1",
                "macos",
                "x64",
                AssetKind::NativePackage
            ),
            "dig-node-0.31.1-macos.pkg"
        );
        assert_eq!(
            expected_asset_name(
                "dig-node",
                "0.31.1",
                "linux",
                "x64",
                AssetKind::NativePackage
            ),
            "dig-node_0.31.1_amd64.deb"
        );
    }

    #[test]
    fn expected_asset_name_encodes_linux_arm64() {
        // RawBinary keeps the `-{os}-{arch}` shape, so linux/arm64 tokens as `-linux-arm64`.
        assert_eq!(
            expected_asset_name("digstore", "0.13.1", "linux", "arm64", AssetKind::RawBinary),
            "digstore-0.13.1-linux-arm64"
        );
        // NativePackage Linux is arch-tokened: arm64 → `_arm64.deb` (the Debian convention).
        assert_eq!(
            expected_asset_name(
                "dig-node",
                "0.31.1",
                "linux",
                "arm64",
                AssetKind::NativePackage
            ),
            "dig-node_0.31.1_arm64.deb"
        );
    }

    #[test]
    fn native_package_linux_x64_deb_is_byte_identical() {
        // Regression guard: the arch-aware branch must not disturb the x64 `.deb` byte-shape.
        assert_eq!(
            expected_asset_name(
                "dig-node",
                "0.31.1",
                "linux",
                "x64",
                AssetKind::NativePackage
            ),
            "dig-node_0.31.1_amd64.deb"
        );
    }

    #[test]
    fn native_package_linux_arm64_selects_the_arm64_deb() {
        // A dig-node-shaped release carrying the arm64 `.deb` resolves it for linux/arm64.
        let release = GithubRelease {
            tag_name: "v0.31.1".into(),
            assets: vec![
                asset("dig-node_0.31.1_amd64.deb"),
                asset("dig-node_0.31.1_arm64.deb"),
                asset("dig-node-0.31.1-macos.pkg"),
                asset("dig-node-0.31.1-windows-x64.msi"),
            ],
        };
        let arts = select_artifacts(&release, &native_package_component(), "0.31.1").unwrap();
        let arm = arts
            .iter()
            .find(|a| a.os == "linux" && a.arch == "arm64")
            .expect("a linux/arm64 artifact");
        assert!(
            arm.url.ends_with("dig-node_0.31.1_arm64.deb"),
            "must select the arm64 .deb, got {}",
            arm.url
        );
    }

    #[test]
    fn raw_binary_linux_arm64_selects_the_linux_arm64_asset() {
        // A digstore release carrying `-linux-arm64` resolves it for linux/arm64.
        let release = GithubRelease {
            tag_name: "v0.13.1".into(),
            assets: vec![
                asset("digstore-0.13.1-linux-x64"),
                asset("digstore-0.13.1-linux-arm64"),
                asset("digstore-0.13.1-macos-arm64"),
                asset("digstore-0.13.1-windows-x64.exe"),
            ],
        };
        let arts = select_artifacts(&release, &component_named("digstore"), "0.13.1").unwrap();
        let arm = arts
            .iter()
            .find(|a| a.os == "linux" && a.arch == "arm64")
            .expect("a linux/arm64 artifact");
        assert!(
            arm.url.ends_with("digstore-0.13.1-linux-arm64"),
            "must select the linux-arm64 binary, got {}",
            arm.url
        );
    }

    #[test]
    fn a_component_without_arm64_still_resolves_its_other_platforms() {
        // Graceful degrade: a component publishing x64/macos/windows but NO arm64 asset still
        // resolves its other platforms and publishes — the same tolerated case as any absent
        // platform, now that linux/arm64 is one more sometimes-absent slot.
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![
                asset("dig-node-0.29.0-linux-x64"),
                asset("dig-node-0.29.0-macos-arm64"),
                asset("dig-node-0.29.0-macos-x64"),
                asset("dig-node-0.29.0-windows-x64.exe"),
            ],
        };
        let arts = select_artifacts(&release, &component(), "0.29.0").unwrap();
        assert_eq!(arts.len(), 4, "the four present platforms resolve");
        assert!(
            !arts.iter().any(|a| a.arch == "arm64" && a.os == "linux"),
            "no linux/arm64 artifact when its asset is absent"
        );
    }

    #[test]
    fn nightly_version_recovers_across_the_new_arm64_slot() {
        // With only the x64 `_amd64.deb` present, the arm64 `_arm64.deb` tail simply does not match
        // and version recovery still succeeds off the x64 asset.
        let x64_only = GithubRelease {
            tag_name: "nightly".into(),
            assets: vec![asset("dig-node_0.32.0-nightly.20260714.deadbee_amd64.deb")],
        };
        assert_eq!(
            resolve_version_from_assets(&x64_only, &native_package_component())
                .expect("recovers from the x64 deb"),
            "0.32.0-nightly.20260714.deadbee"
        );
        // And an arm64-only nightly asset recovers the version off the `_arm64.deb` tail.
        let arm64_only = GithubRelease {
            tag_name: "nightly".into(),
            assets: vec![asset("dig-node_0.32.0-nightly.20260714.deadbee_arm64.deb")],
        };
        assert_eq!(
            resolve_version_from_assets(&arm64_only, &native_package_component())
                .expect("recovers from the arm64 deb"),
            "0.32.0-nightly.20260714.deadbee"
        );
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
        let arts = select_artifacts(&release, &component(), "0.29.0").unwrap();
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
            asset_kind: AssetKind::RawBinary,
            variants: vec![],
        };
        let arts = select_artifacts(&release, &cfg, "0.13.1").unwrap();
        assert_eq!(arts.len(), 1);
        assert_eq!(
            arts[0].url,
            "https://example.test/digstore-0.13.1-linux-x64"
        );
    }

    /// A real dig-node release ships BOTH the raw per-OS binaries AND the native installer packages
    /// (`.msi`/`.pkg`/`.deb`). As a native-package component (#580), the feed must select the
    /// PACKAGES — because the broker installs dig-node via `msiexec`/`installer`/`dpkg`, so signing
    /// the raw PE and staging it as `dig-node.msi` makes `msiexec` reject it (exit 1620).
    fn dig_node_full_release() -> GithubRelease {
        GithubRelease {
            tag_name: "v0.31.1".into(),
            assets: vec![
                asset("dig-node-0.31.1-linux-x64"),
                asset("dig-node-0.31.1-macos-arm64"),
                asset("dig-node-0.31.1-macos-x64"),
                asset("dig-node-0.31.1-macos.pkg"),
                asset("dig-node-0.31.1-windows-x64.exe"),
                asset("dig-node-0.31.1-windows-x64.msi"),
                asset("dig-node_0.31.1_amd64.deb"),
            ],
        }
    }

    #[test]
    fn native_package_windows_selects_the_msi_not_the_raw_exe() {
        let arts = select_artifacts(
            &dig_node_full_release(),
            &native_package_component(),
            "0.31.1",
        )
        .unwrap();
        let windows = arts
            .iter()
            .find(|a| a.os == "windows")
            .expect("a windows artifact");
        assert!(
            windows.url.ends_with("dig-node-0.31.1-windows-x64.msi"),
            "must select the MSI, got {}",
            windows.url
        );
    }

    #[test]
    fn native_package_linux_selects_the_underscore_shaped_deb() {
        let arts = select_artifacts(
            &dig_node_full_release(),
            &native_package_component(),
            "0.31.1",
        )
        .unwrap();
        let linux = arts
            .iter()
            .find(|a| a.os == "linux")
            .expect("a linux artifact");
        assert!(
            linux.url.ends_with("dig-node_0.31.1_amd64.deb"),
            "must select the .deb, got {}",
            linux.url
        );
    }

    #[test]
    fn native_package_both_macos_arches_select_the_single_universal_pkg() {
        // dig-node ships ONE universal `-macos.pkg` (no arch token) covering both arm64 and x64, so
        // both platform entries resolve to the same package URL.
        let arts = select_artifacts(
            &dig_node_full_release(),
            &native_package_component(),
            "0.31.1",
        )
        .unwrap();
        let macos: Vec<_> = arts.iter().filter(|a| a.os == "macos").collect();
        assert_eq!(macos.len(), 2, "both macOS arches resolve");
        for a in macos {
            assert!(
                a.url.ends_with("dig-node-0.31.1-macos.pkg"),
                "must select the .pkg for {}, got {}",
                a.arch,
                a.url
            );
        }
    }

    #[test]
    fn a_raw_binary_component_still_selects_the_exe_from_the_same_release() {
        // The default kind is unchanged: digstore/dig-dns/dig-updater keep resolving the raw
        // per-OS binaries, never the packages.
        let arts = select_artifacts(&dig_node_full_release(), &component(), "0.31.1").unwrap();
        let windows = arts
            .iter()
            .find(|a| a.os == "windows")
            .expect("a windows artifact");
        assert!(
            windows.url.ends_with("dig-node-0.31.1-windows-x64.exe"),
            "a raw-binary component selects the .exe, got {}",
            windows.url
        );
        assert!(
            arts.iter().all(|a| !a.url.ends_with(".msi")
                && !a.url.ends_with(".pkg")
                && !a.url.ends_with(".deb")),
            "a raw-binary component never selects a package"
        );
    }

    /// A dig-app-shaped component declaring a headless variant, plus a release carrying BOTH the
    /// default and the `-headless` linux/x64 assets — the exact dig_ecosystem#1912 shape.
    fn dig_app_with_headless() -> ComponentConfig {
        ComponentConfig {
            name: "dig-app".into(),
            repo: "DIG-Network/dig-app".into(),
            asset_prefix: "dig-app".into(),
            asset_kind: AssetKind::RawBinary,
            variants: vec![crate::config::VariantSpec {
                suffix: "-headless".into(),
                variant: "headless".into(),
            }],
        }
    }

    #[test]
    fn a_declared_variant_emits_a_second_artifact_for_the_same_platform() {
        // dig_ecosystem#1912: the feed must carry BOTH linux/x64 builds — the default (no variant)
        // and the headless one — so the beacon can select the loadable one. The default is emitted
        // first, and the platforms that ship only the default stay single-artifact.
        let release = GithubRelease {
            tag_name: "v3.5.0".into(),
            assets: vec![
                asset("dig-app-3.5.0-linux-x64"),
                asset("dig-app-3.5.0-linux-x64-headless"),
                asset("dig-app-3.5.0-macos-arm64"),
                asset("dig-app-3.5.0-windows-x64.exe"),
            ],
        };
        let arts = select_artifacts(&release, &dig_app_with_headless(), "3.5.0").unwrap();

        let linux: Vec<_> = arts.iter().filter(|a| a.os == "linux").collect();
        assert_eq!(linux.len(), 2, "both linux/x64 builds resolve: {arts:?}");
        assert_eq!(linux[0].variant, None, "the default build comes first");
        assert!(linux[0].url.ends_with("dig-app-3.5.0-linux-x64"));
        assert_eq!(linux[1].variant.as_deref(), Some("headless"));
        assert!(linux[1].url.ends_with("dig-app-3.5.0-linux-x64-headless"));

        // The other platforms ship only the default — one artifact each, variant None.
        for os in ["macos", "windows"] {
            let for_os: Vec<_> = arts.iter().filter(|a| a.os == os).collect();
            assert_eq!(for_os.len(), 1, "{os} ships only the default build");
            assert_eq!(for_os[0].variant, None);
        }
    }

    #[test]
    fn a_component_with_no_declared_variants_emits_only_default_artifacts() {
        // The control: a plain component's selection is untouched — every artifact is the default,
        // even when the release happens to carry a `-headless`-suffixed sibling it did not declare.
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![
                asset("dig-node-0.29.0-linux-x64"),
                asset("dig-node-0.29.0-linux-x64-headless"),
            ],
        };
        let arts = select_artifacts(&release, &component(), "0.29.0").unwrap();
        assert_eq!(arts.len(), 1, "an undeclared suffix is never selected");
        assert_eq!(arts[0].variant, None);
        assert!(arts[0].url.ends_with("dig-node-0.29.0-linux-x64"));
    }

    #[test]
    fn a_declared_variant_absent_from_the_release_is_skipped_not_an_error() {
        // The headless asset simply is not there yet (a platform that has not built it): the default
        // still resolves and selection succeeds, rather than failing the whole feed closed.
        let release = GithubRelease {
            tag_name: "v3.5.0".into(),
            assets: vec![asset("dig-app-3.5.0-linux-x64")],
        };
        let arts = select_artifacts(&release, &dig_app_with_headless(), "3.5.0").unwrap();
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0].variant, None);
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
        let arts = select_artifacts(&release, &component(), "0.29.0").unwrap();
        assert_eq!(arts.len(), 2);
    }

    #[test]
    fn zero_matching_assets_is_an_error() {
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![asset("some-unrelated-file.zip")],
        };
        assert!(matches!(
            select_artifacts(&release, &component(), "0.29.0"),
            Err(FeedsignError::NoArtifacts { .. })
        ));
    }

    /// Nightly resolution: the rolling `nightly` release's tag carries NO version, so the version
    /// (`X.Y.Z-nightly.YYYYMMDD.<sha>`) is recovered from the raw-binary asset names.
    #[test]
    fn resolves_the_nightly_version_from_raw_binary_asset_names() {
        let release = GithubRelease {
            tag_name: "nightly".into(),
            assets: vec![
                asset("dig-updater-0.9.0-nightly.20260714.abc1234-linux-x64"),
                asset("dig-updater-0.9.0-nightly.20260714.abc1234-windows-x64.exe"),
            ],
        };
        let version = resolve_version_from_assets(&release, &component_named("dig-updater"))
            .expect("recovers the nightly version");
        assert_eq!(version, "0.9.0-nightly.20260714.abc1234");

        // …and that recovered version drives an exact selection, same as stable.
        let arts = select_artifacts(&release, &component_named("dig-updater"), &version).unwrap();
        assert_eq!(arts.len(), 2);
    }

    /// A native-package component recovers its nightly version from the `.msi`/`.pkg`/`.deb` names
    /// — including the Debian `_amd64.deb` shape whose head/tail differ from the raw binary.
    #[test]
    fn resolves_the_nightly_version_from_native_package_asset_names() {
        let release = GithubRelease {
            tag_name: "nightly".into(),
            assets: vec![
                asset("dig-node_0.32.0-nightly.20260714.deadbee_amd64.deb"),
                asset("dig-node-0.32.0-nightly.20260714.deadbee-macos.pkg"),
                asset("dig-node-0.32.0-nightly.20260714.deadbee-windows-x64.msi"),
            ],
        };
        let version = resolve_version_from_assets(&release, &native_package_component())
            .expect("recovers the nightly version from package names");
        assert_eq!(version, "0.32.0-nightly.20260714.deadbee");
    }

    /// A rolling `nightly` release with no matching component assets fails closed — the feed never
    /// guesses a version (matters during the #592 fan-out, when a component may lack a nightly yet).
    #[test]
    fn nightly_version_resolution_fails_closed_without_matching_assets() {
        let release = GithubRelease {
            tag_name: "nightly".into(),
            assets: vec![asset("some-other-tool-1.0.0-linux-x64")],
        };
        assert!(matches!(
            resolve_version_from_assets(&release, &component()),
            Err(FeedsignError::NoArtifacts { .. })
        ));
    }

    /// The dig-node NIGHTLY release exactly as it stood for the three weeks the feed job failed
    /// (dig_ecosystem#618): the raw per-OS binaries were published, the native installer packages
    /// were NOT. The component is configured `native_package`, so nothing matched — and the error
    /// must say which PACKAGE names it looked for, not the raw-binary shape (which was present all
    /// along, and whose mention sent triage down a "the assets are misnamed" dead end).
    fn dig_node_nightly_missing_its_packages() -> GithubRelease {
        GithubRelease {
            tag_name: "nightly".into(),
            assets: vec![
                asset("dig-node-0.31.1-linux-x64"),
                asset("dig-node-0.31.1-macos-arm64"),
                asset("dig-node-0.31.1-windows-x64.exe"),
            ],
        }
    }

    #[test]
    fn no_artifacts_names_the_native_package_shapes_it_actually_looked_for() {
        let Err(FeedsignError::NoArtifacts { expected, .. }) = select_artifacts(
            &dig_node_nightly_missing_its_packages(),
            &native_package_component(),
            "0.31.1",
        ) else {
            panic!("a native-package component with no packages must fail closed");
        };
        for name in [
            "dig-node-0.31.1-windows-x64.msi",
            "dig-node-0.31.1-macos.pkg",
            "dig-node_0.31.1_amd64.deb",
        ] {
            assert!(
                expected.contains(name),
                "the error must name {name}, got: {expected}"
            );
        }
        assert!(
            !expected.contains("<platform>") && !expected.contains("dig-node-0.31.1-linux-x64"),
            "the error must not describe the raw-binary shape it never looked for: {expected}"
        );
    }

    #[test]
    fn no_artifacts_for_a_raw_binary_component_names_the_binary_shapes() {
        // The control: the same derivation must describe a RAW-BINARY component in its own terms,
        // never a package name — so the message tracks the component's kind, not one hardcoded shape.
        let release = GithubRelease {
            tag_name: "v0.29.0".into(),
            assets: vec![asset("some-unrelated-file.zip")],
        };
        let Err(FeedsignError::NoArtifacts { expected, .. }) =
            select_artifacts(&release, &component(), "0.29.0")
        else {
            panic!("zero matching assets must fail closed");
        };
        assert!(
            expected.contains("dig-node-0.29.0-linux-x64")
                && expected.contains("dig-node-0.29.0-windows-x64.exe"),
            "got: {expected}"
        );
        assert!(
            !expected.contains(".msi") && !expected.contains(".deb") && !expected.contains(".pkg"),
            "a raw-binary component must not be described with package names: {expected}"
        );
    }

    #[test]
    fn nightly_version_resolution_failure_names_the_shapes_for_the_components_kind() {
        // The nightly path has no version to name yet, so it reports the same derived shapes with a
        // `<version>` placeholder — still the component's OWN kind, still from the matcher.
        let Err(FeedsignError::NoArtifacts { expected, .. }) = resolve_version_from_assets(
            &GithubRelease {
                tag_name: "nightly".into(),
                assets: vec![asset("some-other-tool-1.0.0-linux-x64")],
            },
            &native_package_component(),
        ) else {
            panic!("no matching assets must fail closed");
        };
        assert!(
            expected.contains("dig-node-<version>-windows-x64.msi")
                && expected.contains("dig-node_<version>_amd64.deb")
                && expected.contains("dig-node-<version>-macos.pkg"),
            "got: {expected}"
        );
    }

    #[test]
    fn no_artifacts_also_names_a_declared_variants_asset_family() {
        // select_artifacts searches TWO families per platform: the default name AND, per declared
        // variant, `{default}{suffix}`. dig-app really declares `-headless` (feed-config.json), so a
        // zero-artifact dig-app failure that named only the default family would under-describe its
        // own search — the exact defect this whole change exists to remove.
        //
        // The fixture keeps a truthful control: the release carries a NEARLY-matching headless asset
        // for the wrong version, so an implementation that echoed found-but-unmatched asset names
        // rather than deriving the expected ones would not pass.
        let release = GithubRelease {
            tag_name: "v3.5.0".into(),
            assets: vec![asset("dig-app-3.4.0-linux-x64-headless")],
        };
        let Err(FeedsignError::NoArtifacts { expected, .. }) =
            select_artifacts(&release, &dig_app_with_headless(), "3.5.0")
        else {
            panic!("zero matching assets must fail closed");
        };
        assert!(
            expected.contains("dig-app-3.5.0-linux-x64-headless"),
            "the error must name the declared variant's asset too, got: {expected}"
        );
        assert!(
            expected.contains("dig-app-3.5.0-linux-x64"),
            "…without losing the default family, got: {expected}"
        );
    }

    #[test]
    fn the_default_asset_of_each_platform_is_named_before_its_variants() {
        // Same order select_artifacts tries them, so the message reads as the search it describes.
        let names = expected_asset_names(
            "dig-app",
            "3.5.0",
            AssetKind::RawBinary,
            &dig_app_with_headless().variants,
        );
        assert_eq!(
            names,
            vec![
                "dig-app-3.5.0-linux-x64",
                "dig-app-3.5.0-linux-x64-headless",
                "dig-app-3.5.0-linux-arm64",
                "dig-app-3.5.0-linux-arm64-headless",
                "dig-app-3.5.0-macos-arm64",
                "dig-app-3.5.0-macos-arm64-headless",
                "dig-app-3.5.0-macos-x64",
                "dig-app-3.5.0-macos-x64-headless",
                "dig-app-3.5.0-windows-x64.exe",
                "dig-app-3.5.0-windows-x64.exe-headless",
            ]
        );
    }

    #[test]
    fn the_nightly_version_search_reports_only_the_default_family_it_searches() {
        // Deliberate asymmetry, not an oversight: resolve_version_from_assets strips only the
        // DEFAULT `{head}…{tail}` (a variant suffix would corrupt the recovered version), so its
        // diagnostic must not claim to have looked for variant names.
        let Err(FeedsignError::NoArtifacts { expected, .. }) = resolve_version_from_assets(
            &GithubRelease {
                tag_name: "nightly".into(),
                assets: vec![asset("some-other-tool-1.0.0-linux-x64")],
            },
            &dig_app_with_headless(),
        ) else {
            panic!("no matching assets must fail closed");
        };
        assert!(
            expected.contains("dig-app-<version>-linux-x64"),
            "got: {expected}"
        );
        assert!(
            !expected.contains("-headless"),
            "this site never searches variant names, so it must not claim to: {expected}"
        );
    }

    #[test]
    fn expected_asset_names_are_deduplicated_in_platform_order() {
        // Both macOS arches resolve to ONE universal `.pkg`, so the message lists it once — a
        // duplicate would read as two distinct missing assets.
        let names = expected_asset_names("dig-node", "0.31.1", AssetKind::NativePackage, &[]);
        assert_eq!(
            names,
            vec![
                "dig-node_0.31.1_amd64.deb",
                "dig-node_0.31.1_arm64.deb",
                "dig-node-0.31.1-macos.pkg",
                "dig-node-0.31.1-windows-x64.msi",
            ]
        );
    }

    #[test]
    fn rejects_malformed_release_json() {
        assert!(matches!(
            GithubRelease::from_json("https://api/x", "{not json"),
            Err(FeedsignError::Github { .. })
        ));
    }
}

