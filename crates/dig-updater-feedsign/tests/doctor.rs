//! `feedsign doctor` (dig_ecosystem#2115): validate `feed-config.json` against a channel's live
//! releases WITHOUT the signing secret, reported per component.
//!
//! For three weeks a `native_package` component whose release shipped only raw binaries took the
//! nightly Feed cron red — and the ONLY signal was that red run, because the mismatch is caught
//! INSIDE the signing pass (`produce_feed`, which needs `BEACON_SIGNING_KEY`). Doctor moves that
//! check ahead of signing and names the failing component, so a broken declaration fails legibly.
//!
//! These tests drive it through an in-memory [`ReleaseSource`], so they are deterministic + offline
//! — never the real GitHub API.

use std::collections::HashMap;

use dig_updater_feedsign::{
    audit_exemptions, Channel, DoctorReport, FeedConfig, FeedsignError, GithubRelease,
    ReleaseSource,
};

/// An in-memory release source keyed by `owner/repo` (channel-agnostic here — doctor tests fix the
/// channel per run). A repo with no entry is a fetch failure, mirroring a missing release.
struct FakeSource {
    releases: HashMap<String, GithubRelease>,
}

impl ReleaseSource for FakeSource {
    fn release(&self, repo: &str, _channel: Channel) -> Result<GithubRelease, FeedsignError> {
        self.releases
            .get(repo)
            .cloned()
            .ok_or_else(|| FeedsignError::Fetch {
                url: repo.to_string(),
                detail: "no fake release".to_string(),
            })
    }

    fn download(&self, _url: &str) -> Result<Vec<u8>, FeedsignError> {
        // Doctor never downloads — resolution alone is what it checks.
        Ok(Vec::new())
    }
}

/// A [`GithubRelease`] parsed from the real REST shape the signer consumes, carrying exactly
/// `assets` at `tag`.
fn release(tag: &str, assets: &[&str]) -> GithubRelease {
    let items: Vec<String> = assets
        .iter()
        .map(|name| {
            format!(r#"{{"name":"{name}","browser_download_url":"https://example.test/{name}"}}"#)
        })
        .collect();
    GithubRelease::from_json(
        "https://api/x",
        &format!(r#"{{"tag_name":"{tag}","assets":[{}]}}"#, items.join(",")),
    )
    .expect("the synthesised release parses")
}

fn source(pairs: Vec<(&str, GithubRelease)>) -> FakeSource {
    FakeSource {
        releases: pairs
            .into_iter()
            .map(|(repo, rel)| (repo.to_string(), rel))
            .collect(),
    }
}

/// The full digstore raw-binary platform set at `1.2.3`, minus none — a complete release.
const DIGSTORE_ALL: &[&str] = &[
    "digstore-1.2.3-linux-x64",
    "digstore-1.2.3-linux-arm64",
    "digstore-1.2.3-macos-arm64",
    "digstore-1.2.3-macos-x64",
    "digstore-1.2.3-windows-x64.exe",
];

/// A component whose release is MISSING a non-exempt platform (macos/x64) fails doctor: the report
/// is unhealthy AND names both the component and the missing platform. This is the exact silent
/// failure #2115 exists to surface before the signing pass.
#[test]
fn a_missing_non_exempt_platform_fails_and_is_named() {
    // digstore declares NO exemptions, so every one of the five platforms is required.
    let config = FeedConfig::from_json(
        r#"{"components":[{"name":"digstore","repo":"DIG-Network/digstore","asset_prefix":"digstore"}]}"#,
    )
    .unwrap();
    // The release ships four of five — macos/x64 is absent, and undeclared, so it must fail closed.
    let missing_macos_x64 = &[
        "digstore-1.2.3-linux-x64",
        "digstore-1.2.3-linux-arm64",
        "digstore-1.2.3-macos-arm64",
        "digstore-1.2.3-windows-x64.exe",
    ];
    let src = source(vec![(
        "DIG-Network/digstore",
        release("v1.2.3", missing_macos_x64),
    )]);

    let report = DoctorReport::run(&config, &src, Channel::Stable);

    assert!(
        !report.is_healthy(),
        "a missing non-exempt platform must make the report unhealthy"
    );
    let rendered = report.render();
    assert!(
        rendered.contains("digstore"),
        "the report must name the failing component, got:\n{rendered}"
    );
    assert!(
        rendered.contains("macos/x64"),
        "the report must name the missing platform, got:\n{rendered}"
    );
}

/// The exemption is load-bearing, not incidental: the SAME four-of-five release resolves GREEN once
/// macos/x64 is declared exempt — proving the exemption, not luck, is what makes it pass, and that a
/// legitimately-absent exempt platform does not fail doctor.
#[test]
fn an_exempt_missing_platform_resolves_green() {
    let config = FeedConfig::from_json(
        r#"{"components":[{"name":"digstore","repo":"DIG-Network/digstore","asset_prefix":"digstore",
            "exempt_platforms":[{"os":"macos","arch":"x64"}]}]}"#,
    )
    .unwrap();
    let missing_macos_x64 = &[
        "digstore-1.2.3-linux-x64",
        "digstore-1.2.3-linux-arm64",
        "digstore-1.2.3-macos-arm64",
        "digstore-1.2.3-windows-x64.exe",
    ];
    let src = source(vec![(
        "DIG-Network/digstore",
        release("v1.2.3", missing_macos_x64),
    )]);

    let report = DoctorReport::run(&config, &src, Channel::Stable);

    assert!(
        report.is_healthy(),
        "every platform resolves or is exempt → healthy, got:\n{}",
        report.render()
    );
}

/// A complete release for a fully-specified component resolves green and the report names its
/// resolved version — the healthy baseline.
#[test]
fn a_complete_release_resolves_green_with_its_version() {
    let config = FeedConfig::from_json(
        r#"{"components":[{"name":"digstore","repo":"DIG-Network/digstore","asset_prefix":"digstore"}]}"#,
    )
    .unwrap();
    let src = source(vec![(
        "DIG-Network/digstore",
        release("v1.2.3", DIGSTORE_ALL),
    )]);

    let report = DoctorReport::run(&config, &src, Channel::Stable);

    assert!(report.is_healthy(), "a complete release is healthy");
    assert!(
        report.render().contains("1.2.3"),
        "the report names the resolved version, got:\n{}",
        report.render()
    );
}

/// Doctor reports EVERY component, not just the first failure: with one healthy and one broken
/// component the report is unhealthy and names the broken one while still listing the healthy one —
/// so a maintainer sees the whole feed's health in one pass, not one failure at a time.
#[test]
fn a_mixed_config_reports_all_components_and_fails_on_any() {
    let config = FeedConfig::from_json(
        r#"{"components":[
            {"name":"digstore","repo":"DIG-Network/digstore","asset_prefix":"digstore"},
            {"name":"dig-node","repo":"DIG-Network/dig-node","asset_prefix":"dig-node","asset_kind":"native_package"}
        ]}"#,
    )
    .unwrap();
    // digstore is complete; dig-node is native_package but its release ships only raw binaries —
    // the exact #618 shape — so it resolves ZERO package assets and fails.
    let dig_node_raw_only = &[
        "dig-node-0.31.1-linux-x64",
        "dig-node-0.31.1-macos-arm64",
        "dig-node-0.31.1-windows-x64.exe",
    ];
    let src = source(vec![
        ("DIG-Network/digstore", release("v1.2.3", DIGSTORE_ALL)),
        (
            "DIG-Network/dig-node",
            release("v0.31.1", dig_node_raw_only),
        ),
    ]);

    let report = DoctorReport::run(&config, &src, Channel::Stable);

    assert!(!report.is_healthy(), "any failing component fails doctor");
    let rendered = report.render();
    assert!(
        rendered.contains("dig-node"),
        "the broken component is named, got:\n{rendered}"
    );
    assert!(
        rendered.contains("digstore") && rendered.contains("1.2.3"),
        "the healthy component is still listed, got:\n{rendered}"
    );
}

// --- Exemption-drift audit (dig_ecosystem#2555) -----------------------------------------------
//
// The audit is the OPPOSITE direction from the completeness gate above: it REDs when a declared
// exemption is OVER-BROAD — the component's release actually publishes the exempt platform, so the
// exemption now masks the #2343 gate for it. These tests drive it through a CHANNEL-AWARE in-memory
// source, since an exemption can be over-broad on one channel while accurate on the other.

/// An in-memory source keyed by `(repo, channel)`, so stable and nightly can return DIFFERENT
/// releases for the same repo — the two-channel dimension the audit sweeps.
struct ChannelSource {
    releases: HashMap<(String, Channel), GithubRelease>,
}

impl ReleaseSource for ChannelSource {
    fn release(&self, repo: &str, channel: Channel) -> Result<GithubRelease, FeedsignError> {
        self.releases
            .get(&(repo.to_string(), channel))
            .cloned()
            .ok_or_else(|| FeedsignError::Fetch {
                url: repo.to_string(),
                detail: "no fake release".to_string(),
            })
    }

    fn download(&self, _url: &str) -> Result<Vec<u8>, FeedsignError> {
        Ok(Vec::new())
    }
}

fn channel_source(pairs: Vec<(&str, Channel, GithubRelease)>) -> ChannelSource {
    ChannelSource {
        releases: pairs
            .into_iter()
            .map(|(repo, ch, rel)| ((repo.to_string(), ch), rel))
            .collect(),
    }
}

/// digstore's config declaring linux/arm64 exempt — the shape the audit judges.
fn digstore_exempts_arm64() -> FeedConfig {
    FeedConfig::from_json(
        r#"{"components":[{"name":"digstore","repo":"DIG-Network/digstore","asset_prefix":"digstore",
            "exempt_platforms":[{"os":"linux","arch":"arm64"}]}]}"#,
    )
    .unwrap()
}

/// A digstore nightly release carrying `assets`, versioned so the recovered version matches.
fn digstore_nightly(assets: &[&str]) -> GithubRelease {
    release("nightly", assets)
}

/// DROPPABLE only when over-broad in EVERY channel: linux/arm64 resolves in BOTH stable and nightly,
/// so no channel still needs the exemption → the audit fails and names it to DROP. This is the
/// dig-updater[stable]+[nightly] live case the CI audit caught.
#[test]
fn an_all_channel_overbroad_exemption_is_droppable_and_fails() {
    let src = channel_source(vec![
        (
            "DIG-Network/digstore",
            Channel::Stable,
            release("v1.2.3", DIGSTORE_ALL), // stable ships linux/arm64
        ),
        (
            "DIG-Network/digstore",
            Channel::Nightly,
            digstore_nightly(&[
                "digstore-1.3.0-nightly.20260810.def456-linux-x64",
                "digstore-1.3.0-nightly.20260810.def456-linux-arm64", // nightly ships it too
                "digstore-1.3.0-nightly.20260810.def456-macos-arm64",
                "digstore-1.3.0-nightly.20260810.def456-macos-x64",
                "digstore-1.3.0-nightly.20260810.def456-windows-x64.exe",
            ]),
        ),
    ]);

    let audit = audit_exemptions(&digstore_exempts_arm64(), &src);

    assert!(
        !audit.is_clean(),
        "an exemption resolvable in every channel is droppable → the audit must fail"
    );
    assert_eq!(audit.findings().len(), 1);
    assert!(
        audit.findings()[0].is_droppable(),
        "over-broad in every channel → droppable"
    );
    let rendered = audit.render();
    assert!(
        rendered.contains("DROP")
            && rendered.contains("digstore")
            && rendered.contains("linux/arm64"),
        "the audit must name the droppable component + platform, got:\n{rendered}"
    );
}

/// Legit exemption stays clean: neither channel ships the exempt platform, so the exemption is
/// accurate and the audit is clean — the truthful control.
#[test]
fn a_legitimate_exemption_is_clean_on_both_channels() {
    let src = channel_source(vec![
        (
            "DIG-Network/digstore",
            Channel::Stable,
            release(
                "v1.2.3",
                &[
                    "digstore-1.2.3-linux-x64",
                    "digstore-1.2.3-macos-arm64",
                    "digstore-1.2.3-macos-x64",
                    "digstore-1.2.3-windows-x64.exe",
                ],
            ),
        ),
        (
            "DIG-Network/digstore",
            Channel::Nightly,
            digstore_nightly(&[
                "digstore-1.2.3-nightly.20260810.abc123-linux-x64",
                "digstore-1.2.3-nightly.20260810.abc123-macos-arm64",
                "digstore-1.2.3-nightly.20260810.abc123-macos-x64",
                "digstore-1.2.3-nightly.20260810.abc123-windows-x64.exe",
            ]),
        ),
    ]);

    let audit = audit_exemptions(&digstore_exempts_arm64(), &src);

    assert!(
        audit.is_clean(),
        "an exemption for a genuinely-absent platform on both channels is clean, got:\n{}",
        audit.render()
    );
    assert!(audit.findings().is_empty(), "no over-broad channel at all");
}

/// THE REGRESSION GUARD for the live CI bug (dig-node linux/arm64: stable YES, nightly NO). An
/// exemption over-broad in a STRICT SUBSET of channels is LOAD-BEARING for the channel(s) that lack
/// the platform: dropping it would RED the #2343 gate on nightly and break the live nightly feed. So
/// the audit must stay CLEAN (exit 0) and RETAIN the exemption, recording it only as an
/// informational note — NEVER recommend dropping it.
#[test]
fn a_single_channel_overbroad_exemption_is_retained_not_dropped() {
    let src = channel_source(vec![
        (
            "DIG-Network/digstore",
            Channel::Stable,
            release("v1.2.3", DIGSTORE_ALL), // stable ships linux/arm64
        ),
        (
            "DIG-Network/digstore",
            Channel::Nightly,
            // nightly does NOT ship arm64 → exemption still needed for nightly.
            digstore_nightly(&[
                "digstore-1.3.0-nightly.20260810.def456-linux-x64",
                "digstore-1.3.0-nightly.20260810.def456-macos-arm64",
                "digstore-1.3.0-nightly.20260810.def456-macos-x64",
                "digstore-1.3.0-nightly.20260810.def456-windows-x64.exe",
            ]),
        ),
    ]);

    let audit = audit_exemptions(&digstore_exempts_arm64(), &src);

    assert!(
        audit.is_clean(),
        "a subset-channel over-broad exemption is load-bearing → audit stays clean (exit 0), got:\n{}",
        audit.render()
    );
    assert_eq!(
        audit.findings().len(),
        1,
        "the informational note is still recorded"
    );
    let finding = &audit.findings()[0];
    assert!(
        !finding.is_droppable(),
        "resolvable in stable only → NOT droppable"
    );
    assert_eq!(finding.overbroad_channels, vec![Channel::Stable]);
    assert!(
        audit.render().contains("RETAINED"),
        "the report must mark it retained, got:\n{}",
        audit.render()
    );
}
