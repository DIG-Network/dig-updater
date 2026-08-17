//! The SERVED-vs-RELEASED freshness audit (dig_ecosystem#3046).
//!
//! The feed is what users install FROM; the GitHub Release is not. Those two can disagree, and when
//! they do, EVERY artifact check still passes — the tag exists, it is marked latest, its assets are
//! all present — while no user can obtain the build. That is the failure this audit exists to make
//! visible: it asks the one question nothing else asked, **does the version the feed serves match
//! the version the repo believes it released**, and REDs when it does not.
//!
//! The audit is read-only and secret-free (release metadata + the public manifest), so it is driven
//! here entirely by in-memory fakes — never the real GitHub API or the live feed.
//!
//! The properties pinned below are mostly about the audit REFUSING TO REPORT GREEN. A staleness
//! check that passes when it could not reach a release, when a component is absent from the
//! manifest, or when it was handed nothing to check would be worse than no check at all: it would
//! answer the one question with a confident, wrong "yes".

use std::collections::HashMap;

use dig_updater_feedsign::{
    audit_freshness, Channel, FeedConfig, FeedsignError, GithubRelease, ReleaseSource, ServedFeed,
};

/// An in-memory release source keyed by `owner/repo`. A repo with no entry is a fetch failure,
/// mirroring a release that cannot be reached.
struct FakeSource {
    releases: HashMap<String, GithubRelease>,
}

impl FakeSource {
    /// A source where each `(repo, tag)` pair resolves to a release carrying the full artifact set
    /// the shipped config expects, so resolution succeeds and only the VERSION is under test.
    fn new(releases: &[(&str, &str)]) -> Self {
        Self {
            releases: releases
                .iter()
                .map(|(repo, tag)| ((*repo).to_string(), release(tag)))
                .collect(),
        }
    }
}

impl ReleaseSource for FakeSource {
    fn release(&self, repo: &str, _channel: Channel) -> Result<GithubRelease, FeedsignError> {
        self.releases
            .get(repo)
            .cloned()
            .ok_or_else(|| FeedsignError::Fetch {
                url: format!("fake://{repo}"),
                detail: "no release in the fake source".to_string(),
            })
    }

    fn download(&self, url: &str) -> Result<Vec<u8>, FeedsignError> {
        Err(FeedsignError::Fetch {
            url: url.to_string(),
            detail: "the freshness audit must never download an artifact".to_string(),
        })
    }
}

/// A release tagged `v{version}` whose assets cover every platform the test config needs.
fn release(version: &str) -> GithubRelease {
    let json = format!(
        r#"{{"tag_name":"v{version}","assets":[
            {{"name":"widget-{version}-linux-x64","browser_download_url":"https://example.invalid/l64"}},
            {{"name":"widget-{version}-linux-arm64","browser_download_url":"https://example.invalid/la"}},
            {{"name":"widget-{version}-macos-x64","browser_download_url":"https://example.invalid/m64"}},
            {{"name":"widget-{version}-macos-arm64","browser_download_url":"https://example.invalid/ma"}},
            {{"name":"widget-{version}-windows-x64","browser_download_url":"https://example.invalid/w64"}}
        ]}}"#
    );
    GithubRelease::from_json("fake://release", &json).expect("the fixture release must parse")
}

/// A one-component feed config naming `widget` in `DIG-Network/widget`.
fn config() -> FeedConfig {
    FeedConfig::from_json(
        r#"{
            "schema": 2, "root_version": 1,
            "manifest_ttl_secs": 43200, "delegation_ttl_secs": 2592000,
            "channels": { "stable": 0, "nightly": 0 },
            "components": [
                { "name": "widget", "repo": "DIG-Network/widget", "asset_prefix": "widget" }
            ]
        }"#,
    )
    .expect("the fixture config must parse")
}

/// A served manifest declaring each `(component, version)` pair — the shape `updates.dig.net`
/// actually serves (a signed envelope wrapping the manifest payload).
fn served(components: &[(&str, &str)]) -> ServedFeed {
    let entries = components
        .iter()
        .map(|(name, version)| {
            format!(r#"{{"name":"{name}","version":"{version}","build":1,"artifacts":[]}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        r#"{{"manifest":{{"schema":2,"root_version":1,"sequence":1,"generated":1000,"expires":99999,"rollback_floor_build":0,"components":[{entries}]}},"signature":"c2ln"}}"#
    );
    ServedFeed::from_manifest_json(&json).expect("the fixture manifest must parse")
}

/// The happy path: what the feed serves IS what the repo released, so there is nothing to report.
#[test]
fn a_feed_serving_every_released_version_is_clean() {
    let audit = audit_freshness(
        &config(),
        &FakeSource::new(&[("DIG-Network/widget", "1.2.3")]),
        &served(&[("widget", "1.2.3")]),
        Channel::Stable,
    );

    assert!(
        audit.is_clean(),
        "a feed serving exactly the released version must be clean:\n{}",
        audit.render()
    );
}

/// THE #3046 DEFECT ITSELF: the release is live and correct, the feed still serves the previous
/// version, and every other check in the ecosystem is green. This must be the thing that REDs.
#[test]
fn a_feed_serving_an_older_version_than_the_release_is_not_clean() {
    let audit = audit_freshness(
        &config(),
        &FakeSource::new(&[("DIG-Network/widget", "1.2.3")]),
        &served(&[("widget", "1.2.2")]),
        Channel::Stable,
    );

    assert!(
        !audit.is_clean(),
        "the feed serves 1.2.2 while the repo released 1.2.3 — no user can obtain the release, so \
         this must NOT be clean:\n{}",
        audit.render()
    );
    let report = audit.render();
    for expected in ["widget", "1.2.3", "1.2.2"] {
        assert!(
            report.contains(expected),
            "the report must name {expected:?} so the drift is actionable without re-deriving \
             it:\n{report}"
        );
    }
}

/// A mismatch is a mismatch in EITHER direction. A feed serving a version the repo has not released
/// (a hand-edited manifest, a resolution pointing at the wrong release, an un-latested release) is
/// just as much a disagreement, and reporting only the "behind" direction would let it pass.
#[test]
fn a_feed_serving_a_version_the_repo_did_not_release_is_not_clean() {
    let audit = audit_freshness(
        &config(),
        &FakeSource::new(&[("DIG-Network/widget", "1.2.3")]),
        &served(&[("widget", "9.9.9")]),
        Channel::Stable,
    );

    assert!(
        !audit.is_clean(),
        "the feed serves 9.9.9 which the repo never released — a disagreement in either direction \
         must red:\n{}",
        audit.render()
    );
}

/// ANTI-VACUITY: a configured component that is ABSENT from the served manifest must be a finding,
/// not a silent skip. Absence is the most complete form of "users cannot get this component", so an
/// audit that iterated the manifest's entries instead of the CONFIG's would report green on the
/// worst case.
#[test]
fn a_component_missing_from_the_served_manifest_is_not_clean() {
    let audit = audit_freshness(
        &config(),
        &FakeSource::new(&[("DIG-Network/widget", "1.2.3")]),
        &served(&[("something-else", "1.2.3")]),
        Channel::Stable,
    );

    assert!(
        !audit.is_clean(),
        "`widget` is configured but wholly absent from the served feed — the strongest form of \
         'no user can get this', which must never read as clean:\n{}",
        audit.render()
    );
}

/// ANTI-VACUITY: the check must never report FRESH from a check it could not perform. An
/// unreachable release means the audit does not know the answer, and "I don't know" must present as
/// not-clean — distinctly labelled, so nobody mistakes it for proven staleness.
#[test]
fn a_component_whose_release_cannot_be_resolved_is_not_clean() {
    let audit = audit_freshness(
        &config(),
        &FakeSource::new(&[]), // no release for the configured repo — a fetch failure
        &served(&[("widget", "1.2.3")]),
        Channel::Stable,
    );

    assert!(
        !audit.is_clean(),
        "the release could not be reached, so the audit does not KNOW the feed is current; \
         reporting clean here would answer the question wrongly with confidence:\n{}",
        audit.render()
    );
    assert!(
        audit.render().to_lowercase().contains("could not"),
        "an unresolvable component must be labelled as un-checked, NOT as stale — the two demand \
         different responses:\n{}",
        audit.render()
    );
}

/// ANTI-VACUITY, pinned where the guard actually lives.
///
/// An audit handed NOTHING to check has proven nothing: "no component is stale" is trivially true
/// of an empty component list, so an empty config would otherwise report a confident green forever.
/// `FreshnessAudit::is_clean` refuses an empty finding set for that reason — but that branch is
/// UNREACHABLE through the public path, because `FeedConfig` already refuses to parse a config with
/// no components. This test pins the upstream refusal, which is the guard that genuinely holds; the
/// `is_clean` emptiness check is retained as defence-in-depth behind it.
#[test]
fn a_config_with_no_components_cannot_be_built_at_all() {
    let empty = FeedConfig::from_json(
        r#"{
            "schema": 2, "root_version": 1,
            "manifest_ttl_secs": 43200, "delegation_ttl_secs": 2592000,
            "channels": { "stable": 0, "nightly": 0 },
            "components": []
        }"#,
    );

    assert!(
        empty.is_err(),
        "a config declaring no components must be rejected at parse: it would make every audit \
         over it — this one included — vacuously green"
    );
}

/// One stale component among healthy ones must red the whole audit — a per-component green must
/// never be summed into an overall green.
#[test]
fn one_stale_component_reds_an_otherwise_current_feed() {
    let config = FeedConfig::from_json(
        r#"{
            "schema": 2, "root_version": 1,
            "manifest_ttl_secs": 43200, "delegation_ttl_secs": 2592000,
            "channels": { "stable": 0, "nightly": 0 },
            "components": [
                { "name": "widget", "repo": "DIG-Network/widget", "asset_prefix": "widget" },
                { "name": "gadget", "repo": "DIG-Network/gadget", "asset_prefix": "widget" }
            ]
        }"#,
    )
    .expect("the two-component config must parse");

    let audit = audit_freshness(
        &config,
        &FakeSource::new(&[
            ("DIG-Network/widget", "1.2.3"),
            ("DIG-Network/gadget", "4.5.6"),
        ]),
        &served(&[("widget", "1.2.3"), ("gadget", "4.5.5")]),
        Channel::Stable,
    );

    assert!(
        !audit.is_clean(),
        "`gadget` is a release behind; a healthy `widget` must not mask it:\n{}",
        audit.render()
    );
}

/// The served manifest is read as DATA, so a malformed one must fail loudly at the parse rather
/// than yield an empty view of the feed — which would then read as "every component is missing" or,
/// worse, as nothing to check.
#[test]
fn a_malformed_served_manifest_is_rejected() {
    assert!(
        ServedFeed::from_manifest_json("{ this is not a manifest }").is_err(),
        "a malformed served manifest must be an error, never an empty-but-usable feed view"
    );
}
