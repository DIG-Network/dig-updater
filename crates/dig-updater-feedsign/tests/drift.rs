//! `feedsign drift` (dig_ecosystem#3046): the LIVE feed vs the releases it claims to describe.
//!
//! The feed regenerates on a 6-hour cron, so a component released at 00:05 is invisible to every
//! beacon until 06:00 with nothing red anywhere — the release workflow succeeded, the Feed workflow
//! succeeded at its last tick, and the served manifest simply describes an older world. Measured
//! three times in one day, each needing a hand-run `gh workflow run feed.yml`.
//!
//! `doctor` cannot catch it: doctor asks whether each component's declared assets RESOLVE from its
//! release, and during the outage every component resolved perfectly. What was wrong was the
//! published document, which doctor never reads.
//!
//! These tests drive the whole pass — release resolution, the live manifest fetch over a real
//! loopback socket, parse, compare — with no network and no signing key.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dig_updater_feedsign::{
    check_drift, manifest_url_for, Channel, Drift, FeedConfig, FeedsignError, GithubSource,
};
use dig_updater_trust::{Component, Manifest, SignedManifest};
use ed25519_dalek::SigningKey;

/// A throwaway HTTP server serving a fixed `path -> body` table on an ephemeral loopback port, so
/// the GitHub-API edge AND the live-manifest fetch are both exercised over a real socket.
struct TestServer {
    server: Arc<tiny_http::Server>,
    base: String,
}

struct ServerGuard {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl TestServer {
    fn bind() -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind loopback"));
        let port = server.server_addr().to_ip().expect("ip addr").port();
        Self {
            server,
            base: format!("http://127.0.0.1:{port}"),
        }
    }

    fn serve(&self, routes: HashMap<String, Vec<u8>>) -> ServerGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let server = Arc::clone(&self.server);
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match server.recv_timeout(Duration::from_millis(50)) {
                    Ok(Some(request)) => {
                        let (status, body) = match routes.get(request.url()) {
                            Some(body) => (200u16, body.clone()),
                            None => (404, b"not found".to_vec()),
                        };
                        let response = tiny_http::Response::from_data(body)
                            .with_status_code(tiny_http::StatusCode(status));
                        let _ = request.respond(response);
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        });
        ServerGuard {
            stop,
            handle: Some(handle),
        }
    }
}

/// The one-component config these tests check: dig-app, whose stale 12.16.0 in the feed beside a
/// released 12.17.0 is the measured #3046 outage.
fn config() -> FeedConfig {
    FeedConfig::from_json(
        r#"{"components":[{"name":"dig-app","repo":"DIG-Network/dig-app","asset_prefix":"dig-app"}]}"#,
    )
    .expect("the test config parses")
}

/// The GitHub `releases/latest` body for dig-app at `version`, with the full non-exempt platform
/// set so resolution succeeds and the ONLY thing under test is the version comparison.
fn release_body(version: &str) -> Vec<u8> {
    let assets: Vec<String> = [
        format!("dig-app-{version}-linux-x64"),
        format!("dig-app-{version}-linux-arm64"),
        format!("dig-app-{version}-macos-arm64"),
        format!("dig-app-{version}-macos-x64"),
        format!("dig-app-{version}-windows-x64.exe"),
    ]
    .iter()
    .map(|name| {
        format!(r#"{{"name":"{name}","browser_download_url":"https://example.test/{name}"}}"#)
    })
    .collect();
    format!(
        r#"{{"tag_name":"v{version}","assets":[{}]}}"#,
        assets.join(",")
    )
    .into_bytes()
}

/// A genuinely-shaped signed manifest serving dig-app at `version`, signed with a throwaway key.
///
/// The key is deliberately NOT the pinned root: drift reads the manifest as DATA and never verifies
/// its signature (the Feed job's pinned-key keystone proves that before publication, and the beacon
/// re-proves it on every client). Signing with a stray key here makes that explicit — if drift ever
/// grew a verification step, these tests would start failing and say so.
fn served_manifest(version: &str) -> Vec<u8> {
    let manifest = Manifest {
        schema: 2,
        root_version: 1,
        sequence: 1_762_000_000,
        generated: 1_762_000_000,
        expires: 1_762_043_200,
        rollback_floor_build: 0,
        components: vec![Component {
            name: "dig-app".to_string(),
            version: version.to_string(),
            build: 12_017_000,
            artifacts: vec![],
        }],
    };
    let key = SigningKey::from_bytes(&[7u8; 32]);
    SignedManifest::sign(manifest, &key).to_json().into_bytes()
}

/// Routes for a run where the released version is `released` and the feed serves `in_feed`.
fn routes(released: &str, in_feed: &str) -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "/repos/DIG-Network/dig-app/releases/latest".to_string(),
            release_body(released),
        ),
        (
            "/v1/stable/manifest.json".to_string(),
            served_manifest(in_feed),
        ),
    ])
}

/// THE #3046 OUTAGE, end to end: dig-app released 12.17.0, the live feed still serves 12.16.0.
/// Every workflow involved is green; only this check says so.
#[test]
fn a_live_feed_behind_a_release_is_caught_end_to_end() {
    let srv = TestServer::bind();
    let _guard = srv.serve(routes("12.17.0", "12.16.0"));
    let source = GithubSource::with_api_base(&srv.base, None);
    let feed_base = format!("{}/v1", srv.base);

    let report = check_drift(
        &config(),
        &source,
        Channel::Stable,
        &manifest_url_for(&feed_base, Channel::Stable),
    )
    .expect("the served manifest is readable");

    assert!(
        !report.is_current(),
        "a feed six hours behind a release must NOT read as current: {}",
        report.render()
    );
    assert_eq!(
        report.drifts,
        vec![Drift::Mismatch {
            component: "dig-app".into(),
            released: "12.17.0".into(),
            in_feed: "12.16.0".into(),
        }]
    );
    assert_eq!(report.generated, 1_762_000_000);
    let rendered = report.render();
    assert!(rendered.contains("is BEHIND"), "{rendered}");
    assert!(rendered.contains("12.17.0"), "{rendered}");
}

/// The control: once the feed has been regenerated, the same pass goes green. Without this a check
/// hard-wired to report drift would pass the test above and be useless.
#[test]
fn a_regenerated_feed_reads_as_current() {
    let srv = TestServer::bind();
    let _guard = srv.serve(routes("12.17.0", "12.17.0"));
    let source = GithubSource::with_api_base(&srv.base, None);
    let feed_base = format!("{}/v1", srv.base);

    let report = check_drift(
        &config(),
        &source,
        Channel::Stable,
        &manifest_url_for(&feed_base, Channel::Stable),
    )
    .expect("the served manifest is readable");

    assert!(
        report.is_current(),
        "an up-to-date feed must read as current: {}",
        report.render()
    );
    assert!(report.drifts.is_empty());
    assert!(report.render().contains("is CURRENT"));
}

/// An unreachable feed is an ERROR, never "no drift" — the fail-closed edge. A checker that
/// returned an empty drift list when it could not read the manifest would report the feed healthy
/// during exactly the outage it exists to detect.
#[test]
fn an_unreachable_feed_is_an_error_not_a_clean_bill() {
    let srv = TestServer::bind();
    // The release resolves; the manifest route is absent, so the fetch 404s.
    let mut only_release = routes("12.17.0", "12.17.0");
    only_release.remove("/v1/stable/manifest.json");
    let _guard = srv.serve(only_release);
    let source = GithubSource::with_api_base(&srv.base, None);
    let feed_base = format!("{}/v1", srv.base);

    let result = check_drift(
        &config(),
        &source,
        Channel::Stable,
        &manifest_url_for(&feed_base, Channel::Stable),
    );
    assert!(
        matches!(result, Err(FeedsignError::Fetch { .. })),
        "an unreadable feed must fail closed, got {result:?}"
    );
}

/// A manifest that is served but is not a well-formed signed manifest is likewise an error, not
/// silence — a truncated or half-written S3 object must not read as a healthy feed.
#[test]
fn a_malformed_served_manifest_is_an_error() {
    let srv = TestServer::bind();
    let mut broken = routes("12.17.0", "12.17.0");
    broken.insert(
        "/v1/stable/manifest.json".to_string(),
        b"{\"manifest\": <truncated".to_vec(),
    );
    let _guard = srv.serve(broken);
    let source = GithubSource::with_api_base(&srv.base, None);
    let feed_base = format!("{}/v1", srv.base);

    let result = check_drift(
        &config(),
        &source,
        Channel::Stable,
        &manifest_url_for(&feed_base, Channel::Stable),
    );
    match result {
        Err(FeedsignError::Github { detail, .. }) => assert!(
            detail.contains("well-formed"),
            "the error should name the parse failure, got {detail}"
        ),
        other => panic!("a malformed manifest must fail closed, got {other:?}"),
    }
}

/// A component whose RELEASE cannot be resolved must surface as `Unknown` and count against the
/// verdict. If it were skipped, a GitHub blip on one component would let a genuinely stale feed
/// report itself current — the vacuity this check must not have.
#[test]
fn an_unresolvable_release_does_not_yield_a_clean_bill() {
    let srv = TestServer::bind();
    // Serve the manifest but NOT the release endpoint, so resolution fails while the feed reads.
    let mut no_release = routes("12.17.0", "12.16.0");
    no_release.remove("/repos/DIG-Network/dig-app/releases/latest");
    let _guard = srv.serve(no_release);
    let source = GithubSource::with_api_base(&srv.base, None);
    let feed_base = format!("{}/v1", srv.base);

    let report = check_drift(
        &config(),
        &source,
        Channel::Stable,
        &manifest_url_for(&feed_base, Channel::Stable),
    )
    .expect("the served manifest is still readable");

    assert!(
        !report.is_current(),
        "an uncomparable component must not read as current: {}",
        report.render()
    );
    assert!(matches!(report.drifts.as_slice(), [Drift::Unknown { .. }]));
}

/// The nightly channel reads its own published document, not stable's. A checker that hard-coded
/// the stable path would silently check the wrong feed and never notice nightly going stale.
#[test]
fn the_nightly_channel_checks_the_nightly_feed() {
    let srv = TestServer::bind();
    let nightly_version = "12.18.0-nightly.20260817.abc1234";
    let routes = HashMap::from([
        (
            "/repos/DIG-Network/dig-app/releases/tags/nightly".to_string(),
            release_body(nightly_version),
        ),
        (
            "/v1/nightly/manifest.json".to_string(),
            served_manifest(nightly_version),
        ),
        // Stable's document is deliberately WRONG: if the check read it, the test would fail.
        (
            "/v1/stable/manifest.json".to_string(),
            served_manifest("0.0.0"),
        ),
    ]);
    let _guard = srv.serve(routes);
    let source = GithubSource::with_api_base(&srv.base, None);
    let feed_base = format!("{}/v1", srv.base);

    let report = check_drift(
        &config(),
        &source,
        Channel::Nightly,
        &manifest_url_for(&feed_base, Channel::Nightly),
    )
    .expect("the served nightly manifest is readable");

    assert!(
        report.is_current(),
        "the nightly feed matches its nightly release: {}",
        report.render()
    );
    assert!(report.manifest_url.ends_with("/v1/nightly/manifest.json"));
}
