//! End-to-end install-pass tests on every OS runner: a REAL local install of a DUMMY component
//! from a LOCALLY-SIGNED feed, driven through the broker's privileged apply path
//! ([`dig_updater_broker::Installer::apply`]).
//!
//! The feed is fetched + verified by the actual worker LIBRARY against a throwaway loopback HTTP
//! server (the exact production fetch/verify/stage path), producing the plan the broker then
//! re-verifies under the SAME test root key and installs. Every file operation — staging
//! re-verify, byte install, last-known-good snapshot, rollback restore — is real on disk; only the
//! `--version` probe (impractical to make a cross-OS executable report an arbitrary version in CI)
//! is injected, so the health-gate and enumeration BRANCHES are exercised deterministically while
//! the install/rollback mechanics stay real.
//!
//! Scenarios asserted: fresh-install, update, skip, health-fail → rollback → re-verify, a staging
//! TOCTOU swap → abort, a wrong-root plan → abort, and (Unix, where writability is exact)
//! ACL-violation → abort.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use dig_updater_broker::config::Channel;
use dig_updater_broker::{
    BrokerError, Catalog, ComponentResult, ComponentTarget, DetectedVersion, InstallMethod,
    InstalledBuildStore, Installer, LkgCache, Loadability, PassReport, RetryPolicy,
    TrustStateStore, VersionEvidence,
};
use dig_updater_trust::{
    Artifact, Component, Delegation, Manifest, SignedDelegation, SignedManifest, TrustState,
};
use dig_updater_worker::{run, FeedSource, Platform, VerifiedPlan, WorkerReport, WorkerRequest};

const FAR_FUTURE: u64 = 4_000_000_000;
const NOW: u64 = 600_000;

// --- deterministic test key material (unrelated to the pinned production key) ---

fn test_root() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}
fn test_targets() -> SigningKey {
    SigningKey::from_bytes(&[12u8; 32])
}
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- a throwaway loopback HTTP server, bound FIRST so its URL is known before the feed is built ---

struct Server {
    server: Arc<tiny_http::Server>,
    base: String,
}

struct Guard {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Server {
    fn bind() -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind loopback"));
        let port = server.server_addr().to_ip().unwrap().port();
        Self {
            server,
            base: format!("http://127.0.0.1:{port}"),
        }
    }

    fn serve(&self, routes: HashMap<String, Vec<u8>>) -> Guard {
        let stop = Arc::new(AtomicBool::new(false));
        let (server, st) = (Arc::clone(&self.server), Arc::clone(&stop));
        let handle = thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                if let Ok(Some(req)) = server.recv_timeout(Duration::from_millis(25)) {
                    let response = match routes.get(req.url()).cloned() {
                        Some(body) => tiny_http::Response::from_data(body),
                        None => tiny_http::Response::from_data(b"404".to_vec())
                            .with_status_code(tiny_http::StatusCode(404)),
                    };
                    let _ = req.respond(response);
                }
            }
        });
        Guard {
            stop,
            handle: Some(handle),
        }
    }
}

/// A host that can load anything — the honest default for every scenario whose subject is install
/// MECHANICS rather than host capability (dig_ecosystem#1870).
fn always_loadable(_: &Path) -> Loadability {
    Loadability::Loadable
}

/// The #1858 record store belonging beside `store`'s own state file, so each harness records what it
/// installs exactly where a production pass would.
fn records_beside(store: &TrustStateStore) -> InstalledBuildStore {
    InstalledBuildStore::for_channel(
        store
            .path()
            .parent()
            .expect("the state file has a directory"),
        Channel::Stable,
    )
}

/// A digest reader that PANICS if consulted — see the `digest:` field comment on each harness.
fn digest_must_not_be_read(path: &Path) -> Option<String> {
    panic!(
        "a component established by its `--version` probe must not be hashed: {}",
        path.display()
    )
}

// --- feed + worker helpers ---

/// The component name the digest-evidenced scenarios use — dig-app's real manifest name, since the
/// property under test is exactly the one the shipped catalog declares for it.
const DIGEST_COMPONENT: &str = "dig-app";

/// A manifest with one component ("digstore") whose single artifact targets THIS host and is
/// served at `{base}/artifact`.
fn manifest(base: &str, version: &str, build: u64, floor: u64, artifact: &[u8]) -> Manifest {
    manifest_for("digstore", base, version, build, floor, artifact)
}

/// [`manifest`] for an arbitrarily-NAMED component, so a scenario can drive a component whose catalog
/// entry declares a different evidence class.
fn manifest_for(
    name: &str,
    base: &str,
    version: &str,
    build: u64,
    floor: u64,
    artifact: &[u8],
) -> Manifest {
    let p = Platform::current();
    Manifest {
        schema: 1,
        root_version: 1,
        sequence: 100,
        generated: 500_000,
        expires: FAR_FUTURE,
        rollback_floor_build: floor,
        components: vec![Component {
            name: name.into(),
            version: version.into(),
            build,
            artifacts: vec![Artifact {
                os: p.os,
                arch: p.arch,
                url: format!("{base}/artifact"),
                sha256: hex(&Sha256::digest(artifact)),
                size: artifact.len() as u64,
            }],
        }],
    }
}

/// The 3-route test-signed feed for `manifest` + `artifact`.
fn routes(manifest: &Manifest, artifact: &[u8]) -> HashMap<String, Vec<u8>> {
    let delegation = SignedDelegation::sign(
        Delegation {
            root_version: 1,
            targets_pubkey: b64(&test_targets().verifying_key().to_bytes()),
            expires: FAR_FUTURE,
        },
        &test_root(),
    );
    let signed = SignedManifest::sign(manifest.clone(), &test_targets());
    HashMap::from([
        (
            "/delegation.json".to_string(),
            delegation.to_json().into_bytes(),
        ),
        ("/manifest.json".to_string(), signed.to_json().into_bytes()),
        ("/artifact".to_string(), artifact.to_vec()),
    ])
}

/// Run the worker LIBRARY against the served feed, returning the verified plan report (staged
/// artifact + raw feed bytes) the broker will re-verify + install.
fn stage(base: &str, staging: &Path) -> WorkerReport {
    let request = WorkerRequest {
        feed_sources: vec![FeedSource::new(base)],
        trust_state: TrustState::initial(),
        now: NOW,
        staging_dir: staging.to_string_lossy().into_owned(),
        platform: Platform::current(),
    };
    let plan: VerifiedPlan =
        run(&request, &test_root().verifying_key()).expect("the local test feed must verify");
    WorkerReport::Verified(plan)
}

/// Drive one apply pass: catalog points "digstore" at `dest`; `detect`/`health` are the injected
/// probes; the trust state + last-known-good cache live under `home`.
fn apply(
    root: &VerifyingKey,
    report: &WorkerReport,
    home: &Path,
    dest: &Path,
    detect: &dyn Fn(&Path) -> DetectedVersion,
    health: &dyn Fn(&Path) -> DetectedVersion,
) -> Result<PassReport, BrokerError> {
    apply_with_suppress(root, report, home, dest, detect, health, false)
}

/// As [`apply`], but lets a caller set `suppress_state_advance` (#621 item 1 — an overridden feed
/// installs but must not advance the tracked channel's persisted trust state).
#[allow(clippy::too_many_arguments)]
fn apply_with_suppress(
    root: &VerifyingKey,
    report: &WorkerReport,
    home: &Path,
    dest: &Path,
    detect: &dyn Fn(&Path) -> DetectedVersion,
    health: &dyn Fn(&Path) -> DetectedVersion,
    suppress_state_advance: bool,
) -> Result<PassReport, BrokerError> {
    let store = TrustStateStore::for_channel(home, Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let staging_dir = home.join("staging");
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).expect("apply dir");
    let catalog = Catalog::new(vec![ComponentTarget {
        name: "digstore".into(),
        method: InstallMethod::RawBinary,
        dest: dest.to_path_buf(),
        aliases: vec![],
        service: None,
        evidence: VersionEvidence::SafeToProbe,
    }]);
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
        // Every pre-#1870 scenario asserts install MECHANICS, so its host is declared able to load
        // what it installs; the refusal branch has its own fixture below.
        loadability: &always_loadable,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &staging_dir,
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect,
        health,
        // Every harness in this file drives a SafeToProbe component, whose version comes from its
        // probe — so reading a digest here would mean the planner or the health gate had consulted
        // the wrong evidence source, which this panicking reader makes observable.
        digest: &digest_must_not_be_read,
        service_ctl: &|_, _| Ok(()),
        suppress_state_advance,
    };
    installer.apply(root, report, loaded)
}

/// Drive one apply pass over a component declared [`VersionEvidence::ArtifactDigest`] — dig-app's
/// class (dig_ecosystem#1803) — with BOTH version probes wired to panic.
///
/// The panicking probes are the point of the harness: the guarantee is that a SYSTEM/root beacon never
/// EXECUTES this component, before or after installing it, and a probe that merely returned a mute
/// answer could not tell an exec that happened from one that did not. `digest` is injected so the
/// honest-reader and lying-reader cases can both be driven; the install itself is real bytes on disk.
fn apply_digest_evidenced(
    root: &VerifyingKey,
    report: &WorkerReport,
    home: &Path,
    dest: &Path,
    digest: &dyn Fn(&Path) -> Option<String>,
) -> Result<PassReport, BrokerError> {
    let store = TrustStateStore::for_channel(home, Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let staging_dir = home.join("staging");
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).expect("apply dir");
    let catalog = Catalog::new(vec![ComponentTarget {
        name: DIGEST_COMPONENT.into(),
        method: InstallMethod::RawBinary,
        dest: dest.to_path_buf(),
        aliases: vec![],
        service: None,
        evidence: VersionEvidence::ArtifactDigest,
    }]);
    let never_execute = |path: &Path| -> DetectedVersion {
        panic!(
            "the beacon EXECUTED {} — a digest-evidenced component is never run, at any version, on \
             any path (dig_ecosystem#1803)",
            path.display()
        )
    };
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
        // Every pre-#1870 scenario asserts install MECHANICS, so its host is declared able to load
        // what it installs; the refusal branch has its own fixture below.
        loadability: &always_loadable,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &staging_dir,
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect: &never_execute,
        health: &never_execute,
        digest,
        service_ctl: &|_, _| Ok(()),
        suppress_state_advance: false,
    };
    installer.apply(root, report, loaded)
}

// =============================== the scenarios ===============================

#[test]
fn a_digest_evidenced_component_installs_without_ever_being_executed() {
    // dig_ecosystem#1803 end to end, with the PRODUCTION digest reader and real bytes: a component
    // the beacon may never run is nonetheless brought current and health-gated, because the evidence
    // is the signed manifest's artifact digest measured against the file on disk.
    //
    // Both probes panic, so this cannot pass on an implementation that executes the component
    // anywhere on the path — including the post-install health gate, which is the second exec site
    // and the one a plan-only fix would leave open. The health gate is a REAL re-hash of the
    // just-installed bytes via `installed_digest_hex`, so it is a genuine gate rather than an
    // exemption: it can only pass because the installed bytes actually are the promised artifact.
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("dig-app");

    let artifact = b"the-dig-app-3.4.0-binary-bytes";
    let server = Server::bind();
    let m = manifest_for(
        DIGEST_COMPONENT,
        &server.base,
        "3.4.0",
        3_004_000,
        0,
        artifact,
    );
    let _guard = server.serve(routes(&m, artifact));
    let report = stage(&server.base, &home.path().join("staging"));

    let out = apply_digest_evidenced(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &dig_updater_broker::installed_digest_hex,
    )
    .expect("the pass applies");

    let line = &out.components[0];
    assert_eq!(
        line.result,
        ComponentResult::Installed,
        "a digest-evidenced component installs like any other: {}",
        line.detail
    );
    assert_eq!(
        std::fs::read(&dest).expect("the binary is on disk"),
        artifact,
        "the installed bytes are the verified artifact"
    );
    assert_eq!(
        dig_updater_broker::installed_digest_hex(&dest).as_deref(),
        Some(hex(&Sha256::digest(artifact)).as_str()),
        "and they hash to the digest the signed manifest promised"
    );
    assert!(out.state_advanced, "a fully successful pass advances state");
}

#[test]
fn a_digest_evidenced_component_rolls_back_when_the_post_install_digest_does_not_match() {
    // The health gate's FAILING arm, which is what makes the digest re-hash a gate rather than a
    // rubber stamp. The reader answers a digest that is never the manifest's, so the pass installs
    // and then cannot prove the bytes at the destination are the promised build — and must roll the
    // component back instead of reporting a success it did not verify.
    //
    // The same reader also drives enumeration, so the component is correctly planned as an Update
    // first: the fixture exercises the whole plan → install → gate → rollback path, not just the gate
    // in isolation. The probes still panic, so failing the gate must not fall back to executing it.
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("dig-app");

    let artifact = b"the-dig-app-3.4.0-binary-bytes";
    let server = Server::bind();
    let m = manifest_for(
        DIGEST_COMPONENT,
        &server.base,
        "3.4.0",
        3_004_000,
        0,
        artifact,
    );
    let _guard = server.serve(routes(&m, artifact));
    let report = stage(&server.base, &home.path().join("staging"));

    let a_digest_that_is_never_the_manifests = "0".repeat(64);
    let out = apply_digest_evidenced(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &|_| Some(a_digest_that_is_never_the_manifests.clone()),
    )
    .expect("a rolled-back component is a reported outcome, not a pass failure");

    let line = &out.components[0];
    assert_eq!(line.result, ComponentResult::RolledBack);
    assert!(
        line.detail.contains("digest check failed"),
        "the detail must name the digest as what failed, not a version probe: {}",
        line.detail
    );
    assert!(
        !out.state_advanced,
        "a pass with a rolled-back component must not advance the trust state"
    );
}

#[test]
fn fresh_install_places_bytes_and_advances_state() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("digstore");

    let artifact = b"the-new-digstore-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // Nothing installed yet → Install; the post-install probe reports the new version → healthy.
    let detect = |_: &Path| DetectedVersion::Absent;
    let health = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let result = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect("apply succeeds");

    assert!(result.applied);
    assert_eq!(result.components.len(), 1);
    assert_eq!(result.components[0].result, ComponentResult::Installed);
    assert!(
        result.state_advanced,
        "a fully-successful pass advances state"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        artifact,
        "real bytes installed"
    );
    assert!(
        home.path().join("trust-state-stable.json").exists(),
        "state persisted"
    );
    assert_state_dir_hardened(home.path());
}

#[test]
fn an_overridden_feed_installs_the_bytes_but_never_advances_the_tracked_channel_state() {
    // #621 item 1: a real pass with an out-of-band `--feed-base`/`$DIG_UPDATER_FEED_BASE` override
    // may fetch marks on a DIFFERENT channel's version scale than the tracked channel. Folding those
    // into the tracked channel's monotonic trust state would corrupt its anti-rollback floor (a
    // below-floor self-DoS the operator could not easily undo). So `suppress_state_advance` installs
    // the bytes as normal but WITHHOLDS the state advance — nothing is persisted for the channel.
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("digstore");

    let artifact = b"an-override-fetched-digstore-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let detect = |_: &Path| DetectedVersion::Absent;
    let health = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let result = apply_with_suppress(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
        true, // feed overridden → suppress the state advance
    )
    .expect("apply succeeds even when state advance is suppressed");

    assert!(result.applied);
    assert_eq!(result.components[0].result, ComponentResult::Installed);
    assert!(
        !result.state_advanced,
        "an overridden-feed pass must NOT advance the tracked channel's trust state"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        artifact,
        "the bytes are still installed — only the state advance is withheld"
    );
    assert!(
        !home.path().join("trust-state-stable.json").exists(),
        "no trust state is persisted for the tracked channel from an off-channel override feed"
    );
}

#[test]
fn update_replaces_an_older_binary() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");
    std::fs::write(&dest, b"OLD-digstore-0.1.0-binary").unwrap();

    let artifact = b"the-new-digstore-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let detect = |_: &Path| DetectedVersion::Present("digstore 0.1.0".to_string());
    let health = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let result = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect("apply succeeds");

    assert_eq!(result.components[0].result, ComponentResult::Installed);
    assert_eq!(result.components[0].action, "update");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        artifact,
        "older binary replaced"
    );
    assert!(result.state_advanced);
}

#[test]
fn skip_leaves_a_current_binary_untouched() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");
    std::fs::write(&dest, b"already-current-0.2.0").unwrap();

    let artifact = b"the-new-digstore-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // Installed == latest → Skip; health is not consulted.
    let detect = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let health = |_: &Path| DetectedVersion::Absent;
    let result = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect("apply succeeds");

    assert_eq!(result.components[0].result, ComponentResult::Skipped);
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"already-current-0.2.0",
        "a skip must not touch the binary"
    );
    assert!(
        result.state_advanced,
        "an all-current pass is fully applied"
    );
}

#[test]
fn health_failure_rolls_back_to_the_reverified_previous_build() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");
    let old_bytes = b"GOOD-old-digstore-0.1.0-binary";
    std::fs::write(&dest, old_bytes).unwrap();

    let artifact = b"the-new-but-broken-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // Older build present → Update; but the post-install probe STILL reports 0.1.0 (the new build
    // did not take) → unhealthy → rollback to the re-verified previous build.
    let detect = |_: &Path| DetectedVersion::Present("digstore 0.1.0".to_string());
    let health = |_: &Path| DetectedVersion::Present("digstore 0.1.0".to_string());
    let result = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect("apply completes with a rollback");

    assert_eq!(result.components[0].result, ComponentResult::RolledBack);
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        old_bytes,
        "the previous good binary is restored"
    );
    assert!(
        !result.state_advanced,
        "a rolled-back pass must NOT advance the trust state"
    );
    assert!(
        !home.path().join("trust-state-stable.json").exists(),
        "no state write on a failed pass"
    );
}

#[test]
fn staging_toctou_swap_aborts_the_pass() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");

    let artifact = b"the-honest-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // Simulate a TOCTOU: after the worker staged + reported, an attacker swaps the staged bytes.
    if let WorkerReport::Verified(plan) = &report {
        std::fs::write(
            &plan.artifacts[0].staged_path,
            b"malicious-substituted-bytes",
        )
        .unwrap();
    }

    let detect = |_: &Path| DetectedVersion::Absent;
    let health = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let err = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect_err("swapped staged bytes must abort the pass");
    assert!(matches!(err, BrokerError::StagingReverifyFailed { .. }));
    assert!(
        !dest.exists(),
        "nothing installed when staging re-verify fails"
    );
}

#[test]
fn a_staged_path_outside_staging_is_rejected_by_the_pass() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");

    let artifact = b"honest-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let mut report = stage(&srv.base, &home.path().join("staging"));

    // A compromised worker points the broker at a file OUTSIDE its staging dir. Even the RIGHT
    // bytes at the wrong location must be refused — the broker only installs what it controls.
    let outside = tempfile::tempdir().unwrap();
    let evil = outside.path().join("evil");
    std::fs::write(&evil, artifact).unwrap();
    if let WorkerReport::Verified(plan) = &mut report {
        plan.artifacts[0].staged_path = evil.to_string_lossy().into_owned();
    }

    let detect = |_: &Path| DetectedVersion::Absent;
    let health = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let err = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect_err("a staged path outside the staging dir must abort the pass");
    assert!(matches!(err, BrokerError::StagedPathEscapesStaging { .. }));
    assert!(
        !dest.exists(),
        "nothing installed when the staged path is refused"
    );
}

#[test]
fn a_plan_that_does_not_chain_to_the_pinned_root_is_rejected_on_reverify() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");

    let artifact = b"artifact";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // The worker verified under `test_root`; the broker re-verifies under a DIFFERENT pinned root
    // — modelling a plan whose feed does not chain to the broker's key. It must be rejected.
    let other_root = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
    let detect = |_: &Path| DetectedVersion::Absent;
    let health = |_: &Path| DetectedVersion::Present("digstore 0.2.0".to_string());
    let err = apply(&other_root, &report, home.path(), &dest, &detect, &health)
        .expect_err("a plan that does not chain to the broker's pinned root is rejected");
    assert!(matches!(err, BrokerError::ReverifyFailed(_)));
    assert!(!dest.exists(), "nothing installed when re-verify fails");
}

/// A manifest with TWO components — the beacon's own ("dig-updater", listed FIRST) and an
/// ordinary one ("digstore") — each with its own artifact served at a distinct URL.
fn manifest_with_self_and_other(
    base: &str,
    self_artifact: &[u8],
    other_artifact: &[u8],
) -> Manifest {
    let p = Platform::current();
    Manifest {
        schema: 1,
        root_version: 1,
        sequence: 100,
        generated: 500_000,
        expires: FAR_FUTURE,
        rollback_floor_build: 0,
        components: vec![
            Component {
                name: "dig-updater".into(),
                version: "0.6.0".into(),
                build: 6_000,
                artifacts: vec![Artifact {
                    os: p.os.clone(),
                    arch: p.arch.clone(),
                    url: format!("{base}/self-artifact"),
                    sha256: hex(&Sha256::digest(self_artifact)),
                    size: self_artifact.len() as u64,
                }],
            },
            Component {
                name: "digstore".into(),
                version: "0.2.0".into(),
                build: 2_000,
                artifacts: vec![Artifact {
                    os: p.os,
                    arch: p.arch,
                    url: format!("{base}/other-artifact"),
                    sha256: hex(&Sha256::digest(other_artifact)),
                    size: other_artifact.len() as u64,
                }],
            },
        ],
    }
}

/// The signed-feed routes for [`manifest_with_self_and_other`]'s two distinct artifact URLs.
fn routes_with_self_and_other(
    manifest: &Manifest,
    self_artifact: &[u8],
    other_artifact: &[u8],
) -> HashMap<String, Vec<u8>> {
    let delegation = SignedDelegation::sign(
        Delegation {
            root_version: 1,
            targets_pubkey: b64(&test_targets().verifying_key().to_bytes()),
            expires: FAR_FUTURE,
        },
        &test_root(),
    );
    let signed = SignedManifest::sign(manifest.clone(), &test_targets());
    HashMap::from([
        (
            "/delegation.json".to_string(),
            delegation.to_json().into_bytes(),
        ),
        ("/manifest.json".to_string(), signed.to_json().into_bytes()),
        ("/self-artifact".to_string(), self_artifact.to_vec()),
        ("/other-artifact".to_string(), other_artifact.to_vec()),
    ])
}

/// Drive a two-component pass ("dig-updater" self + "digstore" other) and return the report,
/// generalizing [`apply`] to a caller-supplied catalog (both components share one retry policy).
fn apply_self_and_other(
    report: &WorkerReport,
    home: &Path,
    self_dest: &Path,
    other_dest: &Path,
) -> PassReport {
    let store = TrustStateStore::for_channel(home, Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let staging_dir = home.join("staging");
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).unwrap();
    let catalog = Catalog::new(vec![
        ComponentTarget {
            name: "dig-updater".into(),
            method: InstallMethod::RawBinary,
            dest: self_dest.to_path_buf(),
            aliases: vec![],
            service: None,
            evidence: VersionEvidence::SafeToProbe,
        },
        ComponentTarget {
            name: "digstore".into(),
            method: InstallMethod::RawBinary,
            dest: other_dest.to_path_buf(),
            aliases: vec![],
            service: None,
            evidence: VersionEvidence::SafeToProbe,
        },
    ]);
    let platform = Platform::current();
    let detect = |_: &Path| DetectedVersion::Absent;
    let health = |p: &Path| {
        if p == self_dest {
            DetectedVersion::Present("dig-updater 0.6.0".to_string())
        } else {
            DetectedVersion::Present("digstore 0.2.0".to_string())
        }
    };
    let installer = Installer {
        store: &store,
        // Every pre-#1870 scenario asserts install MECHANICS, so its host is declared able to load
        // what it installs; the refusal branch has its own fixture below.
        loadability: &always_loadable,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &staging_dir,
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 1,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect: &detect,
        health: &health,
        // A SafeToProbe component's version comes from its probe; hashing it here would mean the
        // wrong evidence source was consulted, which this panicking reader makes observable.
        digest: &digest_must_not_be_read,
        service_ctl: &|_, _| Ok(()),
        suppress_state_advance: false,
    };
    installer
        .apply(&test_root().verifying_key(), report, loaded)
        .expect("apply completes")
}

#[test]
fn self_update_is_reported_after_every_other_component() {
    // Both components are fresh installs (SPEC §8.1: self applies LAST, but nothing stops it from
    // succeeding when everything else does too) — this proves the ORDERING half of the contract
    // on every OS; the Windows-only test below proves the trust-state-INDEPENDENCE half using a
    // deterministic self-install failure that has no portable Unix equivalent (see its comment).
    let home = tempfile::tempdir().unwrap();
    let self_dest = home.path().join("dig-updater");
    let other_dest = home.path().join("digstore");

    let self_artifact = b"the-new-beacon-binary";
    let other_artifact = b"the-new-digstore-binary";
    let srv = Server::bind();
    let m = manifest_with_self_and_other(&srv.base, self_artifact, other_artifact);
    let _guard = srv.serve(routes_with_self_and_other(
        &m,
        self_artifact,
        other_artifact,
    ));
    let report = stage(&srv.base, &home.path().join("staging"));

    let result = apply_self_and_other(&report, home.path(), &self_dest, &other_dest);

    assert_eq!(result.components.len(), 2, "both components reported");
    assert_eq!(
        result.components[0].component, "digstore",
        "the ordinary component is reported BEFORE the beacon's own — self applies LAST"
    );
    assert_eq!(
        result.components[1].component, "dig-updater",
        "the beacon's own component is reported LAST"
    );
    assert_eq!(result.components[0].result, ComponentResult::Installed);
    assert_eq!(result.components[1].result, ComponentResult::Installed);
    assert!(result.state_advanced);
    assert_eq!(std::fs::read(&self_dest).unwrap(), self_artifact);
    assert_eq!(std::fs::read(&other_dest).unwrap(), other_artifact);
}

#[cfg(windows)]
#[test]
fn a_deferred_self_update_never_gates_the_other_components_state_advance() {
    // Force the self-swap to fail deterministically WITHOUT touching its destination's type or
    // its parent directory (either of which would abort the whole pass earlier, at the snapshot
    // or staging step, rather than exercising the install step this test targets): hold `dest`
    // open with an EXPLICIT share mode that grants read (so the snapshot's digest read succeeds)
    // but denies write/delete (so any RENAME onto it fails) — Rust's std actually opens files
    // with all three share flags by default (incl. `FILE_SHARE_DELETE`), so reproducing "locked
    // against rename" on Windows needs this explicit override. Unix has no equivalent — a rename
    // there succeeds against an open file by design (see `selfupdate.rs`), which is exactly why
    // this half of the contract is Windows-only.
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    let home = tempfile::tempdir().unwrap();
    let self_dest = home.path().join("dig-updater.exe");
    let other_dest = home.path().join("digstore.exe");
    std::fs::write(&self_dest, b"old-beacon-bytes").unwrap();
    let _holds_dest_open_read_only_share = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&self_dest)
        .unwrap();

    let self_artifact = b"the-new-beacon-binary";
    let other_artifact = b"the-new-digstore-binary";
    let srv = Server::bind();
    let m = manifest_with_self_and_other(&srv.base, self_artifact, other_artifact);
    let _guard = srv.serve(routes_with_self_and_other(
        &m,
        self_artifact,
        other_artifact,
    ));
    let report = stage(&srv.base, &home.path().join("staging"));

    let result = apply_self_and_other(&report, home.path(), &self_dest, &other_dest);

    assert_eq!(result.components[0].component, "digstore");
    assert_eq!(result.components[0].result, ComponentResult::Installed);
    assert_eq!(result.components[1].component, "dig-updater");
    assert_ne!(
        result.components[1].result,
        ComponentResult::Installed,
        "the held-open destination must block the self-swap: {:?}",
        result.components[1].result
    );
    assert!(
        result.state_advanced,
        "digstore's success alone must advance state — the self component's outcome never gates it"
    );
    assert_eq!(std::fs::read(&other_dest).unwrap(), other_artifact);
}

#[cfg(unix)]
#[test]
fn acl_self_check_aborts_on_a_world_writable_binary() {
    use dig_updater_broker::{secure::acl_self_check, Repair};
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let fake_binary = dir.path().join("dig-updater");
    std::fs::write(&fake_binary, b"pretend-beacon").unwrap();
    std::fs::set_permissions(&fake_binary, std::fs::Permissions::from_mode(0o666)).unwrap();

    let err = acl_self_check(&[(fake_binary, Repair::Never)])
        .expect_err("a world-writable beacon binary must abort the pass fail-closed");
    assert!(matches!(err, BrokerError::AclViolation { .. }));
}

// --- assertions ---

/// The state dir is hardened before the first save (SPEC §6/§9.3, #504-E). On Unix that is exactly
/// checkable (owner-only); on Windows the `icacls` DACL is applied but not asserted here.
fn assert_state_dir_hardened(dir: &Path) {
    let _ = dir;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "state dir must be owner-only after a state-advancing pass"
        );
    }
}

// =============================== #666 Bug B — service stop → replace → restart ===============================

use std::sync::Mutex;

use dig_updater_broker::{ServiceAction, ServiceControl};

/// Drive one apply pass with a service-backed "digstore" component (its OS service id set to
/// `service_id`) and a RECORDING service controller, so the stop→replace→restart ORDERING + the
/// failure handling are observable without touching a real service manager (#666 Bug B).
fn apply_with_service(
    report: &WorkerReport,
    home: &Path,
    dest: &Path,
    service_id: &str,
    detect: &dyn Fn(&Path) -> DetectedVersion,
    health: &dyn Fn(&Path) -> DetectedVersion,
    service_ctl: &ServiceControl,
) -> PassReport {
    let store = TrustStateStore::for_channel(home, Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let staging_dir = home.join("staging");
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).expect("apply dir");
    let catalog = Catalog::new(vec![ComponentTarget {
        name: "digstore".into(),
        method: InstallMethod::RawBinary,
        dest: dest.to_path_buf(),
        aliases: vec![],
        service: Some(service_id.to_string()),
        evidence: VersionEvidence::SafeToProbe,
    }]);
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
        // Every pre-#1870 scenario asserts install MECHANICS, so its host is declared able to load
        // what it installs; the refusal branch has its own fixture below.
        loadability: &always_loadable,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &staging_dir,
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect,
        health,
        // These harnesses drive SafeToProbe components (primary + aliases), established by their
        // probes — a digest read here would mean the wrong evidence source was consulted.
        digest: &digest_must_not_be_read,
        service_ctl,
        suppress_state_advance: false,
    };
    installer
        .apply(&test_root().verifying_key(), report, loaded)
        .expect("apply completes")
}

#[test]
fn a_service_backed_component_is_stopped_before_replace_and_restarted_after_666b() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("dig-node");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"OLD-0.32.0").unwrap();

    let artifact = b"the-new-0.33.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.33.0", 33_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let calls: Mutex<Vec<ServiceAction>> = Mutex::new(Vec::new());
    let ctl = |_: &str, action: ServiceAction| {
        calls.lock().unwrap().push(action);
        Ok(())
    };
    let detect = |_: &Path| DetectedVersion::Present("dig-node 0.32.0".to_string());
    let health = |_: &Path| DetectedVersion::Present("dig-node 0.33.0".to_string());
    let result = apply_with_service(
        &report,
        home.path(),
        &dest,
        "net.dignetwork.dig-node",
        &detect,
        &health,
        &ctl,
    );

    assert_eq!(result.components[0].result, ComponentResult::Installed);
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        artifact,
        "the new bytes landed"
    );
    // The lock was released BEFORE the replace and the service brought back AFTER — in that order.
    assert_eq!(
        *calls.lock().unwrap(),
        vec![ServiceAction::Stop, ServiceAction::Start],
        "the service is stopped before the replace and restarted after it"
    );
}

#[test]
fn a_service_is_restarted_even_when_the_replace_rolls_back_666b() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("dig-node");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"OLD-0.32.0").unwrap();

    let artifact = b"the-new-0.33.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.33.0", 33_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let calls: Mutex<Vec<ServiceAction>> = Mutex::new(Vec::new());
    let ctl = |_: &str, action: ServiceAction| {
        calls.lock().unwrap().push(action);
        Ok(())
    };
    // The post-install probe reports the OLD version → the health gate fails → rollback.
    let detect = |_: &Path| DetectedVersion::Present("dig-node 0.32.0".to_string());
    let health = |_: &Path| DetectedVersion::Present("dig-node 0.32.0".to_string());
    let result = apply_with_service(
        &report,
        home.path(),
        &dest,
        "net.dignetwork.dig-node",
        &detect,
        &health,
        &ctl,
    );

    assert_eq!(result.components[0].result, ComponentResult::RolledBack);
    assert!(
        calls.lock().unwrap().contains(&ServiceAction::Start),
        "a stopped service must be restarted even on a failed/rolled-back replace — never left down"
    );
}

#[test]
fn a_service_that_cannot_be_stopped_defers_and_is_left_running_666b() {
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("bin").join("dig-node");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"OLD-0.32.0").unwrap();

    let artifact = b"the-new-0.33.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.33.0", 33_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let calls: Mutex<Vec<ServiceAction>> = Mutex::new(Vec::new());
    let ctl = |_: &str, action: ServiceAction| {
        calls.lock().unwrap().push(action);
        match action {
            ServiceAction::Stop => Err("service refused to stop".to_string()),
            ServiceAction::Start => Ok(()),
        }
    };
    let detect = |_: &Path| DetectedVersion::Present("dig-node 0.32.0".to_string());
    let health = |_: &Path| DetectedVersion::Present("dig-node 0.33.0".to_string());
    let result = apply_with_service(
        &report,
        home.path(),
        &dest,
        "net.dignetwork.dig-node",
        &detect,
        &health,
        &ctl,
    );

    // The stop failed, so the binary is still locked: defer the replace, and NEVER issue a Start
    // (the service was never taken down) — the old bytes stay in place, byte-intact.
    assert_eq!(result.components[0].result, ComponentResult::Deferred);
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"OLD-0.32.0",
        "the replace was not attempted"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec![ServiceAction::Stop],
        "a failed stop is never followed by a start — the service was left running"
    );
}

// =============================== #666 F1/F2/F3 — whole-set rollback, restart-on-error, stale-alias re-drive ===============================

/// Drive one apply pass over a component with ALIASES (+ optional service), so the whole-set
/// snapshot/rollback (#666 F2) and the guaranteed restart-on-error (#666 F1) are observable.
#[allow(clippy::too_many_arguments)] // a test harness threading each injected probe/ctl explicitly
fn apply_aliased(
    report: &WorkerReport,
    home: &Path,
    dest: &Path,
    aliases: Vec<std::path::PathBuf>,
    service_id: Option<&str>,
    detect: &dyn Fn(&Path) -> DetectedVersion,
    health: &dyn Fn(&Path) -> DetectedVersion,
    service_ctl: &ServiceControl,
) -> Result<PassReport, BrokerError> {
    let store = TrustStateStore::for_channel(home, Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let staging_dir = home.join("staging");
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).expect("apply dir");
    let catalog = Catalog::new(vec![ComponentTarget {
        name: "digstore".into(),
        method: InstallMethod::RawBinary,
        dest: dest.to_path_buf(),
        aliases,
        service: service_id.map(str::to_string),
        evidence: VersionEvidence::SafeToProbe,
    }]);
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
        // Every pre-#1870 scenario asserts install MECHANICS, so its host is declared able to load
        // what it installs; the refusal branch has its own fixture below.
        loadability: &always_loadable,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &staging_dir,
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect,
        health,
        // These harnesses drive SafeToProbe components (primary + aliases), established by their
        // probes — a digest read here would mean the wrong evidence source was consulted.
        digest: &digest_must_not_be_read,
        service_ctl,
        suppress_state_advance: false,
    };
    installer.apply(&test_root().verifying_key(), report, loaded)
}

#[test]
fn a_failed_health_rolls_back_the_whole_set_no_split_primary_alias_666f2() {
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let primary = bin.join("digstore");
    let alias = bin.join("digs");
    std::fs::write(&primary, b"OLD-0.14.0").unwrap();
    std::fs::write(&alias, b"OLD-0.14.0").unwrap();

    let artifact = b"the-new-0.15.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.15.0", 15_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // The install lands the new bytes on BOTH primary and alias, but the health probe reports the
    // OLD version → the gate fails → the WHOLE set must roll back (no primary-new/alias-old split).
    let detect = |_: &Path| DetectedVersion::Present("digstore 0.14.0".to_string());
    let health = |_: &Path| DetectedVersion::Present("digstore 0.14.0".to_string());
    let ctl = |_: &str, _: ServiceAction| Ok(());
    let result = apply_aliased(
        &report,
        home.path(),
        &primary,
        vec![alias.clone()],
        None,
        &detect,
        &health,
        &ctl,
    )
    .expect("apply completes");

    assert_eq!(result.components[0].result, ComponentResult::RolledBack);
    assert_eq!(
        std::fs::read(&primary).unwrap(),
        b"OLD-0.14.0",
        "primary rolled back"
    );
    assert_eq!(
        std::fs::read(&alias).unwrap(),
        b"OLD-0.14.0",
        "#666 F2: the alias is rolled back too — never left new while the primary is old"
    );
}

// #666 F1 (restart guaranteed even when the ROLLBACK itself errors) is proven by the deterministic
// unit test `pass::tests::restart_fires_even_when_the_rollback_itself_errors_666f1`, which injects a
// rollback error into `restart_after` and asserts a Start still fires before the error propagates —
// a cleaner, non-flaky injection than trying to corrupt the live LKG cache mid-pass here.

#[test]
fn a_stale_alias_is_re_refreshed_on_a_later_pass_even_when_the_primary_is_current_666f3() {
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let primary = bin.join("digstore");
    let alias = bin.join("digs");
    // Primary already current at 0.15.0; alias left stale at 0.14.0 by a prior deferred pass.
    std::fs::write(&primary, b"current-0.15.0").unwrap();
    std::fs::write(&alias, b"STALE-0.14.0").unwrap();

    let artifact = b"the-0.15.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.15.0", 15_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    // Primary probes 0.15.0 (current) but the alias probes 0.14.0 (stale). Enumeration must re-drive
    // the set as an Update, refresh the alias, and — post-refresh — the alias probes 0.15.0.
    let detect = |p: &Path| {
        if p.ends_with("digs") {
            DetectedVersion::Present("digstore 0.14.0".to_string())
        } else {
            DetectedVersion::Present("digstore 0.15.0".to_string())
        }
    };
    let health = |_: &Path| DetectedVersion::Present("digstore 0.15.0".to_string());
    let ctl = |_: &str, _: ServiceAction| Ok(());
    let result = apply_aliased(
        &report,
        home.path(),
        &primary,
        vec![alias.clone()],
        None,
        &detect,
        &health,
        &ctl,
    )
    .expect("apply completes");

    assert_eq!(
        result.components[0].result,
        ComponentResult::Installed,
        "#666 F3: a current primary with a stale alias is re-driven and refreshed, not skipped"
    );
    assert_eq!(
        std::fs::read(&alias).unwrap(),
        artifact,
        "the stale alias was refreshed to the verified bytes"
    );
}

/// A manifest with an ordinary component ("digstore") beside the per-user daemon ("dig-app"), each
/// with its own artifact URL — the shape a real host sees now that dig-app is in the feed (§10.3).
fn manifest_with_dig_app(base: &str, other_artifact: &[u8], dig_app_artifact: &[u8]) -> Manifest {
    let p = Platform::current();
    Manifest {
        components: vec![
            Component {
                name: "digstore".into(),
                version: "0.2.0".into(),
                build: 2_000,
                artifacts: vec![Artifact {
                    os: p.os.clone(),
                    arch: p.arch.clone(),
                    url: format!("{base}/other-artifact"),
                    sha256: hex(&Sha256::digest(other_artifact)),
                    size: other_artifact.len() as u64,
                }],
            },
            Component {
                name: "dig-app".into(),
                version: "3.4.0".into(),
                build: 3_004_000,
                artifacts: vec![Artifact {
                    os: p.os,
                    arch: p.arch,
                    url: format!("{base}/self-artifact"),
                    sha256: hex(&Sha256::digest(dig_app_artifact)),
                    size: dig_app_artifact.len() as u64,
                }],
            },
        ],
        ..manifest(base, "0.2.0", 2_000, 0, other_artifact)
    }
}

/// A REAL pass over a host running an unsafe-to-probe `dig-app` beside an out-of-date `digstore`
/// (dig_ecosystem#1746/#1749).
///
/// The fixture varies ONE actor: dig-app is declared unsafe to probe, while digstore answers honestly
/// and is genuinely stale — the truthful control that makes a hold distinguishable from an abandoned
/// pass. Both artifacts are really downloaded, verified and staged by the worker, so nothing but the
/// applier's own decision keeps dig-app's bytes off disk.
///
/// Two load-bearing assertions, because the design has two distinct failure modes:
///
/// - **The probe is never called for dig-app.** In production `detect` EXECUTES the target, and
///   dig-app <= 3.3.0 treats any argument as "boot the identity agent" — under SYSTEM, sealing a
///   master seed and binding a signing socket. Both injected probes panic on dig-app's path, so this
///   whole pass fails if the privileged exec happens anywhere: enumeration OR the health gate.
/// - **The destination file is byte-untouched and no `.dig-updater-old` sibling exists.** A hold
///   placed at the wrong layer — filtering in `Plan::actionable`, or skipping late in the apply loop —
///   satisfies "dig-app is not reported as Installed" identically while already having written the
///   file. (A rollback would restore the bytes, so the `Held` RESULT assertion is what catches that
///   variant; the move-aside sibling is what catches a swap that landed and was reverted.)
#[test]
fn an_unsafe_to_probe_dig_app_is_held_unexecuted_while_its_stale_sibling_really_installs() {
    let home = tempfile::tempdir().unwrap();
    let digstore_dest = home.path().join("bin").join("digstore");
    let dig_app_dest = home.path().join("bin").join("dig-app");

    let digstore_artifact = b"the-new-digstore-0.2.0-binary";
    let dig_app_artifact = b"the-new-dig-app-3.4.0-binary";
    let srv = Server::bind();
    let m = manifest_with_dig_app(&srv.base, digstore_artifact, dig_app_artifact);
    let _guard = srv.serve(routes_with_self_and_other(
        &m,
        dig_app_artifact,
        digstore_artifact,
    ));
    let report = stage(&srv.base, &home.path().join("staging"));

    // dig-app IS installed (a real file on disk, so the hold cannot be an artefact of it being
    // absent) and both probes REFUSE to run it; digstore honestly reports a stale 0.1.0.
    std::fs::create_dir_all(dig_app_dest.parent().unwrap()).unwrap();
    std::fs::write(&dig_app_dest, b"the-running-dig-app-3.3.0-binary").unwrap();
    let refuse_to_exec_dig_app = |p: &Path, stage: &str| {
        assert!(
            !p.ends_with("dig-app"),
            "the pass EXECUTED dig-app at {stage} — under SYSTEM that boots the identity agent, \
             seals a master seed and binds a signing socket (dig_ecosystem#1746)"
        );
    };
    let detect = |p: &Path| {
        refuse_to_exec_dig_app(p, "enumeration");
        DetectedVersion::Present("digstore 0.1.0".to_string())
    };
    let health = |p: &Path| {
        refuse_to_exec_dig_app(p, "the health gate");
        DetectedVersion::Present("digstore 0.2.0".to_string())
    };

    let store = TrustStateStore::for_channel(home.path(), Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.path().join("lkg"));
    let apply_dir = home.path().join("apply");
    std::fs::create_dir_all(&apply_dir).unwrap();
    let catalog = Catalog::new(vec![
        ComponentTarget {
            name: "digstore".into(),
            method: InstallMethod::RawBinary,
            dest: digstore_dest.clone(),
            aliases: vec![],
            service: None,
            evidence: VersionEvidence::SafeToProbe,
        },
        ComponentTarget {
            name: "dig-app".into(),
            method: InstallMethod::RawBinary,
            dest: dig_app_dest.clone(),
            aliases: vec![],
            service: None,
            evidence: VersionEvidence::UnsafeToProbe,
        },
    ]);
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
        // Every pre-#1870 scenario asserts install MECHANICS, so its host is declared able to load
        // what it installs; the refusal branch has its own fixture below.
        loadability: &always_loadable,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &home.path().join("staging"),
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 1,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect: &detect,
        health: &health,
        // A SafeToProbe component's version comes from its probe; hashing it here would mean the
        // wrong evidence source was consulted, which this panicking reader makes observable.
        digest: &digest_must_not_be_read,
        service_ctl: &|_, _| Ok(()),
        suppress_state_advance: false,
    };
    let result = installer
        .apply(&test_root().verifying_key(), &report, loaded)
        .expect("a held component never fails the pass");

    let digstore = result
        .components
        .iter()
        .find(|c| c.component == "digstore")
        .expect("digstore is reported");
    assert_eq!(
        digstore.result,
        ComponentResult::Installed,
        "holding dig-app must not abandon the pass: {}",
        digstore.detail
    );
    assert_eq!(
        std::fs::read(&digstore_dest).unwrap(),
        digstore_artifact,
        "the control component's verified bytes really landed"
    );

    let dig_app = result
        .components
        .iter()
        .find(|c| c.component == "dig-app")
        .expect("a held component is REPORTED, never silently dropped from the pass");
    assert_eq!(dig_app.result, ComponentResult::Held);
    assert_eq!(dig_app.action, "hold");
    assert!(
        dig_app.detail.contains("did not run it"),
        "the hold states that the binary was NOT executed: {}",
        dig_app.detail
    );
    assert_eq!(
        std::fs::read(&dig_app_dest).unwrap(),
        b"the-running-dig-app-3.3.0-binary",
        "the held component's binary is BYTE-UNTOUCHED — never installed over, never rolled back"
    );
    assert!(
        !dig_app_dest.with_extension("dig-updater-old").exists(),
        "no move-aside swap was even attempted for a held component"
    );
    assert!(
        result.state_advanced,
        "one un-probeable per-user daemon must not freeze every other component's trust state"
    );
}

// ====================== dig_ecosystem#1870 — an UNLOADABLE artifact is refused ======================

/// The GTK sonames the real `dig-app` `linux/x64` artifact requires — the ones a stock headless
/// server does not have, and the reason a "successful" update killed a working install.
const MISSING_ON_A_HEADLESS_HOST: [&str; 2] = ["libgtk-3.so.0", "libgdk-3.so.0"];

/// A host that cannot load ONE named artifact and can load everything else — the fixture shape that
/// keeps a truthful control in the pass. A resolver that refused everything could not tell a
/// correctly-placed refusal from a beacon that had simply stopped installing.
fn host_missing_libs_for(unloadable: &Path) -> impl Fn(&Path) -> Loadability + '_ {
    move |candidate: &Path| {
        if candidate.file_stem() == unloadable.file_stem() {
            Loadability::Unloadable {
                missing: MISSING_ON_A_HEADLESS_HOST
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            }
        } else {
            Loadability::Loadable
        }
    }
}

/// Drive a REAL two-component pass — an ordinary `digstore` (probe-evidenced, genuinely stale) beside
/// `dig-app` (digest-evidenced, dig-app's shipped class) — with the loadability check and the service
/// controller both INJECTED, so the #1870 refusal is observable end to end on every OS runner.
///
/// `dig-app` is really on disk with known bytes before the pass, so "nothing was installed" is a
/// statement about a file that EXISTS rather than an artefact of its absence, and both version probes
/// refuse to execute it (dig_ecosystem#1803 still binds).
fn apply_with_loadability(
    f: &RefusalFixture,
    loadability: &dyn Fn(&Path) -> Loadability,
    service_ctl: &ServiceControl,
    dig_app_digest: &dyn Fn(&Path) -> Option<String>,
) -> PassReport {
    let home = f.home.path();
    let store = TrustStateStore::for_channel(home, Channel::Stable);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).expect("apply dir");
    let catalog = Catalog::new(vec![
        ComponentTarget {
            name: "digstore".into(),
            method: InstallMethod::RawBinary,
            dest: f.digstore_dest.clone(),
            aliases: vec![],
            service: None,
            evidence: VersionEvidence::SafeToProbe,
        },
        ComponentTarget {
            name: "dig-app".into(),
            method: InstallMethod::RawBinary,
            dest: f.dig_app_dest.clone(),
            aliases: vec![],
            // A service id is declared PURELY so the refusal can be proven to precede the service
            // stop: with none, "zero service calls" would hold trivially.
            service: Some("net.dignetwork.dig-app-test".to_string()),
            // dig-app's SHIPPED evidence class: its build is established by hashing, never by running
            // it — which is exactly why the re-hash health gate cannot notice an unloadable binary.
            evidence: VersionEvidence::ArtifactDigest,
        },
    ]);
    // Both probes REFUSE to run dig-app (dig_ecosystem#1803 still binds — the exec itself is the
    // hazard, so it has to stay observable), and answer honestly for the digstore control: stale at
    // enumeration, current after its install, so the control genuinely completes its health gate.
    let refuse_to_exec_dig_app = |p: &Path, stage: &str| {
        assert!(
            !p.ends_with("dig-app") && !p.ends_with("dig-app.exe"),
            "the pass EXECUTED dig-app at {stage} — never permitted, at any version, on any path \
             (dig_ecosystem#1803)"
        );
    };
    let detect = |p: &Path| {
        refuse_to_exec_dig_app(p, "enumeration");
        DetectedVersion::Present("digstore 0.1.0".to_string())
    };
    let health = |p: &Path| {
        refuse_to_exec_dig_app(p, "the health gate");
        DetectedVersion::Present("digstore 0.2.0".to_string())
    };
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
        loadability,
        installed_builds: &records_beside(&store),
        catalog: &catalog,
        platform: &platform,
        lkg: &lkg,
        staging_dir: &home.join("staging"),
        apply_dir: &apply_dir,
        retry: RetryPolicy {
            attempts: 1,
            backoff: Duration::ZERO,
        },
        now: NOW,
        detect: &detect,
        health: &health,
        digest: dig_app_digest,
        service_ctl,
        suppress_state_advance: false,
    };
    installer
        .apply(&test_root().verifying_key(), &f.report, loaded)
        .expect("a refusal never fails the pass")
}

/// The staged #1870 fixture: a served two-component feed, with `dig-app` ALREADY installed under
/// known bytes so "the working build survived" is a claim about a real file.
struct RefusalFixture {
    home: tempfile::TempDir,
    digstore_dest: std::path::PathBuf,
    dig_app_dest: std::path::PathBuf,
    digstore_artifact: &'static [u8],
    report: WorkerReport,
    _guard: Guard,
    _server: Server,
}

/// The bytes of the dig-app build that WORKS on this host — what must still be at the destination
/// after a refusal.
const RUNNING_DIG_APP_BYTES: &[u8] = b"the-running-dig-app-3.4.0-binary-that-actually-works";

fn refusal_fixture() -> RefusalFixture {
    let home = tempfile::tempdir().unwrap();
    let digstore_dest = home.path().join("bin").join("digstore");
    let dig_app_dest = home.path().join("bin").join("dig-app");
    let digstore_artifact: &'static [u8] = b"the-new-digstore-0.2.0-binary";
    let dig_app_artifact: &'static [u8] = b"the-new-gtk-linked-dig-app-3.4.0-binary";

    let server = Server::bind();
    let m = manifest_with_dig_app(&server.base, digstore_artifact, dig_app_artifact);
    let guard = server.serve(routes_with_self_and_other(
        &m,
        dig_app_artifact,
        digstore_artifact,
    ));
    let report = stage(&server.base, &home.path().join("staging"));

    std::fs::create_dir_all(dig_app_dest.parent().unwrap()).unwrap();
    std::fs::write(&dig_app_dest, RUNNING_DIG_APP_BYTES).unwrap();
    RefusalFixture {
        home,
        digstore_dest,
        dig_app_dest,
        digstore_artifact,
        report,
        _guard: guard,
        _server: server,
    }
}

/// A digest reader answering a value that matches NOTHING, so the digest-evidenced component is
/// planned as an Update — the state a host is in when the feed offers it different bytes.
fn digest_of_something_else(_: &Path) -> Option<String> {
    Some("0000".to_string())
}

#[test]
fn an_unloadable_artifact_is_refused_before_the_live_binary_is_touched() {
    // dig_ecosystem#1870, the whole point: the artifact is signed, downloaded and digest-verified —
    // and it names libraries this host does not have, so installing it would replace a WORKING
    // binary with one that dies in the dynamic linker before `main`, while the pass reported success.
    //
    // The assertions pin the PLACEMENT, not merely the outcome. A refusal decided anywhere AFTER the
    // snapshot/install would satisfy "result == Refused" identically while having already moved the
    // live binary aside and stopped the service — so the bytes at `dest`, the absent move-aside
    // sibling, the ZERO service calls and the cleaned-up private copy are each a separate way for a
    // mis-placed guard to fail. digstore is a truthful control on a loadable artifact.
    let f = refusal_fixture();
    let calls = Mutex::new(Vec::new());
    let ctl = |_: &str, action: ServiceAction| {
        calls.lock().unwrap().push(action);
        Ok(())
    };

    let result = apply_with_loadability(
        &f,
        &host_missing_libs_for(&f.dig_app_dest),
        &ctl,
        &digest_of_something_else,
    );

    let dig_app = result
        .components
        .iter()
        .find(|c| c.component == "dig-app")
        .expect("a refused component is REPORTED, never silently dropped");
    assert_eq!(dig_app.result, ComponentResult::Refused);
    assert_eq!(
        dig_app.action, "refuse",
        "the planned action was overtaken; reporting it as carried out would be a lie"
    );
    assert_eq!(
        std::fs::read(&f.dig_app_dest).unwrap(),
        RUNNING_DIG_APP_BYTES,
        "the WORKING binary is byte-identical — never installed over, never even moved aside"
    );
    assert!(
        !f.dig_app_dest.with_extension("dig-updater-old").exists(),
        "no move-aside swap was attempted, so the refusal happened BEFORE the install"
    );
    assert!(
        calls.lock().unwrap().is_empty(),
        "a refusal precedes the service stop entirely: {:?}",
        calls.lock().unwrap()
    );
    let leftovers: Vec<String> = std::fs::read_dir(f.dig_app_dest.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("dig-app") && name != "dig-app" && name != "dig-app.exe")
        .collect();
    assert!(
        leftovers.is_empty(),
        "the broker-private copy was cleaned up rather than left installable beside the target: \
         {leftovers:?}"
    );

    let digstore = result
        .components
        .iter()
        .find(|c| c.component == "digstore")
        .expect("the control component is reported");
    assert_eq!(
        digstore.result,
        ComponentResult::Installed,
        "one host-incompatible component must not stop the others: {}",
        digstore.detail
    );
    assert_eq!(
        std::fs::read(&f.digstore_dest).unwrap(),
        f.digstore_artifact,
        "the loadable component's verified bytes really landed"
    );
}

#[test]
fn a_refusal_names_the_missing_libraries_in_its_detail() {
    // "Refused" alone is unactionable. The detail must name the sonames, so an operator can either
    // install them or knowingly accept that this component stays at its current build.
    let f = refusal_fixture();
    let result = apply_with_loadability(
        &f,
        &host_missing_libs_for(&f.dig_app_dest),
        &|_, _| Ok(()),
        &digest_of_something_else,
    );
    let detail = &result
        .components
        .iter()
        .find(|c| c.component == "dig-app")
        .expect("dig-app is reported")
        .detail;
    for soname in MISSING_ON_A_HEADLESS_HOST {
        assert!(
            detail.contains(soname),
            "the refusal must NAME {soname}: {detail}"
        );
    }
    assert!(
        detail.contains("left in place") && detail.contains("nothing was installed"),
        "and must state that the working build survived: {detail}"
    );
}

#[test]
fn a_refusal_does_not_withhold_the_state_advance() {
    // On a host that lacks the libraries the refusal is PERMANENT, so treating it as a failure would
    // freeze the monotonic trust state — and with it the anti-rollback floor — for every OTHER
    // component, forever. One Refused beside one Installed must still advance AND persist the state.
    let f = refusal_fixture();
    let result = apply_with_loadability(
        &f,
        &host_missing_libs_for(&f.dig_app_dest),
        &|_, _| Ok(()),
        &digest_of_something_else,
    );
    assert!(
        result.state_advanced,
        "a permanent, correct refusal must not stall the channel"
    );
    let persisted = TrustStateStore::for_channel(f.home.path(), Channel::Stable)
        .load()
        .expect("load state");
    assert!(
        persisted.state.sequence > 0,
        "and the advance was actually WRITTEN, not merely reported"
    );
}

#[test]
fn a_refused_pass_is_applied_and_not_a_fault_but_is_visible() {
    // The #1747 lesson in the opposite direction: a nightly unit that goes permanently red on a
    // correct, unchangeable condition trains an operator to ignore it. So a refusal is APPLIED and is
    // not a fault — and the requirement is carried by VISIBILITY instead.
    let f = refusal_fixture();
    let result = apply_with_loadability(
        &f,
        &host_missing_libs_for(&f.dig_app_dest),
        &|_, _| Ok(()),
        &digest_of_something_else,
    );
    assert!(
        result.applied,
        "the pass DID apply — one component was refused, the other installed"
    );
    assert!(
        !result.is_fault(),
        "a host that lacks GTK is not a beacon fault"
    );
    assert!(result.has_refusals(), "but the refusal must be visible");
    assert_eq!(result.refused, vec!["dig-app".to_string()]);
}

#[test]
fn a_loadable_or_indeterminate_artifact_installs_exactly_as_before() {
    // The no-regression anchor, in BOTH permitting directions. `Loadable` installs, and so does
    // `Indeterminate` — the fail-OPEN case that keeps every `.deb`/`.msi` private copy and every musl
    // host updating. A guard that refused what it could not prove would freeze the fleet.
    for (label, answer) in [
        ("loadable", Loadability::Loadable),
        (
            "indeterminate",
            Loadability::Indeterminate {
                why: "not an ELF image".to_string(),
            },
        ),
    ] {
        let f = refusal_fixture();
        let result = apply_with_loadability(
            &f,
            &|_: &Path| answer.clone(),
            &|_, _| Ok(()),
            // The honest PRODUCTION digest reader: the health gate re-hashes what landed, so this can
            // only pass because the promised bytes really are at the destination.
            &dig_updater_broker::installed_digest_hex,
        );
        let dig_app = result
            .components
            .iter()
            .find(|c| c.component == "dig-app")
            .expect("dig-app is reported");
        assert_eq!(
            dig_app.result,
            ComponentResult::Installed,
            "[{label}] must install exactly as it did before #1870: {}",
            dig_app.detail
        );
        assert_ne!(
            std::fs::read(&f.dig_app_dest).unwrap(),
            RUNNING_DIG_APP_BYTES,
            "[{label}] the new verified bytes really replaced the old ones"
        );
        assert!(
            !result.has_refusals(),
            "[{label}] nothing was refused: {:?}",
            result.refused
        );
    }
}

// ============ dig_ecosystem#1858 — what this beacon installed is remembered per component ============

#[test]
fn a_successful_install_records_the_manifest_build() {
    // The record the #1858 guard later reads. Without it a digest-evidenced host has NO way to know it
    // is ahead of the feed, because a hash can only ever say "not these bytes".
    let f = refusal_fixture();
    let result = apply_with_loadability(
        &f,
        &|_: &Path| Loadability::Loadable,
        &|_, _| Ok(()),
        &dig_updater_broker::installed_digest_hex,
    );
    assert!(result
        .components
        .iter()
        .all(|c| c.result == ComponentResult::Installed));
    let recorded = InstalledBuildStore::for_channel(f.home.path(), Channel::Stable).load();
    assert_eq!(
        recorded.build_of("dig-app"),
        Some(3_004_000),
        "the build the manifest promised is what is now on disk"
    );
    assert_eq!(recorded.build_of("digstore"), Some(2_000));
}

#[test]
fn a_refused_component_records_nothing() {
    // Nothing was installed, so nothing about the destination changed — recording the ATTEMPTED build
    // would make the next pass believe an unloadable binary is installed and skip it forever.
    let f = refusal_fixture();
    apply_with_loadability(
        &f,
        &host_missing_libs_for(&f.dig_app_dest),
        &|_, _| Ok(()),
        &digest_of_something_else,
    );
    let recorded = InstalledBuildStore::for_channel(f.home.path(), Channel::Stable).load();
    assert_eq!(recorded.build_of("dig-app"), None);
    assert_eq!(
        recorded.build_of("digstore"),
        Some(2_000),
        "the component that DID install is still recorded"
    );
}

#[test]
fn a_rollback_re_records_the_reinstated_build_not_the_attempted_one() {
    // A high-water mark would remember the build that FAILED its health gate and was rolled away, so
    // the next pass would skip the install that restores the host — stranding it on the rolled-back
    // build forever. The record must track what is ACTUALLY present.
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");
    // A prior 0.1.0 is installed, so there IS a build to reinstate on rollback.
    std::fs::write(&dest, b"the-old-digstore-0.1.0-binary").unwrap();

    let artifact = b"the-new-digstore-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let detect = |_: &Path| DetectedVersion::Present("digstore 0.1.0".to_string());
    // The install lands, then the health gate still sees the OLD version — the rollback path.
    let health = |_: &Path| DetectedVersion::Present("digstore 0.1.0".to_string());
    let result = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &detect,
        &health,
    )
    .expect("apply completes");
    assert_eq!(result.components[0].result, ComponentResult::RolledBack);

    let recorded = InstalledBuildStore::for_channel(home.path(), Channel::Stable).load();
    assert_eq!(
        recorded.build_of("digstore"),
        Some(1_000),
        "the REINSTATED 0.1.0 build is recorded, never the 0.2.0 that was rolled away"
    );
}

#[test]
fn a_rollback_removes_the_entry_when_nothing_was_installed_before() {
    // The other rollback shape: a FRESH placement that fails its health gate is REMOVED, so there is
    // no build at the destination at all — and therefore nothing to remember. A stale entry would
    // later be compared against the feed as though a build were installed.
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("digstore");
    let store = InstalledBuildStore::for_channel(home.path(), Channel::Stable);
    store
        .record("digstore", Some(1_000))
        .expect("seed a stale record");

    let artifact = b"the-new-digstore-0.2.0-binary";
    let srv = Server::bind();
    let m = manifest(&srv.base, "0.2.0", 2_000, 0, artifact);
    let _guard = srv.serve(routes(&m, artifact));
    let report = stage(&srv.base, &home.path().join("staging"));

    let absent = |_: &Path| DetectedVersion::Absent;
    let result = apply(
        &test_root().verifying_key(),
        &report,
        home.path(),
        &dest,
        &absent,
        &absent,
    )
    .expect("apply completes");
    assert_eq!(result.components[0].result, ComponentResult::RolledBack);
    assert!(!dest.exists(), "the freshly-placed binary was removed");
    assert_eq!(
        store.load().build_of("digstore"),
        None,
        "with nothing installed there, nothing is remembered"
    );
}
