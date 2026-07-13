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

use dig_updater_broker::{
    BrokerError, Catalog, ComponentResult, ComponentTarget, DetectedVersion, InstallMethod,
    Installer, LkgCache, PassReport, RetryPolicy, TrustStateStore,
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

// --- feed + worker helpers ---

/// A manifest with one component ("digstore") whose single artifact targets THIS host and is
/// served at `{base}/artifact`.
fn manifest(base: &str, version: &str, build: u64, floor: u64, artifact: &[u8]) -> Manifest {
    let p = Platform::current();
    Manifest {
        schema: 1,
        root_version: 1,
        sequence: 100,
        generated: 500_000,
        expires: FAR_FUTURE,
        rollback_floor_build: floor,
        components: vec![Component {
            name: "digstore".into(),
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
    let store = TrustStateStore::at(home);
    let loaded = store.load().expect("load state");
    let lkg = LkgCache::at(home.join("lkg"));
    let staging_dir = home.join("staging");
    let apply_dir = home.join("apply");
    std::fs::create_dir_all(&apply_dir).expect("apply dir");
    let catalog = Catalog::new(vec![ComponentTarget {
        name: "digstore".into(),
        method: InstallMethod::RawBinary,
        dest: dest.to_path_buf(),
    }]);
    let platform = Platform::current();
    let installer = Installer {
        store: &store,
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
    };
    installer.apply(root, report, loaded)
}

// =============================== the scenarios ===============================

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
        home.path().join("trust-state.json").exists(),
        "state persisted"
    );
    assert_state_dir_hardened(home.path());
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
        !home.path().join("trust-state.json").exists(),
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
