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
        service_ctl: &|_, _| Ok(()),
        suppress_state_advance,
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
        },
        ComponentTarget {
            name: "digstore".into(),
            method: InstallMethod::RawBinary,
            dest: other_dest.to_path_buf(),
            aliases: vec![],
            service: None,
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
