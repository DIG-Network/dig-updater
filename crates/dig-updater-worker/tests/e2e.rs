//! End-to-end worker tests over a REAL local HTTP server: the full fetch → verify → stage pass
//! and the named adversarial vectors, each exercised through the actual network path the beacon
//! uses in production (ureq → socket → streaming SHA-256 → staging file). This runs on every OS
//! runner, so it doubles as the cross-platform DRY-verify e2e.
//!
//! Each adversarial test asserts the SPECIFIC, distinct rejection code — the evidence the dual
//! review gate depends on. The trust anchor is an injected TEST key: the shipped binary pins the
//! real key and is proven separately (see the reject-under-pinned-key spawn test).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use dig_updater_trust::{
    Artifact, Component, Delegation, Manifest, SignedDelegation, SignedManifest, TrustState,
};
use dig_updater_worker::{run, FeedSource, Platform, VerifiedPlan, WorkerError, WorkerRequest};

const FAR_FUTURE: u64 = 4_000_000_000;

// --- test key material (deterministic, unrelated to the pinned production key) ---

fn root() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}
fn targets() -> SigningKey {
    SigningKey::from_bytes(&[2u8; 32])
}
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// --- a throwaway HTTP server that serves a fixed route table ---

/// A local HTTP server bound to an ephemeral loopback port. Routes are `path -> (status, body)`;
/// anything unmatched is a 404. The background thread stops when the returned guard drops.
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

    fn serve(&self, routes: HashMap<String, (u16, Vec<u8>)>) -> ServerGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let server = Arc::clone(&self.server);
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match server.recv_timeout(Duration::from_millis(50)) {
                    Ok(Some(request)) => {
                        let (status, body) = routes
                            .get(request.url())
                            .cloned()
                            .unwrap_or((404, b"not found".to_vec()));
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

// --- feed builders ---

/// A manifest with one component whose single artifact targets THIS machine's platform, so the
/// worker actually downloads + digest-verifies it against `{base}/artifact`.
fn base_manifest(base: &str, artifact_bytes: &[u8], advisory_size: u64) -> Manifest {
    let p = Platform::current();
    Manifest {
        schema: 1,
        root_version: 1,
        sequence: 100,
        generated: 500_000,
        expires: 1_000_000,
        rollback_floor_build: 20,
        components: vec![Component {
            name: "dig-node".into(),
            version: "0.26.0".into(),
            build: 26,
            artifacts: vec![Artifact {
                os: p.os,
                arch: p.arch,
                url: format!("{base}/artifact"),
                sha256: hex::encode(Sha256::digest(artifact_bytes)),
                size: advisory_size,
            }],
        }],
    }
}

/// The standard 3-route feed: a delegation signed by `root`, a manifest signed by `targets`, and
/// the artifact bytes. `deleg_root_version`/`deleg_expires` let a test craft a mismatch/expiry.
fn feed_routes(
    root: &SigningKey,
    targets: &SigningKey,
    deleg_root_version: u32,
    deleg_expires: u64,
    manifest: &Manifest,
    artifact_bytes: &[u8],
) -> HashMap<String, (u16, Vec<u8>)> {
    let delegation = SignedDelegation::sign(
        Delegation {
            root_version: deleg_root_version,
            targets_pubkey: b64(&targets.verifying_key().to_bytes()),
            expires: deleg_expires,
        },
        root,
    );
    let signed = SignedManifest::sign(manifest.clone(), targets);
    HashMap::from([
        (
            "/delegation.json".to_string(),
            (200u16, delegation.to_json().into_bytes()),
        ),
        (
            "/manifest.json".to_string(),
            (200, signed.to_json().into_bytes()),
        ),
        ("/artifact".to_string(), (200, artifact_bytes.to_vec())),
    ])
}

fn request(bases: &[String], state: TrustState, now: u64, staging: &Path) -> WorkerRequest {
    WorkerRequest {
        feed_sources: bases.iter().map(FeedSource::new).collect(),
        trust_state: state,
        now,
        staging_dir: staging.to_string_lossy().into_owned(),
        platform: Platform::current(),
    }
}

/// Serve `routes`, run the worker against `bases`, and return the result plus the staging dir
/// (kept alive so callers can inspect staged files).
fn run_pass(
    routes: HashMap<String, (u16, Vec<u8>)>,
    bases: &[String],
    state: TrustState,
    now: u64,
    server: &TestServer,
) -> (Result<VerifiedPlan, WorkerError>, TempDir) {
    let staging = TempDir::new().expect("staging dir");
    let _guard = server.serve(routes);
    let req = request(bases, state, now, staging.path());
    let result = run(&req, &root().verifying_key());
    (result, staging)
}

fn assert_rejected(result: Result<VerifiedPlan, WorkerError>, code: &str) {
    let err = result.expect_err("expected a rejection");
    assert_eq!(err.code(), code, "unexpected rejection: {err}");
}

// =========================== accept path (the DRY verify pass) ===========================

#[test]
fn full_dry_verify_pass_accepts_and_stages() {
    let srv = TestServer::bind();
    let artifact = b"the-real-dig-node-artifact-bytes";
    let manifest = base_manifest(&srv.base, artifact, artifact.len() as u64);
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);

    let (result, _staging) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );

    let plan = result.expect("a valid feed must verify");
    assert_eq!(plan.source, srv.base);
    assert_eq!(plan.sequence, 100);
    assert_eq!(plan.root_version, 1);
    assert_eq!(plan.artifacts.len(), 1);
    let staged = &plan.artifacts[0];
    assert_eq!(staged.component, "dig-node");
    assert_eq!(staged.version, "0.26.0");
    assert_eq!(staged.size, artifact.len() as u64);
    // The staged file exists and its bytes are exactly what the digest authorized.
    let on_disk = std::fs::read(&staged.staged_path).expect("staged file exists");
    assert_eq!(on_disk, artifact);
    assert_eq!(hex::encode(Sha256::digest(&on_disk)), staged.sha256);
}

/// Root-cause evidence for #540: a feed that verifies cleanly is STILL reported as a
/// `staging_io_error` rejection when the staging directory cannot be created — because staging
/// the artifact bytes is load-bearing for the digest check. This is exactly what defeated the
/// `feed.yml` keystone: run UNELEVATED, the worker's staging dir defaulted under the Admin-only
/// state dir (`/var/lib/dig-updater/staging`), `create_dir_all` was denied, and a valid,
/// correctly-signed feed came back non-verified → `dig-updater check` exited 2. The fix is NOT in
/// the worker (a dry verify genuinely needs a writable scratch dir to hash into) but in giving the
/// dry check a WRITABLE staging location (see `Broker::for_dry_check` + `DIG_UPDATER_STATE_DIR`).
#[test]
fn valid_feed_with_an_uncreatable_staging_dir_reports_staging_io_not_a_verification_failure() {
    let srv = TestServer::bind();
    let artifact = b"the-real-dig-node-artifact-bytes";
    let manifest = base_manifest(&srv.base, artifact, artifact.len() as u64);
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);

    // Make the staging path un-creatable in a permission-free, cross-platform way: its parent is a
    // regular FILE, so `create_dir_all` fails just as an EACCES under `/var/lib` would on CI.
    let tmp = TempDir::new().expect("scratch dir");
    let blocking_file = tmp.path().join("parent-is-a-file");
    std::fs::write(&blocking_file, b"x").expect("write blocking file");
    let staging = blocking_file.join("staging");

    let _guard = srv.serve(routes);
    let req = request(
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &staging,
    );
    let result = run(&req, &root().verifying_key());

    // The trust chain verified — the ONLY failure is that the artifact could not be staged. The
    // worker classifies this distinctly (`staging_io_error`), never as a security rejection.
    let err = result.expect_err("an uncreatable staging dir must fail the pass");
    assert_eq!(
        err.code(),
        "staging_io_error",
        "a write/permission failure must NOT be reported as a verification rejection"
    );
}

#[test]
fn feed_ladder_falls_back_to_second_source() {
    let srv = TestServer::bind();
    let artifact = b"artifact-served-by-the-fallback";
    // The manifest's artifact URL is absolute, so it does not matter which feed base served it.
    let manifest = base_manifest(&srv.base, artifact, artifact.len() as u64);
    let good = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);

    // Primary paths 404; fallback paths serve the good feed.
    let mut routes = HashMap::new();
    routes.insert(
        "/primary/delegation.json".to_string(),
        (404u16, b"nope".to_vec()),
    );
    routes.insert(
        "/primary/manifest.json".to_string(),
        (404, b"nope".to_vec()),
    );
    routes.insert(
        "/fallback/delegation.json".to_string(),
        good["/delegation.json"].clone(),
    );
    routes.insert(
        "/fallback/manifest.json".to_string(),
        good["/manifest.json"].clone(),
    );
    routes.insert("/artifact".to_string(), good["/artifact"].clone());

    let bases = [
        format!("{}/primary", srv.base),
        format!("{}/fallback", srv.base),
    ];
    let (result, _staging) = run_pass(routes, &bases, TrustState::initial(), 600_000, &srv);

    let plan = result.expect("the fallback source must verify");
    assert_eq!(plan.source, format!("{}/fallback", srv.base));
}

#[test]
fn unknown_field_manifest_still_verifies_over_the_wire() {
    let srv = TestServer::bind();
    let artifact = b"forward-compatible-artifact";
    let manifest = base_manifest(&srv.base, artifact, artifact.len() as u64);

    // A future signer emits an additive top-level field and signs the exact bytes it emits.
    let canonical = String::from_utf8(manifest.signing_bytes()).unwrap();
    let with_extra = format!("{{\"future_flag\":true,{}", &canonical[1..]);
    let sig = b64(&targets().sign(with_extra.as_bytes()).to_bytes());
    let manifest_json = format!(r#"{{"manifest":{with_extra},"signature":"{sig}"}}"#);
    let delegation = SignedDelegation::sign(
        Delegation {
            root_version: 1,
            targets_pubkey: b64(&targets().verifying_key().to_bytes()),
            expires: FAR_FUTURE,
        },
        &root(),
    );
    let routes = HashMap::from([
        (
            "/delegation.json".to_string(),
            (200u16, delegation.to_json().into_bytes()),
        ),
        (
            "/manifest.json".to_string(),
            (200, manifest_json.into_bytes()),
        ),
        ("/artifact".to_string(), (200, artifact.to_vec())),
    ]);

    let (result, _staging) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert!(result.is_ok(), "an additive future field must still verify");
}

// =========================== adversarial vectors (distinct rejections) ===========================

#[test]
fn tampered_manifest_body_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1);
    let mut routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    // Flip a byte inside the signed manifest body after signing.
    let (_s, body) = routes.get_mut("/manifest.json").unwrap();
    let mut json = String::from_utf8(body.clone()).unwrap();
    json = json.replace("0.26.0", "9.9.9");
    *body = json.into_bytes();

    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "manifest_signature_invalid");
}

#[test]
fn tampered_delegation_body_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1);
    let mut routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    // Corrupt the delegation's targets_pubkey after signing (still valid base64 shape).
    let (_s, body) = routes.get_mut("/delegation.json").unwrap();
    let json = String::from_utf8(body.clone()).unwrap();
    let evil = b64(&SigningKey::from_bytes(&[42u8; 32])
        .verifying_key()
        .to_bytes());
    let re = regex_replace_targets(&json, &evil);
    *body = re.into_bytes();

    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "delegation_signature_invalid");
}

/// Replace the `targets_pubkey` value in a delegation JSON with `new_key` (a small, dependency
/// free string edit — the field is `"targets_pubkey":"<44-char b64>"`).
fn regex_replace_targets(json: &str, new_key: &str) -> String {
    let marker = "\"targets_pubkey\":\"";
    let start = json.find(marker).expect("targets_pubkey present") + marker.len();
    let end = start + json[start..].find('"').expect("closing quote");
    format!("{}{}{}", &json[..start], new_key, &json[end..])
}

#[test]
fn feed_signed_by_wrong_root_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1);
    // Sign the delegation with a DIFFERENT root than the verifier's key.
    let evil_root = SigningKey::from_bytes(&[99u8; 32]);
    let routes = feed_routes(&evil_root, &targets(), 1, FAR_FUTURE, &manifest, artifact);

    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "delegation_signature_invalid");
}

#[test]
fn expired_manifest_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1); // expires 1_000_000
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        1_000_001,
        &srv,
    );
    assert_rejected(result, "manifest_expired");
}

#[test]
fn expired_delegation_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1);
    let routes = feed_routes(&root(), &targets(), 1, 100, &manifest, artifact); // deleg expires 100
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "delegation_expired");
}

#[test]
fn sequence_replay_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1); // sequence 100
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    let state = TrustState {
        sequence: 200,
        ..TrustState::initial()
    };
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        state,
        600_000,
        &srv,
    );
    assert_rejected(result, "sequence_regressed");
}

#[test]
fn generated_regression_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1); // generated 500_000
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    let state = TrustState {
        generated: 600_000,
        ..TrustState::initial()
    };
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        state,
        700_000,
        &srv,
    );
    assert_rejected(result, "generated_regressed");
}

#[test]
fn root_version_regression_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1); // root_version 1
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    let state = TrustState {
        root_version: 5,
        ..TrustState::initial()
    };
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        state,
        600_000,
        &srv,
    );
    assert_rejected(result, "root_version_regressed");
}

#[test]
fn root_version_mismatch_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1); // manifest root_version 1
                                                          // Delegation asserts root_version 2 — a mixed delegation+manifest pair.
    let routes = feed_routes(&root(), &targets(), 2, FAR_FUTURE, &manifest, artifact);
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "root_version_mismatch");
}

#[test]
fn below_rollback_floor_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let mut manifest = base_manifest(&srv.base, artifact, 1);
    manifest.rollback_floor_build = 100; // component build is 26
    let routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "below_rollback_floor");
}

#[test]
fn digest_mismatch_rejected_and_staging_cleaned() {
    let srv = TestServer::bind();
    let declared = b"the-bytes-the-manifest-commits-to";
    let manifest = base_manifest(&srv.base, declared, declared.len() as u64);
    let mut routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, declared);
    // A hostile CDN serves DIFFERENT bytes than the signed digest.
    routes.insert(
        "/artifact".to_string(),
        (200, b"malicious-substitution".to_vec()),
    );

    let (result, staging) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "digest_mismatch");
    // No unverified file is left behind for the broker to install.
    let leftovers: Vec<_> = std::fs::read_dir(staging.path()).unwrap().collect();
    assert!(leftovers.is_empty(), "staging must be cleaned on mismatch");
}

#[test]
fn oversize_artifact_rejected_and_staging_cleaned() {
    let srv = TestServer::bind();
    let declared = vec![7u8; 4]; // advisory 10 -> cap 40 bytes
    let manifest = base_manifest(&srv.base, &declared, 10);
    let mut routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, &declared);
    // Serve far more than the cap of min(4*10, 2GiB) = 40 bytes.
    routes.insert("/artifact".to_string(), (200, vec![7u8; 1000]));

    let (result, staging) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    let err = result.expect_err("oversize must reject");
    assert_eq!(err.code(), "artifact_too_large");
    let leftovers: Vec<_> = std::fs::read_dir(staging.path()).unwrap().collect();
    assert!(leftovers.is_empty(), "staging must be cleaned on oversize");
}

#[test]
fn malformed_manifest_json_rejected() {
    let srv = TestServer::bind();
    let artifact = b"x";
    let manifest = base_manifest(&srv.base, artifact, 1);
    let mut routes = feed_routes(&root(), &targets(), 1, FAR_FUTURE, &manifest, artifact);
    routes.insert(
        "/manifest.json".to_string(),
        (200, b"{not valid json".to_vec()),
    );
    let (result, _s) = run_pass(
        routes,
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    assert_rejected(result, "malformed_json");
}

#[test]
fn unreachable_feed_is_transient_unavailable() {
    let srv = TestServer::bind();
    // Serve nothing — every path 404s.
    let (result, _s) = run_pass(
        HashMap::new(),
        std::slice::from_ref(&srv.base),
        TrustState::initial(),
        600_000,
        &srv,
    );
    let err = result.expect_err("an empty feed must fail");
    assert_eq!(err.code(), "feed_unavailable");
    assert!(
        err.is_transient(),
        "an unreachable feed is a retry, not a rejection"
    );
}
