//! Integration test for the broker→worker spawn plumbing, exercised on every OS runner.
//!
//! It spawns the REAL `dig-updater-worker` binary (which pins the PRODUCTION root key) against a
//! local feed signed by a TEST key. Because the shipped binary has no way to override its pinned
//! key, it MUST reject the test-signed feed — proving both (a) the spawn/pipe IPC works and (b)
//! the pinned key is enforced with no override reachable in the built binary. This is the
//! binary-level companion to the worker's library-level accept-path e2e.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use dig_updater_broker::{spawn_worker, Sandbox};
use dig_updater_trust::{
    Artifact, Component, Delegation, Manifest, SignedDelegation, SignedManifest, TrustState,
};
use dig_updater_worker::{FeedSource, Platform, WorkerReport, WorkerRequest};

/// Locate the compiled worker binary next to the current test executable.
fn worker_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current exe");
    dir.pop(); // the test binary file
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join(if cfg!(windows) {
        "dig-updater-worker.exe"
    } else {
        "dig-updater-worker"
    })
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

struct Server {
    server: Arc<tiny_http::Server>,
    base: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(routes: HashMap<String, Vec<u8>>) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind"));
        let base = format!(
            "http://127.0.0.1:{}",
            server.server_addr().to_ip().unwrap().port()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let (s, st) = (Arc::clone(&server), Arc::clone(&stop));
        let handle = thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                if let Ok(Some(req)) = s.recv_timeout(Duration::from_millis(50)) {
                    let body = routes.get(req.url()).cloned();
                    let response = match body {
                        Some(b) => tiny_http::Response::from_data(b),
                        None => tiny_http::Response::from_data(b"nf".to_vec())
                            .with_status_code(tiny_http::StatusCode(404)),
                    };
                    let _ = req.respond(response);
                }
            }
        });
        Self {
            server,
            base,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = &self.server;
    }
}

/// A feed signed by a TEST root/targets pair. The artifact is never fetched — the delegation
/// signature fails first under the binary's pinned key — so its URL is a placeholder.
fn test_signed_routes() -> HashMap<String, Vec<u8>> {
    let root = SigningKey::from_bytes(&[3u8; 32]);
    let targets = SigningKey::from_bytes(&[4u8; 32]);
    let artifact = b"irrelevant-the-signature-is-what-fails";
    let p = Platform::current();
    let manifest = Manifest {
        schema: 1,
        root_version: 1,
        sequence: 100,
        generated: 500_000,
        expires: 4_000_000_000,
        rollback_floor_build: 20,
        components: vec![Component {
            name: "dig-node".into(),
            version: "0.26.0".into(),
            build: 26,
            artifacts: vec![Artifact {
                os: p.os,
                arch: p.arch,
                url: "http://127.0.0.1:1/artifact".into(),
                sha256: hex::encode(Sha256::digest(artifact)),
                size: artifact.len() as u64,
            }],
        }],
    };
    let delegation = SignedDelegation::sign(
        Delegation {
            root_version: 1,
            targets_pubkey: b64(&targets.verifying_key().to_bytes()),
            expires: 4_000_000_000,
        },
        &root,
    );
    let signed = SignedManifest::sign(manifest, &targets);
    HashMap::from([
        (
            "/delegation.json".to_string(),
            delegation.to_json().into_bytes(),
        ),
        ("/manifest.json".to_string(), signed.to_json().into_bytes()),
        ("/artifact".to_string(), artifact.to_vec()),
    ])
}

fn request(base: &str) -> WorkerRequest {
    WorkerRequest {
        feed_sources: vec![FeedSource::new(base)],
        trust_state: TrustState::initial(),
        now: 600_000,
        staging_dir: std::env::temp_dir()
            .join(format!("dig-updater-spawn-test-{}", std::process::id()))
            .to_string_lossy()
            .into_owned(),
        platform: Platform::current(),
    }
}

/// The shipped worker binary rejects a feed not signed by its pinned root key — via a normal
/// (inherited-privilege) spawn. Proves the IPC plumbing on every OS.
#[test]
fn spawned_worker_rejects_feed_not_signed_by_pinned_key_inherit() {
    let server = Server::start(test_signed_routes());
    let report = spawn_worker(&worker_binary(), &request(&server.base), Sandbox::Inherit)
        .expect("spawn + parse report");
    match report {
        WorkerReport::Rejected { reason, .. } => {
            assert_eq!(reason, "delegation_signature_invalid");
        }
        WorkerReport::Verified(_) => {
            panic!("a test-signed feed must NOT verify under the pinned key")
        }
    }
}

/// The same, but through the RESTRICTED sandbox path (exercises the privilege-drop spawn code on
/// each OS; on Windows this drives the restricted-token machinery, falling back to a plain spawn
/// when the host denies spawn-as-user).
#[test]
fn spawned_worker_rejects_feed_not_signed_by_pinned_key_restricted() {
    let server = Server::start(test_signed_routes());
    let report = spawn_worker(
        &worker_binary(),
        &request(&server.base),
        Sandbox::Restricted,
    )
    .expect("spawn + parse report");
    assert!(
        matches!(report, WorkerReport::Rejected { .. }),
        "the pinned key must reject a test-signed feed regardless of sandbox"
    );
}
