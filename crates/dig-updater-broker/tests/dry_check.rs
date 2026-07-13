//! Integration test for [`Broker::dry_check`] — the -D end-to-end path: load the persisted trust
//! state, spawn the real worker binary against a (local, test-signed) feed, and return its
//! report WITHOUT advancing the state. The worker pins the production key, so a test-signed feed
//! is rejected; the point here is that the broker loads state, builds the request, spawns, and
//! parses correctly — and that the state file is never written by a dry check.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use dig_updater_broker::Broker;
use dig_updater_trust::{
    Artifact, Component, Delegation, Manifest, SignedDelegation, SignedManifest,
};
use dig_updater_worker::{FeedSource, Platform, WorkerReport};

fn worker_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join(if cfg!(windows) {
        "dig-updater-worker.exe"
    } else {
        "dig-updater-worker"
    })
}

struct Server {
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
        let st = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                if let Ok(Some(req)) = server.recv_timeout(Duration::from_millis(50)) {
                    let body = routes.get(req.url()).cloned().unwrap_or_default();
                    let _ = req.respond(tiny_http::Response::from_data(body));
                }
            }
        });
        Self {
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
    }
}

fn test_feed() -> HashMap<String, Vec<u8>> {
    let root = SigningKey::from_bytes(&[5u8; 32]);
    let targets = SigningKey::from_bytes(&[6u8; 32]);
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
                sha256: hex::encode(Sha256::digest(b"x")),
                size: 1,
            }],
        }],
    };
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
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
    ])
}

#[test]
fn dry_check_loads_state_spawns_worker_and_never_writes_state() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let broker = Broker::with_paths(state_dir.path().to_path_buf(), worker_binary());
    let server = Server::start(test_feed());

    let report = broker
        .dry_check(vec![FeedSource::new(&server.base)])
        .expect("dry_check runs the worker and parses its report");

    // The worker pins the production key, so a test-signed feed is rejected — proving the whole
    // broker→worker path executed (load → spawn → parse).
    assert!(matches!(report, WorkerReport::Rejected { .. }));

    // A dry check must NEVER persist trust state.
    assert!(
        !state_dir.path().join("trust-state.json").exists(),
        "dry_check must not write the trust state"
    );
}
