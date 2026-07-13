//! End-to-end trust-chain test: sign a delegation + manifest exactly as the CI signer
//! will, serialize them to their JSON envelopes, parse them back as a verifier would (over the
//! RECEIVED bytes), then walk the verify chain a beacon pass runs — establishing the baseline
//! on a fresh install, accepting a newer manifest, and rejecting a rollback replay. This
//! doubles as executable documentation of how a caller composes the trust core.

use dig_updater_trust::{
    verify_artifact_digest, verify_update_chain, Artifact, Component, Delegation, Manifest,
    SignedDelegation, SignedManifest, TrustError, TrustState,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Sign a delegation and round-trip it through its JSON envelope, exactly as the wire path does
/// (signer emits JSON; verifier parses it and captures the received bytes).
fn wire_delegation(sk: &SigningKey, d: Delegation) -> SignedDelegation {
    let json = SignedDelegation::sign(d, sk).to_json();
    SignedDelegation::from_json(&json).expect("valid delegation envelope")
}

fn wire_manifest(sk: &SigningKey, m: Manifest) -> SignedManifest {
    let json = SignedManifest::sign(m, sk).to_json();
    SignedManifest::from_json(&json).expect("valid manifest envelope")
}

fn manifest(sequence: u64, generated: u64, artifact_bytes: &[u8]) -> Manifest {
    Manifest {
        schema: 1,
        root_version: 1,
        sequence,
        generated,
        expires: generated + 43_200, // 12h heartbeat window
        rollback_floor_build: 20,
        components: vec![Component {
            name: "dig-node".to_string(),
            version: "0.26.0".to_string(),
            build: 26,
            artifacts: vec![Artifact {
                os: "linux".to_string(),
                arch: "x64".to_string(),
                url: "https://updates.dig.net/dig-node/0.26.0/linux-x64".to_string(),
                sha256: hex::encode(Sha256::digest(artifact_bytes)),
                size: artifact_bytes.len() as u64,
            }],
        }],
    }
}

#[test]
fn baseline_accept_then_advance_then_reject_rollback() {
    let (root_sk, root_vk) = keypair(1);
    let (targets_sk, targets_vk) = keypair(2);

    let delegation = wire_delegation(
        &root_sk,
        Delegation {
            root_version: 1,
            targets_pubkey: b64(&targets_vk.to_bytes()),
            expires: 1_000_000_000,
        },
    );

    let mut state = TrustState::initial();

    // --- Pass 1: first validly-signed manifest establishes the baseline. ---
    let bytes_v1 = b"dig-node-artifact-v1";
    let m1 = wire_manifest(&targets_sk, manifest(100, 500_000, bytes_v1));
    assert_eq!(
        verify_update_chain(&root_vk, &state, &delegation, &m1, 500_100),
        Ok(())
    );
    // The fetched artifact must match the in-manifest digest before install.
    let art = &m1.manifest.components[0].artifacts[0];
    assert_eq!(verify_artifact_digest(art, bytes_v1), Ok(()));
    assert_eq!(
        verify_artifact_digest(art, b"tampered"),
        Err(TrustError::DigestMismatch {
            expected: art.sha256.clone(),
            actual: hex::encode(Sha256::digest(b"tampered")),
        })
    );
    state.advance(&m1.manifest);

    // --- Pass 2: a newer manifest (higher sequence + generated) is accepted. ---
    let m2 = wire_manifest(&targets_sk, manifest(101, 540_000, b"dig-node-artifact-v2"));
    assert_eq!(
        verify_update_chain(&root_vk, &state, &delegation, &m2, 540_100),
        Ok(())
    );
    state.advance(&m2.manifest);

    // --- Pass 3: replaying pass 1 (a rollback) is rejected on sequence regression. ---
    // Replay inside m1's own validity window (before its 543_200 expiry) so the rejection
    // is specifically the anti-rollback sequence check, not the expiry check.
    assert_eq!(
        verify_update_chain(&root_vk, &state, &delegation, &m1, 543_000),
        Err(TrustError::SequenceRegressed {
            trusted: 101,
            manifest: 100,
        })
    );
}

#[test]
fn manifest_from_forged_root_is_rejected() {
    // An attacker with their OWN root+targets keys cannot get an update accepted under the
    // real pinned root key — the delegation signature fails to verify.
    let (_real_root_sk, real_root_vk) = keypair(1);
    let (evil_root_sk, _evil_root_vk) = keypair(9);
    let (_evil_targets_sk, evil_targets_vk) = keypair(8);

    let evil_delegation = wire_delegation(
        &evil_root_sk,
        Delegation {
            root_version: 1,
            targets_pubkey: b64(&evil_targets_vk.to_bytes()),
            expires: 1_000_000_000,
        },
    );
    let m = wire_manifest(&evil_root_sk, manifest(100, 500_000, b"evil"));
    assert_eq!(
        verify_update_chain(
            &real_root_vk,
            &TrustState::initial(),
            &evil_delegation,
            &m,
            500_100
        ),
        Err(TrustError::DelegationSignatureInvalid)
    );
}
