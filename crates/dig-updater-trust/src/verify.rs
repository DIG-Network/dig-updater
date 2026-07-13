//! The verification surface: signature checks, freshness/monotonicity checks, per-artifact
//! digest checks, and the composed [`verify_update_chain`] that a caller applies in order.
//!
//! Every check fails **closed** with a specific [`TrustError`]. The signature checks use
//! `ed25519_dalek`'s strict verification (`verify_strict`), which rejects small-order /
//! non-canonical public keys and malleable signatures.

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::manifest::{Artifact, Manifest, SignedDelegation, SignedManifest};
use crate::trust_state::TrustState;

/// Everything that can make an update untrusted. Each variant is a distinct, testable
/// rejection reason; nothing is collapsed into a generic "invalid".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A signature string was not valid base64 or not a 64-byte Ed25519 signature.
    #[error("malformed signature encoding: {0}")]
    BadSignatureEncoding(String),
    /// A public-key string was not valid base64 or not a valid 32-byte Ed25519 key.
    #[error("malformed key encoding: {0}")]
    BadKeyEncoding(String),
    /// The delegation's signature did not verify under the pinned root key.
    #[error("delegation signature does not verify under the pinned root key")]
    DelegationSignatureInvalid,
    /// The manifest's signature did not verify under the delegated targets key.
    #[error("manifest signature does not verify under the delegated targets key")]
    ManifestSignatureInvalid,
    /// The delegation has expired.
    #[error("delegation expired at {expires}, now {now}")]
    DelegationExpired {
        /// The delegation's `expires` timestamp.
        expires: u64,
        /// The current time supplied to the check.
        now: u64,
    },
    /// The manifest has expired (anti-freeze: a stalled feed is not trusted forever).
    #[error("manifest expired at {expires}, now {now}")]
    ManifestExpired {
        /// The manifest's `expires` timestamp.
        expires: u64,
        /// The current time supplied to the check.
        now: u64,
    },
    /// The manifest was signed under a delegation version older than one already trusted.
    #[error("root_version regressed: trusted {trusted}, manifest {manifest}")]
    RootVersionRegressed {
        /// The highest `root_version` already trusted.
        trusted: u32,
        /// The candidate manifest's `root_version`.
        manifest: u32,
    },
    /// The manifest's `sequence` regressed vs the last accepted manifest (anti-rollback).
    #[error("sequence regressed: trusted {trusted}, manifest {manifest}")]
    SequenceRegressed {
        /// The highest `sequence` already trusted.
        trusted: u64,
        /// The candidate manifest's `sequence`.
        manifest: u64,
    },
    /// The manifest's `generated` timestamp regressed (anti-freeze replay of an old feed).
    #[error("generated timestamp regressed: trusted {trusted}, manifest {manifest}")]
    GeneratedRegressed {
        /// The highest `generated` already trusted.
        trusted: u64,
        /// The candidate manifest's `generated`.
        manifest: u64,
    },
    /// The manifest's `root_version` does not match the delegation that carried the key
    /// which signed it (a mixed/mismatched delegation+manifest pair).
    #[error(
        "manifest root_version {manifest} does not match delegation root_version {delegation}"
    )]
    RootVersionMismatch {
        /// The manifest's declared `root_version`.
        manifest: u32,
        /// The verifying delegation's `root_version`.
        delegation: u32,
    },
    /// A component's build is strictly below the anti-downgrade floor.
    #[error("component {name} build {build} is below the rollback floor {floor}")]
    BelowRollbackFloor {
        /// The offending component name.
        name: String,
        /// That component's build number.
        build: u64,
        /// The manifest's `rollback_floor_build`.
        floor: u64,
    },
    /// A downloaded artifact's bytes did not match the manifest's SHA-256.
    #[error("artifact digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch {
        /// The expected lowercase-hex digest from the signed manifest.
        expected: String,
        /// The digest actually computed over the downloaded bytes.
        actual: String,
    },
    /// The manifest's declared digest was not valid 32-byte lowercase hex.
    #[error("malformed artifact digest hex: {0}")]
    BadDigestHex(String),
}

/// Decode a base64 32-byte Ed25519 public key.
fn decode_verifying_key(b64: &str) -> Result<VerifyingKey, TrustError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| TrustError::BadKeyEncoding(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TrustError::BadKeyEncoding("key is not 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| TrustError::BadKeyEncoding(e.to_string()))
}

/// Decode a base64 64-byte Ed25519 signature.
fn decode_signature(b64: &str) -> Result<Signature, TrustError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| TrustError::BadSignatureEncoding(e.to_string()))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| TrustError::BadSignatureEncoding("signature is not 64 bytes".to_string()))?;
    Ok(Signature::from_bytes(&arr))
}

/// Verify a [`SignedDelegation`] against the pinned **root** key and its expiry, returning
/// the **targets** key it authorizes.
///
/// This is step 1 of the chain: it establishes which key is currently allowed to sign
/// manifests. A delegation that is unsigned-by-root, malformed, or expired yields no
/// targets key.
pub fn verify_delegation(
    root: &VerifyingKey,
    signed: &SignedDelegation,
    now: u64,
) -> Result<VerifyingKey, TrustError> {
    let sig = decode_signature(&signed.signature)?;
    root.verify_strict(&signed.delegation.signing_bytes(), &sig)
        .map_err(|_| TrustError::DelegationSignatureInvalid)?;
    if now > signed.delegation.expires {
        return Err(TrustError::DelegationExpired {
            expires: signed.delegation.expires,
            now,
        });
    }
    decode_verifying_key(&signed.delegation.targets_pubkey)
}

/// Verify a [`SignedManifest`]'s signature under the given **targets** key. This checks the
/// signature ONLY; freshness/expiry/monotonicity are [`verify_freshness`].
pub fn verify_manifest_signature(
    targets: &VerifyingKey,
    signed: &SignedManifest,
) -> Result<(), TrustError> {
    let sig = decode_signature(&signed.signature)?;
    targets
        .verify_strict(&signed.manifest.signing_bytes(), &sig)
        .map_err(|_| TrustError::ManifestSignatureInvalid)
}

/// Enforce freshness against prior [`TrustState`]: not expired, and no regression of
/// `root_version` / `sequence` / `generated`. This is what defeats freeze and rollback
/// replays of authentically-signed but stale manifests.
pub fn verify_freshness(
    state: &TrustState,
    manifest: &Manifest,
    now: u64,
) -> Result<(), TrustError> {
    if now > manifest.expires {
        return Err(TrustError::ManifestExpired {
            expires: manifest.expires,
            now,
        });
    }
    if manifest.root_version < state.root_version {
        return Err(TrustError::RootVersionRegressed {
            trusted: state.root_version,
            manifest: manifest.root_version,
        });
    }
    if manifest.sequence < state.sequence {
        return Err(TrustError::SequenceRegressed {
            trusted: state.sequence,
            manifest: manifest.sequence,
        });
    }
    if manifest.generated < state.generated {
        return Err(TrustError::GeneratedRegressed {
            trusted: state.generated,
            manifest: manifest.generated,
        });
    }
    Ok(())
}

/// Enforce the anti-downgrade floor: every component's `build` must be at or above the
/// manifest's `rollback_floor_build`.
pub fn verify_rollback_floor(manifest: &Manifest) -> Result<(), TrustError> {
    for c in &manifest.components {
        if c.build < manifest.rollback_floor_build {
            return Err(TrustError::BelowRollbackFloor {
                name: c.name.clone(),
                build: c.build,
                floor: manifest.rollback_floor_build,
            });
        }
    }
    Ok(())
}

/// Verify that `bytes` hash to the artifact's declared SHA-256. This is the last gate
/// before a downloaded artifact reaches the privileged installer: verify-then-install,
/// never install-then-verify.
pub fn verify_artifact_digest(artifact: &Artifact, bytes: &[u8]) -> Result<(), TrustError> {
    let expected = artifact.sha256.to_ascii_lowercase();
    // Validate the declared digest is well-formed 32-byte hex before comparing.
    let expected_raw =
        hex::decode(&expected).map_err(|e| TrustError::BadDigestHex(e.to_string()))?;
    if expected_raw.len() != 32 {
        return Err(TrustError::BadDigestHex(format!(
            "expected 32 bytes, got {}",
            expected_raw.len()
        )));
    }
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        return Err(TrustError::DigestMismatch { expected, actual });
    }
    Ok(())
}

/// The full trust chain, applied in order: verify the delegation under the pinned root key,
/// verify the manifest under the delegated targets key, require the manifest's
/// `root_version` to match the delegation, enforce freshness against prior state, and
/// enforce the anti-downgrade floor.
///
/// On success the caller MAY fetch the artifacts, verify each with
/// [`verify_artifact_digest`], install, and then [`TrustState::advance`] the state. This
/// function performs no I/O and does not mutate the state.
pub fn verify_update_chain(
    root: &VerifyingKey,
    state: &TrustState,
    delegation: &SignedDelegation,
    manifest: &SignedManifest,
    now: u64,
) -> Result<(), TrustError> {
    let targets = verify_delegation(root, delegation, now)?;
    verify_manifest_signature(&targets, manifest)?;
    if manifest.manifest.root_version != delegation.delegation.root_version {
        return Err(TrustError::RootVersionMismatch {
            manifest: manifest.manifest.root_version,
            delegation: delegation.delegation.root_version,
        });
    }
    verify_freshness(state, &manifest.manifest, now)?;
    verify_rollback_floor(&manifest.manifest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Artifact, Component, Delegation};
    use ed25519_dalek::{Signer, SigningKey};

    // Deterministic test keys (fixed seeds — no rng). These are TEST keys only; they are
    // unrelated to the pinned production root key (whose private half is a CI secret).
    fn root_keys() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }
    fn targets_keys() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn sign_delegation(sk: &SigningKey, d: Delegation) -> SignedDelegation {
        let signature = b64(&sk.sign(&d.signing_bytes()).to_bytes());
        SignedDelegation {
            delegation: d,
            signature,
        }
    }
    fn sign_manifest(sk: &SigningKey, m: Manifest) -> SignedManifest {
        let signature = b64(&sk.sign(&m.signing_bytes()).to_bytes());
        SignedManifest {
            manifest: m,
            signature,
        }
    }

    fn sample_manifest() -> Manifest {
        Manifest {
            schema: 1,
            root_version: 1,
            sequence: 10,
            generated: 1000,
            expires: 2000,
            rollback_floor_build: 5,
            components: vec![Component {
                name: "dig-node".to_string(),
                version: "0.26.0".to_string(),
                build: 26,
                artifacts: vec![Artifact {
                    os: "linux".to_string(),
                    arch: "x64".to_string(),
                    url: "https://updates.dig.net/dig-node/0.26.0/linux-x64".to_string(),
                    sha256: hex::encode(Sha256::digest(b"the-artifact-bytes")),
                    size: 18,
                }],
            }],
        }
    }

    /// The whole chain accepts a correctly-signed, fresh, in-floor update.
    #[test]
    fn full_chain_accepts_valid_update() {
        let (rk, rv) = root_keys();
        let (tk, tv) = targets_keys();
        let deleg = sign_delegation(
            &rk,
            Delegation {
                root_version: 1,
                targets_pubkey: b64(&tv.to_bytes()),
                expires: 5000,
            },
        );
        let man = sign_manifest(&tk, sample_manifest());
        let state = TrustState::initial();
        assert_eq!(verify_update_chain(&rv, &state, &deleg, &man, 1500), Ok(()));
    }

    /// A good manifest signature verifies under the delegated targets key.
    #[test]
    fn good_manifest_signature_passes() {
        let (tk, tv) = targets_keys();
        let man = sign_manifest(&tk, sample_manifest());
        assert_eq!(verify_manifest_signature(&tv, &man), Ok(()));
    }

    /// Tampering with the manifest payload after signing invalidates the signature.
    #[test]
    fn tampered_manifest_fails_signature() {
        let (tk, tv) = targets_keys();
        let mut man = sign_manifest(&tk, sample_manifest());
        man.manifest.components[0].version = "9.9.9".to_string(); // tamper post-sign
        assert_eq!(
            verify_manifest_signature(&tv, &man),
            Err(TrustError::ManifestSignatureInvalid)
        );
    }

    /// A manifest signed by the wrong (undelegated) key is rejected.
    #[test]
    fn manifest_signed_by_wrong_key_fails() {
        let (_rk, _rv) = root_keys();
        let (_tk, tv) = targets_keys();
        // Sign with the ROOT key but verify under the TARGETS key.
        let (rk, _) = root_keys();
        let man = sign_manifest(&rk, sample_manifest());
        assert_eq!(
            verify_manifest_signature(&tv, &man),
            Err(TrustError::ManifestSignatureInvalid)
        );
    }

    /// The delegation must be signed by the pinned root key.
    #[test]
    fn delegation_signed_by_wrong_key_fails() {
        let (_rk, rv) = root_keys();
        let (tk, tv) = targets_keys();
        // Sign the delegation with the TARGETS key instead of the root key.
        let deleg = sign_delegation(
            &tk,
            Delegation {
                root_version: 1,
                targets_pubkey: b64(&tv.to_bytes()),
                expires: 5000,
            },
        );
        assert_eq!(
            verify_delegation(&rv, &deleg, 1000),
            Err(TrustError::DelegationSignatureInvalid)
        );
    }

    /// An expired manifest is rejected by the freshness check.
    #[test]
    fn expired_manifest_fails() {
        let state = TrustState::initial();
        let m = sample_manifest(); // expires: 2000
        assert_eq!(
            verify_freshness(&state, &m, 2001),
            Err(TrustError::ManifestExpired {
                expires: 2000,
                now: 2001
            })
        );
    }

    /// An expired delegation is rejected even with a valid signature.
    #[test]
    fn expired_delegation_fails() {
        let (rk, rv) = root_keys();
        let (_tk, tv) = targets_keys();
        let deleg = sign_delegation(
            &rk,
            Delegation {
                root_version: 1,
                targets_pubkey: b64(&tv.to_bytes()),
                expires: 100,
            },
        );
        assert_eq!(
            verify_delegation(&rv, &deleg, 101),
            Err(TrustError::DelegationExpired {
                expires: 100,
                now: 101
            })
        );
    }

    /// A downgraded (lower-sequence) manifest is rejected against advanced state.
    #[test]
    fn downgraded_sequence_fails() {
        let mut state = TrustState::initial();
        state.sequence = 20; // we've already seen sequence 20
        let m = sample_manifest(); // sequence: 10
        assert_eq!(
            verify_freshness(&state, &m, 1500),
            Err(TrustError::SequenceRegressed {
                trusted: 20,
                manifest: 10
            })
        );
    }

    /// A regressed generated timestamp (freeze replay) is rejected.
    #[test]
    fn regressed_generated_fails() {
        let mut state = TrustState::initial();
        state.generated = 5000;
        let m = sample_manifest(); // generated: 1000
        assert_eq!(
            verify_freshness(&state, &m, 1500),
            Err(TrustError::GeneratedRegressed {
                trusted: 5000,
                manifest: 1000
            })
        );
    }

    /// A regressed root_version is rejected.
    #[test]
    fn regressed_root_version_fails() {
        let mut state = TrustState::initial();
        state.root_version = 3;
        let m = sample_manifest(); // root_version: 1
        assert_eq!(
            verify_freshness(&state, &m, 1500),
            Err(TrustError::RootVersionRegressed {
                trusted: 3,
                manifest: 1
            })
        );
    }

    /// A manifest whose root_version disagrees with the delegation is rejected.
    #[test]
    fn root_version_mismatch_fails() {
        let (rk, rv) = root_keys();
        let (tk, tv) = targets_keys();
        let deleg = sign_delegation(
            &rk,
            Delegation {
                root_version: 2, // delegation says 2
                targets_pubkey: b64(&tv.to_bytes()),
                expires: 5000,
            },
        );
        let man = sign_manifest(&tk, sample_manifest()); // manifest says 1
        assert_eq!(
            verify_update_chain(&rv, &TrustState::initial(), &deleg, &man, 1500),
            Err(TrustError::RootVersionMismatch {
                manifest: 1,
                delegation: 2
            })
        );
    }

    /// A component below the rollback floor is rejected (anti-downgrade).
    #[test]
    fn below_rollback_floor_fails() {
        let mut m = sample_manifest();
        m.rollback_floor_build = 100; // floor above the component's build (26)
        assert_eq!(
            verify_rollback_floor(&m),
            Err(TrustError::BelowRollbackFloor {
                name: "dig-node".to_string(),
                build: 26,
                floor: 100
            })
        );
    }

    /// A correct artifact digest passes.
    #[test]
    fn artifact_digest_matches() {
        let bytes = b"the-artifact-bytes";
        let art = &sample_manifest().components[0].artifacts[0];
        assert_eq!(verify_artifact_digest(art, bytes), Ok(()));
    }

    /// A tampered artifact (wrong bytes) is rejected.
    #[test]
    fn artifact_digest_mismatch_fails() {
        let art = &sample_manifest().components[0].artifacts[0];
        let err = verify_artifact_digest(art, b"malicious-bytes").unwrap_err();
        assert!(matches!(err, TrustError::DigestMismatch { .. }));
    }

    /// A malformed declared digest is rejected as bad hex, not silently accepted.
    #[test]
    fn artifact_digest_bad_hex_fails() {
        let mut art = sample_manifest().components[0].artifacts[0].clone();
        art.sha256 = "not-hex".to_string();
        let err = verify_artifact_digest(&art, b"whatever").unwrap_err();
        assert!(matches!(err, TrustError::BadDigestHex(_)));
    }

    /// Malformed signature/key encodings are rejected with the specific error.
    #[test]
    fn malformed_encodings_fail() {
        assert!(matches!(
            decode_signature("!!not base64!!"),
            Err(TrustError::BadSignatureEncoding(_))
        ));
        assert!(matches!(
            decode_signature(&b64(&[0u8; 10])), // valid b64, wrong length
            Err(TrustError::BadSignatureEncoding(_))
        ));
        assert!(matches!(
            decode_verifying_key("!!not base64!!"),
            Err(TrustError::BadKeyEncoding(_))
        ));
        assert!(matches!(
            decode_verifying_key(&b64(&[0u8; 10])),
            Err(TrustError::BadKeyEncoding(_))
        ));
    }

    /// The delegation's targets-key encoding is surfaced when malformed.
    #[test]
    fn delegation_bad_targets_key_fails() {
        let (rk, rv) = root_keys();
        let deleg = sign_delegation(
            &rk,
            Delegation {
                root_version: 1,
                targets_pubkey: "not-a-key".to_string(),
                expires: 5000,
            },
        );
        assert!(matches!(
            verify_delegation(&rv, &deleg, 1000),
            Err(TrustError::BadKeyEncoding(_))
        ));
    }

    /// `TrustState::advance` folds the manifest's marks forward and never regresses.
    #[test]
    fn trust_state_advances_monotonically() {
        let mut state = TrustState::initial();
        let m = sample_manifest();
        state.advance(&m);
        assert_eq!(state.root_version, 1);
        assert_eq!(state.sequence, 10);
        assert_eq!(state.generated, 1000);
        assert_eq!(state.rollback_floor_build, 5);
        // Advancing with an older manifest does not move the marks backward.
        let mut older = sample_manifest();
        older.sequence = 1;
        older.generated = 1;
        state.advance(&older);
        assert_eq!(state.sequence, 10);
        assert_eq!(state.generated, 1000);
    }

    /// Error values render a human-readable message (agent/log friendliness).
    #[test]
    fn errors_display() {
        let e = TrustError::ManifestExpired { expires: 1, now: 2 };
        assert!(e.to_string().contains("expired"));
    }

    /// Manifest lookups by component/artifact resolve as expected.
    #[test]
    fn manifest_lookups() {
        let m = sample_manifest();
        assert!(m.component("dig-node").is_some());
        assert!(m.component("nope").is_none());
        let c = m.component("dig-node").unwrap();
        assert!(c.artifact("linux", "x64").is_some());
        assert!(c.artifact("windows", "x64").is_none());
    }
}
