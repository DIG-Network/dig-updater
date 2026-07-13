//! The verification surface: signature checks, freshness/monotonicity checks, per-artifact
//! digest checks, and the composed [`verify_update_chain`] that a caller applies in order.
//!
//! Every check fails **closed** with a specific [`TrustError`]. The signature checks use
//! `ed25519_dalek`'s strict verification (`verify_strict`), which rejects small-order /
//! non-canonical public keys and malleable signatures. Signatures are always checked over the
//! **exact received payload bytes** ([`SignedDelegation::signed_payload`] /
//! [`SignedManifest::signed_payload`]), never over a re-serialization — see the [`manifest`]
//! module docs for why (forward-compatibility, SPEC §5.4).
//!
//! [`manifest`]: crate::manifest

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::manifest::{Artifact, Manifest, SignedDelegation, SignedManifest};
use crate::trust_state::TrustState;

/// Everything that can make an update untrusted. Each variant is a distinct, testable
/// rejection reason; nothing is collapsed into a generic "invalid". [`TrustError::code`]
/// exposes a stable machine-classifiable string for each (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A signature string was not valid base64 or not a 64-byte Ed25519 signature.
    #[error("malformed signature encoding: {0}")]
    BadSignatureEncoding(String),
    /// A public-key string was not valid base64 or not a valid 32-byte Ed25519 key.
    #[error("malformed key encoding: {0}")]
    BadKeyEncoding(String),
    /// A signed feed object (envelope or payload) was not well-formed JSON.
    #[error("malformed JSON: {0}")]
    MalformedJson(String),
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
    /// The manifest's `rollback_floor_build` is LOWER than the highest floor ever accepted. The
    /// floor is a monotonic high-water-mark (SPEC §6) — it may rise but never fall — so a manifest
    /// that lowers it is rejected. This blocks a compromised targets key from setting the floor
    /// back to 0 to re-enable a downgrade to an old, validly-signed, vulnerable build within a
    /// `root_version` epoch (the pinned root would otherwise have to rotate the delegation to
    /// undo it).
    #[error("rollback floor regressed: trusted {trusted}, manifest {manifest}")]
    RollbackFloorRegressed {
        /// The highest `rollback_floor_build` already trusted.
        trusted: u64,
        /// The candidate manifest's `rollback_floor_build`.
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

impl TrustError {
    /// A stable, machine-classifiable snake_case code for this rejection. Stable codes let the
    /// broker, logs, and agents branch on the reason without parsing human prose (§6.2).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadSignatureEncoding(_) => "bad_signature_encoding",
            Self::BadKeyEncoding(_) => "bad_key_encoding",
            Self::MalformedJson(_) => "malformed_json",
            Self::DelegationSignatureInvalid => "delegation_signature_invalid",
            Self::ManifestSignatureInvalid => "manifest_signature_invalid",
            Self::DelegationExpired { .. } => "delegation_expired",
            Self::ManifestExpired { .. } => "manifest_expired",
            Self::RootVersionRegressed { .. } => "root_version_regressed",
            Self::SequenceRegressed { .. } => "sequence_regressed",
            Self::GeneratedRegressed { .. } => "generated_regressed",
            Self::RollbackFloorRegressed { .. } => "rollback_floor_regressed",
            Self::RootVersionMismatch { .. } => "root_version_mismatch",
            Self::BelowRollbackFloor { .. } => "below_rollback_floor",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::BadDigestHex(_) => "bad_digest_hex",
        }
    }
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
/// targets key. The signature is checked over the delegation's exact received bytes.
pub fn verify_delegation(
    root: &VerifyingKey,
    signed: &SignedDelegation,
    now: u64,
) -> Result<VerifyingKey, TrustError> {
    let sig = decode_signature(&signed.signature)?;
    root.verify_strict(signed.signed_payload(), &sig)
        .map_err(|_| TrustError::DelegationSignatureInvalid)?;
    if now > signed.delegation.expires {
        return Err(TrustError::DelegationExpired {
            expires: signed.delegation.expires,
            now,
        });
    }
    decode_verifying_key(&signed.delegation.targets_pubkey)
}

/// Verify a [`SignedManifest`]'s signature under the given **targets** key, over the manifest's
/// exact received bytes. This checks the signature ONLY; freshness/expiry/monotonicity are
/// [`verify_freshness`].
pub fn verify_manifest_signature(
    targets: &VerifyingKey,
    signed: &SignedManifest,
) -> Result<(), TrustError> {
    let sig = decode_signature(&signed.signature)?;
    targets
        .verify_strict(signed.signed_payload(), &sig)
        .map_err(|_| TrustError::ManifestSignatureInvalid)
}

/// Enforce freshness against prior [`TrustState`]: not expired, and no regression of any
/// monotonic high-water-mark — `root_version`, `sequence`, `generated`, or `rollback_floor_build`.
/// This is what defeats freeze and rollback replays of authentically-signed but stale manifests,
/// and (via the floor mark) an authentically-signed manifest that tries to LOWER the anti-downgrade
/// floor to re-enable a downgrade.
///
/// All four marks are strictly monotonic per SPEC §6 — they may rise but never fall — so the four
/// checks here are the runtime enforcement of that invariant. A caller that accepts the manifest
/// then folds it in with [`TrustState::advance`] keeps the marks moving forward only.
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
    // The rollback floor is a monotonic mark too (SPEC §6): a manifest may raise it but never lower
    // it. Rejecting a lowered floor blocks a compromised targets key from re-opening a downgrade
    // window within the current `root_version` epoch.
    if manifest.rollback_floor_build < state.rollback_floor_build {
        return Err(TrustError::RollbackFloorRegressed {
            trusted: state.rollback_floor_build,
            manifest: manifest.rollback_floor_build,
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

/// Verify that a computed SHA-256 equals a declared lowercase-hex digest. The declared digest
/// MUST be well-formed 32-byte hex or the check fails closed with [`TrustError::BadDigestHex`].
///
/// This is the shared digest gate: [`verify_artifact_digest`] uses it for an in-memory slice,
/// and the worker's streaming downloader uses it for the incrementally-hashed artifact — so a
/// hostile CDN's bytes are rejected identically whether hashed at once or in chunks.
pub fn verify_sha256(expected_hex: &str, actual: &[u8; 32]) -> Result<(), TrustError> {
    let expected = expected_hex.to_ascii_lowercase();
    let expected_raw =
        hex::decode(&expected).map_err(|e| TrustError::BadDigestHex(e.to_string()))?;
    if expected_raw.len() != 32 {
        return Err(TrustError::BadDigestHex(format!(
            "expected 32 bytes, got {}",
            expected_raw.len()
        )));
    }
    if expected_raw.as_slice() != actual.as_slice() {
        return Err(TrustError::DigestMismatch {
            expected,
            actual: hex::encode(actual),
        });
    }
    Ok(())
}

/// Verify that `bytes` hash to the artifact's declared SHA-256. This is the last gate
/// before a downloaded artifact reaches the privileged installer: verify-then-install,
/// never install-then-verify.
pub fn verify_artifact_digest(artifact: &Artifact, bytes: &[u8]) -> Result<(), TrustError> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    verify_sha256(&artifact.sha256, &actual)
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
    use crate::manifest::{Artifact, Component, Delegation, SignedDelegation, SignedManifest};
    use ed25519_dalek::SigningKey;

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

    fn sample_delegation(root_version: u32, expires: u64, targets: &VerifyingKey) -> Delegation {
        Delegation {
            root_version,
            targets_pubkey: b64(&targets.to_bytes()),
            expires,
        }
    }

    /// The whole chain accepts a correctly-signed, fresh, in-floor update.
    #[test]
    fn full_chain_accepts_valid_update() {
        let (rk, rv) = root_keys();
        let (tk, tv) = targets_keys();
        let deleg = SignedDelegation::sign(sample_delegation(1, 5000, &tv), &rk);
        let man = SignedManifest::sign(sample_manifest(), &tk);
        let state = TrustState::initial();
        assert_eq!(verify_update_chain(&rv, &state, &deleg, &man, 1500), Ok(()));
    }

    /// A good manifest signature verifies under the delegated targets key.
    #[test]
    fn good_manifest_signature_passes() {
        let (tk, tv) = targets_keys();
        let man = SignedManifest::sign(sample_manifest(), &tk);
        assert_eq!(verify_manifest_signature(&tv, &man), Ok(()));
    }

    /// Tampering with the manifest payload after parsing invalidates the signature: the
    /// signature covers the received bytes, so a re-serialized tampered payload no longer
    /// matches. (We tamper by re-signing bytes that differ from the envelope's payload.)
    #[test]
    fn tampered_manifest_body_fails_signature() {
        let (tk, tv) = targets_keys();
        // Sign the honest manifest, then splice its signature onto a DIFFERENT payload.
        let honest = SignedManifest::sign(sample_manifest(), &tk);
        let mut evil = sample_manifest();
        evil.components[0].version = "9.9.9".to_string();
        let evil_json = format!(
            r#"{{"manifest":{},"signature":"{}"}}"#,
            String::from_utf8(evil.signing_bytes()).unwrap(),
            honest.signature
        );
        let spliced = SignedManifest::from_json(&evil_json).unwrap();
        assert_eq!(
            verify_manifest_signature(&tv, &spliced),
            Err(TrustError::ManifestSignatureInvalid)
        );
    }

    /// A manifest signed by the wrong (undelegated) key is rejected.
    #[test]
    fn manifest_signed_by_wrong_key_fails() {
        let (rk, _rv) = root_keys();
        let (_tk, tv) = targets_keys();
        // Sign with the ROOT key but verify under the TARGETS key.
        let man = SignedManifest::sign(sample_manifest(), &rk);
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
        let deleg = SignedDelegation::sign(sample_delegation(1, 5000, &tv), &tk);
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
        let deleg = SignedDelegation::sign(sample_delegation(1, 100, &tv), &rk);
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

    /// A manifest that LOWERS the rollback floor below the accepted high-water-mark is rejected
    /// (anti-downgrade of the floor itself). This is the regression proof for the #504-E finding:
    /// a compromised targets key must not be able to reset the floor to re-enable a downgrade.
    #[test]
    fn lowered_rollback_floor_fails() {
        let mut state = TrustState::initial();
        state.rollback_floor_build = 20; // we've accepted a floor of 20
        let mut m = sample_manifest();
        m.rollback_floor_build = 0; // a manifest trying to drop the floor back to 0
        assert_eq!(
            verify_freshness(&state, &m, 1500),
            Err(TrustError::RollbackFloorRegressed {
                trusted: 20,
                manifest: 0
            })
        );
    }

    /// A manifest that RAISES the floor is accepted (the floor may rise).
    #[test]
    fn raised_rollback_floor_passes() {
        let mut state = TrustState::initial();
        state.rollback_floor_build = 5;
        let mut m = sample_manifest();
        m.rollback_floor_build = 10; // raising the floor is allowed
        assert_eq!(verify_freshness(&state, &m, 1500), Ok(()));
    }

    /// A manifest whose root_version disagrees with the delegation is rejected.
    #[test]
    fn root_version_mismatch_fails() {
        let (rk, rv) = root_keys();
        let (tk, tv) = targets_keys();
        let deleg = SignedDelegation::sign(sample_delegation(2, 5000, &tv), &rk); // says 2
        let man = SignedManifest::sign(sample_manifest(), &tk); // says 1
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

    /// A declared digest of the wrong byte length is rejected as bad hex.
    #[test]
    fn digest_wrong_length_fails() {
        let short = hex::encode([0u8; 16]);
        assert!(matches!(
            verify_sha256(&short, &[0u8; 32]),
            Err(TrustError::BadDigestHex(_))
        ));
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
        let deleg = SignedDelegation::sign(
            Delegation {
                root_version: 1,
                targets_pubkey: "not-a-key".to_string(),
                expires: 5000,
            },
            &rk,
        );
        assert!(matches!(
            verify_delegation(&rv, &deleg, 1000),
            Err(TrustError::BadKeyEncoding(_))
        ));
    }

    /// Every rejection carries a distinct, stable code (no two variants collide).
    #[test]
    fn error_codes_are_distinct_and_stable() {
        use std::collections::HashSet;
        let errors = [
            TrustError::BadSignatureEncoding(String::new()),
            TrustError::BadKeyEncoding(String::new()),
            TrustError::MalformedJson(String::new()),
            TrustError::DelegationSignatureInvalid,
            TrustError::ManifestSignatureInvalid,
            TrustError::DelegationExpired { expires: 0, now: 0 },
            TrustError::ManifestExpired { expires: 0, now: 0 },
            TrustError::RootVersionRegressed {
                trusted: 0,
                manifest: 0,
            },
            TrustError::SequenceRegressed {
                trusted: 0,
                manifest: 0,
            },
            TrustError::GeneratedRegressed {
                trusted: 0,
                manifest: 0,
            },
            TrustError::RollbackFloorRegressed {
                trusted: 0,
                manifest: 0,
            },
            TrustError::RootVersionMismatch {
                manifest: 0,
                delegation: 0,
            },
            TrustError::BelowRollbackFloor {
                name: String::new(),
                build: 0,
                floor: 0,
            },
            TrustError::DigestMismatch {
                expected: String::new(),
                actual: String::new(),
            },
            TrustError::BadDigestHex(String::new()),
        ];
        let codes: HashSet<_> = errors.iter().map(TrustError::code).collect();
        assert_eq!(codes.len(), errors.len(), "codes must be unique");
    }

    /// A manifest carrying an unknown, additive field STILL verifies (SPEC §5.2/§5.4
    /// forward-compatibility). This is the regression proof for the #504-D fix: the signature
    /// is checked over the received bytes (which include the unknown field), so an old reader
    /// that cannot interpret the field still accepts the message.
    #[test]
    fn unknown_field_manifest_still_verifies() {
        let (tk, tv) = targets_keys();
        // A signer emits a canonical manifest AND an additive future field, and signs the
        // exact bytes it emits.
        let canonical = String::from_utf8(sample_manifest().signing_bytes()).unwrap();
        // Insert `"future_flag":true,` right after the opening brace (still valid JSON).
        let with_extra = format!("{{\"future_flag\":true,{}", &canonical[1..]);
        let sig = b64(&{
            use ed25519_dalek::Signer;
            tk.sign(with_extra.as_bytes()).to_bytes()
        });
        let envelope = format!(r#"{{"manifest":{with_extra},"signature":"{sig}"}}"#);

        let parsed = SignedManifest::from_json(&envelope).expect("well-formed JSON");
        // The old reader parsed the known fields and ignored `future_flag`...
        assert_eq!(parsed.manifest.sequence, 10);
        // ...and the signature STILL verifies over the received bytes.
        assert_eq!(verify_manifest_signature(&tv, &parsed), Ok(()));
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
}
