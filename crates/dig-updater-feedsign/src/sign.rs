//! Loading the Ed25519 signing key from the `BEACON_SIGNING_KEY` secret, and proving it is the
//! pinned beacon root key before anything is signed.
//!
//! The alpha key was generated with `openssl genpkey -algorithm ed25519` (SPEC §4.3), so the
//! secret is most naturally a PKCS#8 private key — but rather than assume ONE encoding, this
//! accepts the three shapes the secret could hold and normalizes them all to the 32-byte Ed25519
//! seed:
//!
//! * a PKCS#8 v1 PEM (`-----BEGIN PRIVATE KEY-----` … openssl's default output),
//! * the bare base64 of that PKCS#8 DER, or
//! * the base64 of the raw 32-byte seed.
//!
//! Whatever the shape, [`assert_pinned_root`] then confirms the derived PUBLIC key equals the
//! pinned `BEACON_ROOT_PUBKEY_B64`. If it does not, signing is refused — a feed signed under a
//! stray key would verify under no shipped beacon, so failing closed here turns a key-hygiene
//! mistake into a loud CI failure instead of a silently-broken feed.

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};

use dig_updater_trust::BEACON_ROOT_PUBKEY_B64;

use crate::error::FeedsignError;

/// The fixed 16-byte DER prefix of a PKCS#8 v1 Ed25519 private key (RFC 8410 §7):
/// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { <32-byte seed> } } }`.
/// The 32-byte seed follows this prefix, for 48 bytes total.
const PKCS8_ED25519_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Standard-alphabet base64 (RFC 4648 §4), the encoding the beacon uses on the wire.
fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Load the Ed25519 signing key from the raw secret string, accepting a PKCS#8 PEM, a base64
/// PKCS#8 DER, or the base64 of the raw 32-byte seed (see the module docs).
///
/// # Errors
///
/// [`FeedsignError::SigningKey`] if the material is not decodable into a 32-byte Ed25519 seed.
pub fn signing_key_from_secret(secret: &str) -> Result<SigningKey, FeedsignError> {
    let der = decode_key_material(secret)?;
    let seed = extract_seed(&der)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Strip any PEM armor + whitespace and base64-decode to the underlying bytes (raw seed or DER).
fn decode_key_material(secret: &str) -> Result<Vec<u8>, FeedsignError> {
    let body: String = secret
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err(FeedsignError::SigningKey("empty key material".to_string()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(&body)
        .map_err(|e| FeedsignError::SigningKey(format!("base64: {e}")))
}

/// Reduce decoded key material to the 32-byte Ed25519 seed: the bytes themselves if they are a
/// raw seed, or the tail of a PKCS#8 v1 Ed25519 private key.
fn extract_seed(der: &[u8]) -> Result<[u8; 32], FeedsignError> {
    match der.len() {
        32 => der
            .try_into()
            .map_err(|_| FeedsignError::SigningKey("seed is not 32 bytes".to_string())),
        48 if der[..16] == PKCS8_ED25519_V1_PREFIX => der[16..]
            .try_into()
            .map_err(|_| FeedsignError::SigningKey("PKCS#8 seed is not 32 bytes".to_string())),
        other => Err(FeedsignError::SigningKey(format!(
            "expected a 32-byte raw seed or a 48-byte PKCS#8 Ed25519 key, got {other} bytes"
        ))),
    }
}

/// Whether a verifying key is the pinned beacon root key (a base64 comparison of the 32 key bytes
/// against [`BEACON_ROOT_PUBKEY_B64`]).
#[must_use]
pub fn is_pinned_root(key: &VerifyingKey) -> bool {
    b64_encode(&key.to_bytes()) == BEACON_ROOT_PUBKEY_B64
}

/// Confirm the signing key derives the pinned beacon root key. This is the hard gate the binary
/// runs before signing: it guarantees the produced feed will verify under every shipped beacon.
///
/// # Errors
///
/// [`FeedsignError::KeyNotPinned`] if the derived public key is not the pinned root key.
pub fn assert_pinned_root(key: &SigningKey) -> Result<(), FeedsignError> {
    if is_pinned_root(&key.verifying_key()) {
        Ok(())
    } else {
        Err(FeedsignError::KeyNotPinned {
            expected: BEACON_ROOT_PUBKEY_B64.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_updater_trust::beacon_root_verifying_key;

    /// A deterministic throwaway seed for the encoding tests (unrelated to the pinned key).
    const SEED: [u8; 32] = [42u8; 32];

    fn pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
        let mut der = PKCS8_ED25519_V1_PREFIX.to_vec();
        der.extend_from_slice(seed);
        der
    }

    #[test]
    fn parses_raw_seed_base64() {
        let secret = b64_encode(&SEED);
        let key = signing_key_from_secret(&secret).unwrap();
        assert_eq!(key.to_bytes(), SEED);
    }

    #[test]
    fn parses_pkcs8_der_base64() {
        let secret = b64_encode(&pkcs8_der(&SEED));
        let key = signing_key_from_secret(&secret).unwrap();
        assert_eq!(key.to_bytes(), SEED);
    }

    #[test]
    fn parses_pkcs8_pem_with_armor_and_newlines() {
        let der_b64 = b64_encode(&pkcs8_der(&SEED));
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{der_b64}\n-----END PRIVATE KEY-----\n");
        let key = signing_key_from_secret(&pem).unwrap();
        assert_eq!(key.to_bytes(), SEED);
    }

    #[test]
    fn all_three_encodings_yield_the_same_key() {
        let raw = signing_key_from_secret(&b64_encode(&SEED)).unwrap();
        let der = signing_key_from_secret(&b64_encode(&pkcs8_der(&SEED))).unwrap();
        assert_eq!(raw.to_bytes(), der.to_bytes());
    }

    #[test]
    fn rejects_empty_and_malformed_material() {
        assert!(matches!(
            signing_key_from_secret(""),
            Err(FeedsignError::SigningKey(_))
        ));
        assert!(matches!(
            signing_key_from_secret("!!not base64!!"),
            Err(FeedsignError::SigningKey(_))
        ));
    }

    #[test]
    fn rejects_wrong_length_material() {
        // 16 bytes: neither a raw seed nor a PKCS#8 key.
        assert!(matches!(
            signing_key_from_secret(&b64_encode(&[0u8; 16])),
            Err(FeedsignError::SigningKey(_))
        ));
    }

    #[test]
    fn pinned_check_recognizes_the_real_root_key() {
        // The trust crate can build the pinned verifying key from its public constant; a signer
        // holding the matching private key must be recognized as the pinned root.
        assert!(is_pinned_root(&beacon_root_verifying_key()));
    }

    #[test]
    fn pinned_check_rejects_a_throwaway_key() {
        let throwaway = SigningKey::from_bytes(&SEED);
        assert!(!is_pinned_root(&throwaway.verifying_key()));
        assert!(matches!(
            assert_pinned_root(&throwaway),
            Err(FeedsignError::KeyNotPinned { .. })
        ));
    }
}
