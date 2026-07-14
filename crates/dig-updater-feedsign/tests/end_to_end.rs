//! The feed-signer's end-to-end trust proof, hermetic (no network, throwaway key): assemble +
//! sign a feed with [`produce_feed`], then verify the produced `delegation.json` + `manifest.json`
//! with the beacon trust core — the SAME `verify_update_chain` the shipped beacon runs. If the
//! signer's canonicalization and the verifier's received-bytes check ever drifted, this would
//! fail; that they agree is the keystone the feed pipeline depends on.
//!
//! The CI `feed.yml` job proves the OTHER half — the REAL pinned key against the REAL shipped
//! binary. This test proves the assembly + signing logic against the trust library exhaustively
//! and without a secret, so every PR runs it.

use std::collections::HashMap;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use dig_updater_feedsign::{
    produce_feed, Channel, FeedConfig, FeedsignError, GithubRelease, GithubSource, ReleaseSource,
    SIGNATURE_FILE, SIGNING_BYTES_FILE, TARGETS_PUBKEY_FILE,
};
use dig_updater_trust::{
    verify_artifact_digest, verify_update_chain, SignedDelegation, SignedManifest, TrustState,
};

const GENERATED: u64 = 1_000_000;

/// An in-memory [`ReleaseSource`]: a per-channel `(repo, channel) → release JSON` table plus an
/// asset URL → bytes table. No network — the whole assemble → sign → verify keystone runs
/// hermetically against a throwaway key.
struct FakeSource {
    releases: HashMap<(String, Channel), String>,
    assets: HashMap<String, Vec<u8>>,
}

impl ReleaseSource for FakeSource {
    fn release(&self, repo: &str, channel: Channel) -> Result<GithubRelease, FeedsignError> {
        let json = self
            .releases
            .get(&(repo.to_string(), channel))
            .unwrap_or_else(|| panic!("no fake {} release for {repo}", channel.as_str()));
        GithubRelease::from_json(repo, json)
    }

    fn download(&self, url: &str) -> Result<Vec<u8>, FeedsignError> {
        Ok(self
            .assets
            .get(url)
            .unwrap_or_else(|| panic!("no fake asset for {url}"))
            .clone())
    }
}

/// Two components, each with a linux + windows asset, mirroring the real release-asset shape — for
/// BOTH channels. Stable resolves `releases/latest` (`vX.Y.Z` tag); nightly resolves the rolling
/// `nightly` tag, whose version lives only in the asset names (`X.Y.Z-nightly.YYYYMMDD.<sha>`).
fn fake_source() -> FakeSource {
    let mut releases = HashMap::new();
    let mut assets = HashMap::new();

    // --- STABLE: releases/latest, version from the tag ---
    releases.insert(
        ("DIG-Network/dig-node".to_string(), Channel::Stable),
        r#"{"tag_name":"v0.29.0","assets":[
            {"name":"dig-node-0.29.0-linux-x64","browser_download_url":"https://dl.test/dig-node/linux"},
            {"name":"dig-node-0.29.0-windows-x64.exe","browser_download_url":"https://dl.test/dig-node/windows"},
            {"name":"dig-node-0.29.0-x86_64-unknown-linux-gnu.tar.gz","browser_download_url":"https://dl.test/dig-node/tarball"}
        ]}"#.to_string(),
    );
    releases.insert(
        ("DIG-Network/digstore".to_string(), Channel::Stable),
        r#"{"tag_name":"v0.13.1","assets":[
            {"name":"digstore-0.13.1-linux-x64","browser_download_url":"https://dl.test/digstore/linux"}
        ]}"#.to_string(),
    );

    // --- NIGHTLY: releases/tags/nightly, version recovered from the asset names ---
    releases.insert(
        ("DIG-Network/dig-node".to_string(), Channel::Nightly),
        r#"{"tag_name":"nightly","assets":[
            {"name":"dig-node-0.30.0-nightly.20260714.abc1234-linux-x64","browser_download_url":"https://dl.test/dig-node/nightly-linux"},
            {"name":"dig-node-0.30.0-nightly.20260714.abc1234-windows-x64.exe","browser_download_url":"https://dl.test/dig-node/nightly-windows"}
        ]}"#.to_string(),
    );
    releases.insert(
        ("DIG-Network/digstore".to_string(), Channel::Nightly),
        r#"{"tag_name":"nightly","assets":[
            {"name":"digstore-0.14.0-nightly.20260714.abc1234-linux-x64","browser_download_url":"https://dl.test/digstore/nightly-linux"}
        ]}"#.to_string(),
    );

    for (url, bytes) in [
        (
            "https://dl.test/dig-node/linux",
            b"dig-node-linux-binary".as_slice(),
        ),
        (
            "https://dl.test/dig-node/windows",
            b"dig-node-windows-binary".as_slice(),
        ),
        (
            "https://dl.test/digstore/linux",
            b"digstore-linux-binary".as_slice(),
        ),
        (
            "https://dl.test/dig-node/nightly-linux",
            b"dig-node-nightly-linux".as_slice(),
        ),
        (
            "https://dl.test/dig-node/nightly-windows",
            b"dig-node-nightly-windows".as_slice(),
        ),
        (
            "https://dl.test/digstore/nightly-linux",
            b"digstore-nightly-linux".as_slice(),
        ),
    ] {
        assets.insert(url.to_string(), bytes.to_vec());
    }

    FakeSource { releases, assets }
}

fn config() -> FeedConfig {
    FeedConfig::from_json(
        r#"{
            "components": [
                { "name": "dig-node", "repo": "DIG-Network/dig-node", "asset_prefix": "dig-node" },
                { "name": "digstore", "repo": "DIG-Network/digstore", "asset_prefix": "digstore" }
            ]
        }"#,
    )
    .unwrap()
}

/// THE keystone: a signer-produced feed verifies under the beacon trust core, including every
/// artifact digest against the exact bytes the source served.
#[test]
fn produced_feed_verifies_end_to_end() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let source = fake_source();
    let feed = produce_feed(&config(), &source, Channel::Stable, GENERATED, &signing_key)
        .expect("feed produced");

    // Parse the produced envelopes exactly as the beacon does (over the received bytes).
    let delegation = SignedDelegation::from_json(&feed.delegation_json).expect("delegation parses");
    let manifest = SignedManifest::from_json(&feed.manifest_json).expect("manifest parses");

    // The full trust chain verifies under the (throwaway) root key: delegation signature +
    // expiry, manifest signature, root_version binding, freshness, and the rollback floor.
    let now = GENERATED + 60;
    verify_update_chain(
        &signing_key.verifying_key(),
        &TrustState::initial(),
        &delegation,
        &manifest,
        now,
    )
    .expect("the whole trust chain must verify the signer's output");

    // Every artifact's signed digest matches the exact bytes the source served — the digest gate
    // the beacon runs before install.
    for component in &manifest.manifest.components {
        for artifact in &component.artifacts {
            let bytes = source.download(&artifact.url).unwrap();
            verify_artifact_digest(artifact, &bytes)
                .unwrap_or_else(|e| panic!("digest for {} must match: {e}", artifact.url));
        }
    }
}

/// The delegation binds the manifest: both carry the same `root_version`, and the manifest is
/// signed by the key the delegation names.
#[test]
fn delegation_names_the_signing_key_as_targets() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    let delegation = SignedDelegation::from_json(&feed.delegation_json).unwrap();

    let expected_targets =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
    assert_eq!(delegation.delegation.targets_pubkey, expected_targets);
    assert_eq!(delegation.delegation.root_version, 1);
}

/// The manifest carries the resolved versions + packed build numbers, and `sequence`/`generated`
/// equal the supplied timestamp (SPEC §10).
#[test]
fn manifest_reflects_resolved_builds_and_timestamp() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    let manifest = SignedManifest::from_json(&feed.manifest_json)
        .unwrap()
        .manifest;

    assert_eq!(manifest.sequence, GENERATED);
    assert_eq!(manifest.generated, GENERATED);
    assert_eq!(manifest.expires, GENERATED + 12 * 60 * 60);

    let dig_node = manifest.component("dig-node").expect("dig-node present");
    assert_eq!(dig_node.version, "0.29.0");
    assert_eq!(dig_node.build, 29_000);
    // The `.tar.gz` sibling is excluded; only the two platform binaries are artifacts.
    assert_eq!(dig_node.artifacts.len(), 2);

    let digstore = manifest.component("digstore").expect("digstore present");
    assert_eq!(digstore.build, 13_001);
    assert_eq!(digstore.artifacts.len(), 1);
}

/// The NIGHTLY channel resolves the rolling `nightly` release, records the FULL prerelease version
/// string (so the beacon compares against the real installed nightly, #591 D5 point 5), and uses
/// the UTC build DATE `YYYYMMDD` as the anti-downgrade build — and the whole chain still verifies.
#[test]
fn nightly_feed_resolves_the_rolling_release_and_dates_the_build() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let source = fake_source();
    let feed = produce_feed(
        &config(),
        &source,
        Channel::Nightly,
        GENERATED,
        &signing_key,
    )
    .expect("nightly feed produced");

    // The full trust chain verifies exactly like the stable feed — one key signs both channels.
    let delegation = SignedDelegation::from_json(&feed.delegation_json).unwrap();
    let manifest = SignedManifest::from_json(&feed.manifest_json).unwrap();
    verify_update_chain(
        &signing_key.verifying_key(),
        &TrustState::initial(),
        &delegation,
        &manifest,
        GENERATED + 60,
    )
    .expect("the nightly trust chain must verify");

    let dig_node = manifest
        .manifest
        .component("dig-node")
        .expect("dig-node present");
    assert_eq!(dig_node.version, "0.30.0-nightly.20260714.abc1234");
    assert_eq!(dig_node.build, 20_260_714, "build is the UTC date YYYYMMDD");
    assert_eq!(dig_node.artifacts.len(), 2);

    let digstore = manifest
        .manifest
        .component("digstore")
        .expect("digstore present");
    assert_eq!(digstore.version, "0.14.0-nightly.20260714.abc1234");
    assert_eq!(digstore.build, 20_260_714);
}

/// Per-channel INDEPENDENCE: signing the SAME source on the two channels yields two DIFFERENT feeds
/// — different resolved versions and different build scales (packed semver vs YYYYMMDD) — so each
/// channel is a distinct signed feed. Their freshness marks (`sequence`/`generated`) coincide only
/// because the same `generated` timestamp is supplied to both in one run.
#[test]
fn the_two_channels_produce_independent_feeds() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let source = fake_source();

    let stable =
        produce_feed(&config(), &source, Channel::Stable, GENERATED, &signing_key).unwrap();
    let nightly = produce_feed(
        &config(),
        &source,
        Channel::Nightly,
        GENERATED,
        &signing_key,
    )
    .unwrap();

    // Two genuinely different signed manifests, not a shared envelope.
    assert_ne!(stable.manifest_json, nightly.manifest_json);

    let stable_node = SignedManifest::from_json(&stable.manifest_json)
        .unwrap()
        .manifest
        .component("dig-node")
        .unwrap()
        .clone();
    let nightly_node = SignedManifest::from_json(&nightly.manifest_json)
        .unwrap()
        .manifest
        .component("dig-node")
        .unwrap()
        .clone();

    assert_eq!(stable_node.version, "0.29.0");
    assert_eq!(stable_node.build, 29_000);
    assert_eq!(nightly_node.version, "0.30.0-nightly.20260714.abc1234");
    assert_eq!(nightly_node.build, 20_260_714);
    // The two build scales never overlap: a stable build is thousands, a nightly build is tens of
    // millions — so cross-channel comparison is meaningless by construction (#591 D5).
    assert!(nightly_node.build > stable_node.build);
}

/// Byte-exact + deterministic: the same inputs produce identical feed bytes (the property that
/// lets the feed be served byte-for-byte as signed — SPEC §10 no-transform requirement).
#[test]
fn feed_is_byte_identical_across_runs() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let a = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    let b = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    assert_eq!(a.delegation_json, b.delegation_json);
    assert_eq!(a.manifest_json, b.manifest_json);
}

/// The per-artifact digests reported for the summary equal the SHA-256 of the served bytes.
#[test]
fn reported_digests_match_bytes() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let source = fake_source();
    let feed = produce_feed(&config(), &source, Channel::Stable, GENERATED, &signing_key).unwrap();

    assert_eq!(feed.digests.len(), 3); // 2 dig-node + 1 digstore
    for d in &feed.digests {
        // Find the URL for this digest by matching the manifest, then re-hash the served bytes.
        let manifest = SignedManifest::from_json(&feed.manifest_json)
            .unwrap()
            .manifest;
        let artifact = manifest
            .component(&d.component)
            .and_then(|c| c.artifact(&d.os, &d.arch))
            .expect("artifact present");
        let bytes = source.download(&artifact.url).unwrap();
        assert_eq!(d.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(d.size, bytes.len() as u64);
    }
}

/// A component whose release has no matching platform assets fails the whole run closed.
#[test]
fn missing_component_assets_fail_closed() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let mut source = fake_source();
    source.releases.insert(
        ("DIG-Network/dig-node".to_string(), Channel::Stable),
        r#"{"tag_name":"v0.29.0","assets":[{"name":"unrelated.zip","browser_download_url":"https://dl.test/x"}]}"#.to_string(),
    );
    assert!(matches!(
        produce_feed(&config(), &source, Channel::Stable, GENERATED, &signing_key),
        Err(FeedsignError::NoArtifacts { .. })
    ));
}

/// `write_to` emits the two feed objects byte-for-byte as produced, at the expected names — the
/// files the workflow serves + publishes.
#[test]
fn writes_both_feed_files_verbatim() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();

    let dir = tempfile::TempDir::new().unwrap();
    feed.write_to(dir.path()).unwrap();

    let delegation = std::fs::read_to_string(dir.path().join("delegation.json")).unwrap();
    let manifest = std::fs::read_to_string(dir.path().join("manifest.json")).unwrap();
    assert_eq!(delegation, feed.delegation_json);
    assert_eq!(manifest, feed.manifest_json);
}

/// The job summary reports the sequence + every component/digest and carries no key material.
#[test]
fn summary_is_informative_and_secret_free() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();

    let summary = feed.summary();
    assert!(summary.contains(&format!("sequence={GENERATED}")));
    assert!(summary.contains("dig-node 0.29.0"));
    assert!(summary.contains("digstore 0.13.1"));
    // The private seed bytes must never surface in the summary.
    let seed_b64 = base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());
    assert!(!summary.contains(&seed_b64));
}

/// The transparency record derives, from the produced feed alone, the exact bytes the targets key
/// signed — and the detached signature over them verifies under the recorded targets public key.
/// This is what a public transparency log (Rekor, #533) records so any observer can later prove
/// this manifest was publicly logged.
#[test]
fn transparency_record_signature_verifies_over_signed_bytes() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    let record = feed
        .transparency()
        .expect("transparency derives from a produced feed");

    // The signed bytes are the manifest payload EXACTLY as it will be served (the crate's
    // canonicalization, reused — not a re-serialization).
    let manifest = SignedManifest::from_json(&feed.manifest_json).unwrap();
    assert_eq!(record.signing_bytes, manifest.signed_payload());

    // The recorded public key is the targets key, and the detached 64-byte signature verifies
    // over the signed bytes under it — the property a transparency log entry attests.
    assert_eq!(
        record.targets_pubkey,
        signing_key.verifying_key().to_bytes()
    );
    assert_eq!(record.signature.len(), 64);
    let vk = VerifyingKey::from_bytes(&record.targets_pubkey).unwrap();
    let sig = Signature::from_slice(&record.signature).unwrap();
    vk.verify(&record.signing_bytes, &sig)
        .expect("the detached targets signature must verify over the signed bytes");
}

/// The targets public key is emitted as a standard Ed25519 SubjectPublicKeyInfo PEM (RFC 8410),
/// so `rekor-cli --pki-format=x509 --public-key` accepts it: a 12-byte SPKI prefix + the raw
/// 32-byte key, base64-wrapped between the PUBLIC KEY armor.
#[test]
fn transparency_pubkey_is_spki_ed25519_pem() {
    // The fixed DER prefix of an Ed25519 SPKI: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }.
    const SPKI_ED25519_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    let record = feed.transparency().unwrap();

    let pem = record.targets_pubkey_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));

    // The DER between the armor is the SPKI prefix followed by the raw 32-byte key.
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("PEM body is base64");
    let mut expected = SPKI_ED25519_PREFIX.to_vec();
    expected.extend_from_slice(&signing_key.verifying_key().to_bytes());
    assert_eq!(der, expected);
}

/// `write_transparency_to` emits the triple — signed bytes, detached signature, and PEM public key
/// — byte-for-byte as derived, at the names the workflow feeds to `rekor-cli`.
#[test]
fn write_transparency_emits_the_triple() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let feed = produce_feed(
        &config(),
        &fake_source(),
        Channel::Stable,
        GENERATED,
        &signing_key,
    )
    .unwrap();
    let record = feed.transparency().unwrap();

    let dir = tempfile::TempDir::new().unwrap();
    record.write_to(dir.path()).unwrap();

    assert_eq!(
        std::fs::read(dir.path().join(SIGNING_BYTES_FILE)).unwrap(),
        record.signing_bytes
    );
    assert_eq!(
        std::fs::read(dir.path().join(SIGNATURE_FILE)).unwrap(),
        record.signature
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(TARGETS_PUBKEY_FILE)).unwrap(),
        record.targets_pubkey_pem()
    );
}

/// A LIVE smoke test against the real GitHub API + release assets, signing with a THROWAWAY key
/// (so no secret is needed) and verifying the produced feed under that same key. `#[ignore]`d so
/// the offline gate never depends on the network; run locally with
/// `cargo test -p dig-updater-feedsign --test end_to_end -- --ignored --nocapture` to confirm the
/// real resolution → download → assemble → sign → verify path works end-to-end against live
/// releases. Uses only `dig-updater` (a small binary) to stay fast.
#[test]
#[ignore = "hits the live GitHub API; run manually with --ignored"]
fn live_github_resolution_smoke() {
    let config = FeedConfig::from_json(
        r#"{ "components": [
            { "name": "dig-updater", "repo": "DIG-Network/dig-updater", "asset_prefix": "dig-updater" }
        ] }"#,
    )
    .unwrap();
    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let source = GithubSource::github(token);
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);

    let feed = produce_feed(&config, &source, Channel::Stable, GENERATED, &signing_key)
        .expect("live feed produced");

    let delegation = SignedDelegation::from_json(&feed.delegation_json).unwrap();
    let manifest = SignedManifest::from_json(&feed.manifest_json).unwrap();
    verify_update_chain(
        &signing_key.verifying_key(),
        &TrustState::initial(),
        &delegation,
        &manifest,
        GENERATED + 60,
    )
    .expect("the live-resolved, signed feed must verify");
    assert!(
        !manifest.manifest.components[0].artifacts.is_empty(),
        "at least one real artifact must resolve"
    );
    println!("{}", feed.summary());
}
