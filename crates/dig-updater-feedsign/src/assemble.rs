//! Assembling the signed feed's payloads from resolved components + the run's timestamp.
//!
//! This is the deterministic core: given the per-component builds (already resolved + digested)
//! and the single `generated` timestamp the workflow supplies, it produces the exact [`Manifest`]
//! and [`Delegation`] payloads. It calls no clock and does no I/O, so the same inputs always yield
//! byte-identical output — the property the feed's byte-exact serving requirement (SPEC §10)
//! depends on.

use dig_updater_trust::{Component, Delegation, Manifest};

use crate::config::FeedConfig;

/// Build the update [`Manifest`] for this run of one channel.
///
/// `sequence` and `generated` are both set to the supplied `generated` timestamp (SPEC §10): the
/// 6-hour signing cadence makes the unix timestamp a naturally monotonic per-run counter, so it
/// serves as the anti-rollback `sequence` and the anti-freeze `generated` high-water-mark at once.
/// The `rollback_floor_build` is the PER-CHANNEL floor the caller resolved from the config
/// ([`FeedConfig::floor_for`]) — passed in rather than read from `config` because it differs per
/// channel and is on a channel-specific build scale (SPEC §7.6, #591 D5).
#[must_use]
pub fn assemble_manifest(
    config: &FeedConfig,
    rollback_floor_build: u64,
    generated: u64,
    components: Vec<Component>,
) -> Manifest {
    Manifest {
        schema: config.schema,
        root_version: config.root_version,
        sequence: generated,
        generated,
        expires: generated.saturating_add(config.manifest_ttl_secs),
        rollback_floor_build,
        components,
    }
}

/// Build the root→targets [`Delegation`] for this run.
///
/// In the alpha floor root and targets are the same key (SPEC §4.3), so `targets_pubkey` is the
/// pinned root key itself; the delegation still exists on the wire so the beacon walks the full
/// production verification path from day one.
#[must_use]
pub fn assemble_delegation(
    config: &FeedConfig,
    generated: u64,
    targets_pubkey_b64: String,
) -> Delegation {
    Delegation {
        root_version: config.root_version,
        targets_pubkey: targets_pubkey_b64,
        expires: generated.saturating_add(config.delegation_ttl_secs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_updater_trust::Artifact;

    fn config() -> FeedConfig {
        FeedConfig::from_json(
            r#"{
                "schema": 1,
                "root_version": 1,
                "manifest_ttl_secs": 43200,
                "delegation_ttl_secs": 2592000,
                "components": [
                    { "name": "dig-node", "repo": "DIG-Network/dig-node", "asset_prefix": "dig-node" }
                ]
            }"#,
        )
        .unwrap()
    }

    fn component() -> Component {
        Component {
            name: "dig-node".into(),
            version: "0.29.0".into(),
            build: 29_000,
            artifacts: vec![Artifact {
                os: "linux".into(),
                arch: "x64".into(),
                url: "https://example.test/dig-node-0.29.0-linux-x64".into(),
                sha256: "ab".repeat(32),
                size: 100,
            }],
        }
    }

    #[test]
    fn manifest_uses_generated_for_sequence_and_expiry() {
        let m = assemble_manifest(&config(), 7, 1_000_000, vec![component()]);
        assert_eq!(m.schema, 1);
        assert_eq!(m.root_version, 1);
        assert_eq!(m.sequence, 1_000_000);
        assert_eq!(m.generated, 1_000_000);
        assert_eq!(m.expires, 1_000_000 + 43_200);
        // The floor is the PER-CHANNEL value the caller resolved, not a config-wide field.
        assert_eq!(m.rollback_floor_build, 7);
        assert_eq!(m.components.len(), 1);
    }

    #[test]
    fn manifest_expiry_saturates_rather_than_overflowing() {
        let m = assemble_manifest(&config(), 0, u64::MAX, vec![component()]);
        assert_eq!(m.expires, u64::MAX);
    }

    #[test]
    fn delegation_carries_targets_key_and_thirty_day_expiry() {
        let d = assemble_delegation(&config(), 1_000_000, "the-targets-key".into());
        assert_eq!(d.root_version, 1);
        assert_eq!(d.targets_pubkey, "the-targets-key");
        assert_eq!(d.expires, 1_000_000 + 2_592_000);
    }
}
