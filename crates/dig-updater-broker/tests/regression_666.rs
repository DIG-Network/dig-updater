//! Regression tests for #666 — "beacon reports updates Installed but they don't fully apply".
//!
//! Two independent defects, each pinned to a failing assertion below. These are RED against the
//! current code (which models a component as a single `dest` with no alias/service awareness) and
//! turn GREEN only once the apply/replace path is fixed to (A) enumerate + replace + health-check
//! the FULL binary set of a component — its primary AND its byte-identical aliases — and (B) stop a
//! running service before replacing its binary so the post-install probe reads the NEW on-disk code.
//!
//! Canonical alias contract (`.claude/skills/canonical`, SYSTEM.md): `digs ≡ digstore`,
//! `digd ≡ dig-dns`, `dign ≡ dig-node` — byte-identical, shipped together as their own release
//! assets (dig-dns v0.14.0 ships `digd-0.14.0-<platform>` for all four platforms).

use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

use dig_updater_broker::install::{
    install_from_private, private_target, InstallOutcome, RetryPolicy,
};
use dig_updater_broker::plan::{Catalog, InstallMethod, PlannedComponent};
use dig_updater_worker::Platform;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn linux() -> Platform {
    Platform {
        os: "linux".into(),
        arch: "x64".into(),
    }
}

// ---------------------------------------------------------------------------------------------
// Bug A — the alias binary (digd/digs/dign) is never updated, yet the pass reports "Installed".
// ---------------------------------------------------------------------------------------------

/// The install catalog must know that `dig-dns` is TWO on-disk binaries — the primary `dig-dns`
/// and its byte-identical alias `digd` — so the applier can replace + health-check both. Today the
/// catalog exposes only `dest`, so `digd` is invisible to the beacon and silently left at the
/// install-time version while `dig-dns` advances (the exact #666 Bug A symptom: `dig-dns 0.14.0`
/// but `digd --version` → 0.13.2).
#[test]
fn dig_dns_component_enumerates_its_digd_alias_666a() {
    let cat = Catalog::alpha_defaults(&linux());
    let target = cat
        .target("dig-dns")
        .expect("dig-dns is a tracked component");

    // The full set of binaries this component owns on disk — primary first, then every alias.
    let binaries: Vec<PathBuf> = target
        .binaries()
        .map(std::path::Path::to_path_buf)
        .collect();

    let bin_dir = target.dest.parent().expect("dest has a parent bin dir");
    assert!(
        binaries.contains(&target.dest),
        "the primary dig-dns binary must be in the set"
    );
    assert!(
        binaries.contains(&bin_dir.join("digd")),
        "#666 Bug A: the byte-identical alias `digd` MUST be part of the dig-dns binary set so the \
         beacon replaces + version-checks it; today it is invisible and left stale"
    );
}

/// Applying a raw-binary component must refresh EVERY binary in its set (primary + aliases) with the
/// verified bytes. Today `install_from_private` renames only `pc.dest`, so a byte-identical alias is
/// never touched — `dig-dns` gets the new bytes and `digd` keeps the old ones.
#[test]
fn applying_dig_dns_also_refreshes_its_digd_alias_666a() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    let primary = bin.join("dig-dns");
    let alias = bin.join("digd");
    std::fs::write(&primary, b"old-dig-dns-0.13.2").unwrap();
    std::fs::write(&alias, b"old-dig-dns-0.13.2").unwrap();

    let new_bytes = b"new-dig-dns-0.14.0-bytes";
    let pc = PlannedComponent {
        name: "dig-dns".into(),
        method: InstallMethod::RawBinary,
        dest: primary.clone(),
        // Intended new field: the byte-identical alias destinations shipped alongside the primary.
        aliases: vec![alias.clone()],
        version: "0.14.0".into(),
        build: 14_000,
        expected_digest: hex(&Sha256::digest(new_bytes)),
        staged_path: PathBuf::new(),
        action: dig_release_resolver::UpdateAction::Update,
        summary: String::new(),
        installed_build: Some(13_002),
    };

    let private = private_target(&pc, dir.path());
    std::fs::write(&private, new_bytes).unwrap();

    let outcome = install_from_private(
        &pc,
        &private,
        &RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        },
    );
    assert_eq!(outcome, InstallOutcome::Installed);
    assert_eq!(
        std::fs::read(&primary).unwrap(),
        new_bytes,
        "primary updated"
    );
    assert_eq!(
        std::fs::read(&alias).unwrap(),
        new_bytes,
        "#666 Bug A: the alias `digd` MUST be refreshed to the new bytes in the same pass, not \
         left at the install-time version"
    );
}

// ---------------------------------------------------------------------------------------------
// Bug B — a running-service component (dig-node) can never self-update: its binary is file-locked
// while the service runs, the install "succeeds" but the on-disk file is not swapped in-pass, and
// the post-install `--version` probe reads the still-old binary → health gate rolls it back.
// ---------------------------------------------------------------------------------------------

/// dig-node runs as the OS service `net.dignetwork.dig-node`; its executable is held open while the
/// service runs. For the apply to actually land (and for the post-install probe to read the NEW
/// version), the applier must know the component is service-backed so it can stop → replace →
/// restart it. Today the catalog carries no service identity, so nothing stops the service and the
/// locked binary is never swapped within the pass.
#[test]
fn dig_node_declares_its_managed_service_for_stop_replace_restart_666b() {
    let cat = Catalog::alpha_defaults(&linux());
    let target = cat
        .target("dig-node")
        .expect("dig-node is a tracked component");

    assert_eq!(
        target.service_id(),
        Some("net.dignetwork.dig-node"),
        "#666 Bug B: dig-node is a running service; the applier must know to stop it before \
         replacing its file-locked binary and restart it after, so the health probe reads the new \
         version instead of the still-running old one"
    );
}

/// A running/locked target that has been stopped must actually be REPLACED (not deferred) so the
/// post-install version probe — which reads the binary on disk — sees the new bytes. This models
/// the dig-node symptom directly: with the current path a service-backed component's install leaves
/// the old bytes in place, so `check_health` reads v0.32.0 and rolls back. After the fix the
/// service is stopped (releasing the lock) and the resilient move-aside replace lands the new bytes.
#[cfg(unix)]
#[test]
fn a_service_backed_replace_lands_new_bytes_on_disk_before_health_666b() {
    use dig_release_resolver::DetectedVersion;
    use dig_updater_broker::health::check_health;
    use dig_updater_broker::plan::ComponentTarget;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let dest = bin.join("dig-node");
    std::fs::write(&dest, b"dig-node-0.32.0").unwrap();

    let new_bytes = b"dig-node-0.33.0-new";
    let target = ComponentTarget {
        name: "dig-node".into(),
        method: InstallMethod::RawBinary,
        dest: dest.clone(),
        aliases: vec![],
        // Intended new field: the service this component's binary belongs to.
        service: Some("net.dignetwork.dig-node".to_string()),
    };

    let pc = PlannedComponent {
        name: "dig-node".into(),
        method: target.method,
        dest: target.dest.clone(),
        aliases: target.aliases.clone(),
        version: "0.33.0".into(),
        build: 33_000,
        expected_digest: hex(&Sha256::digest(new_bytes)),
        staged_path: PathBuf::new(),
        action: dig_release_resolver::UpdateAction::Update,
        summary: String::new(),
        installed_build: Some(32_000),
    };

    let private = private_target(&pc, dir.path());
    std::fs::write(&private, new_bytes).unwrap();

    let outcome = install_from_private(
        &pc,
        &private,
        &RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        },
    );
    assert_eq!(
        outcome,
        InstallOutcome::Installed,
        "#666 Bug B: a stopped service's binary must be replaced, not deferred"
    );

    // The health probe reads the binary ON DISK. After a real replace it must be the new version.
    let probe =
        |p: &std::path::Path| DetectedVersion::Present(format!("dig-node {}", contents_version(p)));
    let observed = check_health(&dest, "0.33.0", &probe)
        .expect("#666 Bug B: post-install probe must see the newly-written 0.33.0 binary");
    assert!(matches!(observed, DetectedVersion::Present(_)));
    assert_eq!(std::fs::read(&dest).unwrap(), new_bytes);
}

#[cfg(unix)]
fn contents_version(p: &std::path::Path) -> String {
    let bytes = std::fs::read(p).unwrap_or_default();
    if bytes.starts_with(b"dig-node-0.33.0") {
        "0.33.0".into()
    } else {
        "0.32.0".into()
    }
}
