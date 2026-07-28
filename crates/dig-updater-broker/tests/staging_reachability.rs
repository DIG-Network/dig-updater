//! The staging directory must be REACHABLE by the privilege-dropped worker that owns it (#1747).
//!
//! On a real install the beacon created `/var/lib/dig-updater/staging`, chowned it to `nobody`, and
//! then could never use it: the parent `/var/lib/dig-updater` is `0700 root`, and entering a
//! directory requires the traverse right on every component above it. Every pass — real and dry —
//! returned `staging_io_error: Permission denied (os error 13)`, and the persisted trust state had
//! never left `root_version: 0`. Nothing about the staging directory's OWN mode or ownership was
//! wrong, which is why a test asserting that the directories exist, or that they are `0700` and
//! worker-owned, passed against the defect. These tests assert TRAVERSABILITY instead.

use std::path::Path;

#[cfg(unix)]
use dig_updater_broker::sandbox::{prepare_worker_writable_dir, Sandbox};
#[cfg(unix)]
use dig_updater_broker::secure::{first_untraversable_ancestor, harden_state_dir};
use dig_updater_broker::Broker;

/// A hardened state directory beneath a world-traversable root, mirroring a real install:
/// `<root>` stands in for `/var/lib` (mode `0755`) and `<root>/dig-updater` for the `0700` state
/// directory. Returns `(root, broker)`.
#[cfg(unix)]
fn install_layout() -> (tempfile::TempDir, Broker) {
    let root = tempfile::tempdir().expect("temp root");
    make_world_traversable(root.path());

    let state_dir = root.path().join("dig-updater");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    harden_state_dir(&state_dir).expect("harden the state dir");

    let broker = Broker::with_paths(state_dir, root.path().join("dig-updater-worker"));
    (root, broker)
}

/// Give `dir` the `0755` mode `/var/lib` really has. `tempfile` creates its directories `0700`,
/// which would otherwise make the boundary of every traversal walk look like a blocker — an
/// artifact of the harness, not of the layout under test.
#[cfg(unix)]
fn make_world_traversable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
        .expect("relax the temp root to 0755");
}

// Traversal rights are a Unix mode-word property, and the #1747 defect is a Unix one: on Windows
// reachability is governed by the DACL `harden_state_dir` applies, whose alpha-floor posture is
// documented on `secure::classify_writability`. Rather than let these read as passing there, they
// compile only where they can actually assert something.
#[cfg(unix)]
#[test]
fn the_staging_dir_is_reachable_by_the_worker_identity_where_a_nested_one_would_not_be() {
    let (root, broker) = install_layout();
    let staging = broker.staging_dir();
    prepare_worker_writable_dir(&staging, Sandbox::Inherit).expect("prepare staging");

    // The property under test: nothing between the filesystem root and the staging directory
    // withholds traverse from an identity that is neither owner nor group — so the worker the
    // beacon drops to `nobody` can enter the directory the beacon chowned to it.
    assert_eq!(
        first_untraversable_ancestor(&staging, root.path()),
        None,
        "every ancestor of {} must be traversable by the worker identity",
        staging.display()
    );

    // The truthful control, and what makes the assertion above load-bearing rather than vacuous:
    // the SHIPPED layout — staging nested inside the hardened state dir — is detected as blocked,
    // by the same predicate, in the same harness. Without this, a predicate that always answered
    // `None` (e.g. one reading the wrong mode bit) would satisfy the test above.
    let nested_staging = broker.state_dir().join("staging");
    assert_eq!(
        first_untraversable_ancestor(&nested_staging, root.path()),
        Some(broker.state_dir().to_path_buf()),
        "a staging dir nested inside the hardened state dir must be reported unreachable"
    );
}

#[cfg(unix)]
#[test]
fn making_staging_reachable_did_not_widen_the_state_dir() {
    // The `0700` on the state dir is not incidental: the persisted per-channel trust state holds
    // the anti-rollback high-water marks, and `config.json` holds the channel + pause posture. It
    // is also the ONLY barrier protecting them — those files are written with the process umask,
    // not an explicit restrictive mode — so granting the state dir `o+x` (the other obvious fix for
    // #1747) would let any local identity open the trust state BY NAME and read, and with a lax
    // umask rewrite, the beacon's anti-rollback memory. This pins that the reachability fix bought
    // nothing at the state dir's expense.
    let (_root, broker) = install_layout();
    prepare_worker_writable_dir(&broker.staging_dir(), Sandbox::Inherit).expect("prepare staging");

    assert_grants_nothing_to_other(broker.state_dir());
}

#[cfg(unix)]
#[test]
fn the_staging_dir_itself_stays_closed_to_unrelated_identities() {
    // Reachable is not the same as open. Staging holds the artifacts the broker is about to hash
    // and install, so a third local identity must not be able to swap them (SPEC §8.3) — the whole
    // reason staging is not `/tmp`. Only its owner (the worker) and root may enter it.
    let (_root, broker) = install_layout();
    let staging = broker.staging_dir();
    prepare_worker_writable_dir(&staging, Sandbox::Inherit).expect("prepare staging");

    assert_grants_nothing_to_other(&staging);
}

/// Assert `dir` grants an unrelated identity no right at all — read, write, or traverse.
#[cfg(unix)]
fn assert_grants_nothing_to_other(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir)
        .expect("stat the directory")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o007,
        0,
        "{} must grant nothing to other identities, got mode {:o}",
        dir.display(),
        mode
    );
}

#[test]
fn staging_is_a_sibling_of_the_state_dir_and_never_under_tmp() {
    // Placement, stated once: beside the state dir (so it is reachable) and NOT in shared `/tmp`
    // (so its bytes are not swappable by any local user, SPEC §8.3, #504-E).
    let broker = Broker::with_paths(
        Path::new("/var/lib/dig-updater").to_path_buf(),
        Path::new("worker").to_path_buf(),
    );
    assert_eq!(
        broker.staging_dir(),
        Path::new("/var/lib/dig-updater-staging")
    );
    assert!(!broker.staging_dir().starts_with(std::env::temp_dir()));
}
