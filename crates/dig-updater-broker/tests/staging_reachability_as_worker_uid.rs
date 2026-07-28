//! The end of the #1747 proof chain: drop to the real worker uid with `setpriv` and WRITE into the
//! staging directory the broker just prepared — the exact procedure that exposed the defect on a
//! fresh Ubuntu 24.04 install.
//!
//! The structural checks in `staging_reachability.rs` reason about modes; this one asks the kernel.
//! It needs root (only root can chown staging to the worker identity and then shed privilege), so
//! off a root runner it reports itself SKIPPED rather than pretending to have proven anything. Set
//! `DIG_UPDATER_REQUIRE_ROOT_PROOF=1` to turn that skip into a failure — an e2e or nightly runner
//! that believes it is root uses it to prove this test actually executed.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use dig_updater_broker::sandbox::{prepare_worker_writable_dir, Sandbox};
use dig_updater_broker::secure::harden_state_dir;
use dig_updater_broker::Broker;

/// The environment variable that forbids this test from skipping.
const REQUIRE_ROOT_PROOF: &str = "DIG_UPDATER_REQUIRE_ROOT_PROOF";

/// The conventional `nobody` uid/gid the broker drops the worker to.
const NOBODY: &str = "65534";

#[test]
fn the_dropped_worker_uid_can_write_into_the_staging_dir_the_broker_prepared() {
    let Some(reason) = unavailable_reason() else {
        return prove_the_worker_uid_can_write();
    };
    assert!(
        std::env::var_os(REQUIRE_ROOT_PROOF).is_none(),
        "{REQUIRE_ROOT_PROOF} demands the real privilege-dropped proof, but it cannot run: {reason}"
    );
    eprintln!("SKIPPED (the real privilege-dropped proof needs {reason})");
}

/// Why the privilege-dropped proof cannot run here, or `None` when it can.
fn unavailable_reason() -> Option<&'static str> {
    if !running_as_root() {
        return Some(
            "root: only root can chown staging to the worker identity and then drop to it",
        );
    }
    if !setpriv_available() {
        return Some("`setpriv` (util-linux), the tool that sheds privilege for the probe");
    }
    None
}

/// Build a real install layout, prepare staging exactly as a production pass does, then write into
/// it as the unprivileged worker identity.
fn prove_the_worker_uid_can_write() {
    let root = tempfile::tempdir().expect("temp root");
    relax_to_world_traversable(root.path()); // stands in for `/var/lib`

    let state_dir = root.path().join("dig-updater");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    harden_state_dir(&state_dir).expect("harden the state dir");

    let broker = Broker::with_paths(state_dir, root.path().join("dig-updater-worker"));
    let staging = broker.staging_dir();
    // `Restricted` is the production posture: as root this chowns staging to the worker identity.
    prepare_worker_writable_dir(&staging, Sandbox::Restricted).expect("prepare staging");

    let probe = staging.join("probe");
    let output = Command::new("setpriv")
        .args([
            &format!("--reuid={NOBODY}"),
            &format!("--regid={NOBODY}"),
            "--clear-groups",
            "sh",
            "-c",
        ])
        .arg(format!("touch {}", probe.display()))
        .output()
        .expect("run setpriv");

    assert!(
        output.status.success(),
        "the worker identity could not write into its own staging dir {}: {}",
        staging.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    assert!(
        probe.is_file(),
        "the probe file the worker wrote is missing"
    );
}

fn running_as_root() -> bool {
    // `id -u` avoids pulling `libc` into the test target just to read a uid.
    Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}

fn setpriv_available() -> bool {
    Command::new("setpriv")
        .arg("--help")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Give the stand-in for `/var/lib` the `0755` mode it really has (`tempfile` creates `0700`).
fn relax_to_world_traversable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
        .expect("relax the temp root to 0755");
}
