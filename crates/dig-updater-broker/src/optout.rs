//! The Admin/SYSTEM-only "schedule opt-out" sentinel — the deliberate-vs-accidental guard for the
//! daily-schedule self-heal (#584).
//!
//! The self-heal ([`crate::scheduler::ensure`]) and the always-on re-arm driver (dig-node, a
//! follow-on) both re-register a provably-absent daily schedule so a beacon whose task was DELETED
//! resurrects its own wake. But a user who ran `dig-updater schedule uninstall` removed the schedule
//! ON PURPOSE — an always-on driver that blindly re-armed it would fight that deliberate choice
//! forever. This sentinel distinguishes the two: `schedule uninstall` WRITES it, `schedule install`
//! CLEARS it, and `ensure` short-circuits to [`crate::scheduler::EnsureAction::SuppressedByOptOut`]
//! while it is present.
//!
//! ## Security: the marker MUST be un-forgeable, so it lives in the Admin-only state dir
//!
//! Suppressing auto-updates is an attack surface — a stale-pin/downgrade vector — so a
//! non-privileged process must not be able to FORGE the marker to silence the beacon. The sentinel
//! is written INTO the beacon's Admin/SYSTEM-only state directory
//! ([`crate::paths::default_state_dir`], DACL'd Admin+SYSTEM on Windows / root `0700` on Unix) and
//! is itself re-hardened to Admin/SYSTEM-only ([`crate::secure::harden_state_dir`]) after every
//! write, so only a privileged identity can create it.
//!
//! ## Fail-OPEN toward availability
//!
//! [`is_opted_out`] answers `true` ONLY for a marker that provably EXISTS. A missing marker — or an
//! ambiguous/unreadable one (e.g. a `try_exists` that errors) — answers `false` (NOT opted out =
//! re-arm). Auto-updates staying alive is the safe failure: only a present, Admin-owned marker (one
//! a non-admin could never have planted) suppresses the self-heal.

use std::path::{Path, PathBuf};

use crate::error::BrokerError;
use crate::secure::harden_state_dir;

/// The file name of the opt-out sentinel within the beacon state directory.
const OPTOUT_MARKER_NAME: &str = "schedule-optout";

/// The human-readable note written INTO the marker. Its CONTENTS carry no trust — the marker's mere
/// presence (in the Admin-only state dir) is the entire signal; this text only helps an operator who
/// stumbles on the file understand why it exists.
const OPTOUT_MARKER_NOTE: &str = "\
This file records that the DIG auto-update daily schedule was DELIBERATELY removed via
`dig-updater schedule uninstall`. While it exists, `dig-updater schedule ensure` (and the
always-on re-arm driver) will NOT re-register the schedule. Run `dig-updater schedule install`
to re-enable auto-updates (which clears this file).
";

/// The path of the opt-out sentinel within `state_dir`.
#[must_use]
pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(OPTOUT_MARKER_NAME)
}

/// Whether the operator has DELIBERATELY opted out of the daily schedule (a `schedule uninstall`
/// wrote the sentinel into the Admin-only `state_dir`).
///
/// FAIL-OPEN: only a marker that provably EXISTS answers `true`; a missing OR unreadable/ambiguous
/// marker answers `false` (re-arm). See the module doc for why availability is the safe failure.
#[must_use]
pub fn is_opted_out(state_dir: &Path) -> bool {
    marker_path(state_dir).try_exists().unwrap_or(false)
}

/// Record a DELIBERATE opt-out: write the sentinel into `state_dir` and harden it Admin/SYSTEM-only.
///
/// Idempotent — re-writing an already-present marker succeeds. The state directory is created if
/// missing (it is the Admin-only default in production), so `schedule uninstall` sets the opt-out
/// even on a machine where a pass never created the state dir.
///
/// # Errors
///
/// [`BrokerError::Io`] if the state dir cannot be created, the marker cannot be written, or its
/// Admin/SYSTEM-only ACL cannot be applied (fail-closed — an un-hardenable marker would be
/// forgeable, so writing it must not silently "succeed" un-hardened).
pub fn set_opted_out(state_dir: &Path) -> Result<(), BrokerError> {
    std::fs::create_dir_all(state_dir).map_err(|e| BrokerError::Io(e.to_string()))?;
    let path = marker_path(state_dir);
    std::fs::write(&path, OPTOUT_MARKER_NOTE).map_err(|e| BrokerError::Io(e.to_string()))?;
    harden_state_dir(&path)
}

/// Clear a previous opt-out (a `schedule install` re-enables auto-updates).
///
/// Idempotent: clearing an already-absent marker is success, not an error.
///
/// # Errors
///
/// [`BrokerError::Io`] if the marker exists but could not be removed.
pub fn clear_opted_out(state_dir: &Path) -> Result<(), BrokerError> {
    match std::fs::remove_file(marker_path(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BrokerError::Io(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_state_dir_is_not_opted_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            !is_opted_out(dir.path()),
            "no marker present => not opted out => re-arm"
        );
    }

    #[test]
    fn set_then_is_opted_out_then_clear_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        set_opted_out(dir.path()).expect("write the opt-out marker");
        assert!(
            is_opted_out(dir.path()),
            "a written marker reads as opted out"
        );
        clear_opted_out(dir.path()).expect("clear the opt-out marker");
        assert!(
            !is_opted_out(dir.path()),
            "a cleared marker reads as not opted out"
        );
    }

    #[test]
    fn set_opted_out_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        set_opted_out(dir.path()).expect("first write");
        set_opted_out(dir.path()).expect("re-writing an existing marker succeeds");
        assert!(is_opted_out(dir.path()));
    }

    #[test]
    fn clear_opted_out_on_an_absent_marker_is_a_no_op_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        clear_opted_out(dir.path()).expect("clearing an absent marker is success, not an error");
    }

    #[test]
    fn set_opted_out_creates_a_missing_state_dir() {
        // `schedule uninstall` must set the opt-out even when no pass ever created the state dir.
        let parent = tempfile::tempdir().expect("tempdir");
        let state_dir = parent.path().join("never-created").join("updater");
        set_opted_out(&state_dir).expect("creates the state dir on the way to writing the marker");
        assert!(is_opted_out(&state_dir));
    }

    #[cfg(unix)]
    #[test]
    fn the_marker_is_hardened_admin_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        set_opted_out(dir.path()).expect("write the marker");
        let mode = std::fs::metadata(marker_path(dir.path()))
            .expect("marker exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the marker must not be group/other accessible — only a privileged identity may forge it"
        );
    }

    #[test]
    fn marker_path_is_inside_the_state_dir() {
        let dir = PathBuf::from("/var/lib/dig-updater");
        assert_eq!(
            marker_path(&dir),
            PathBuf::from("/var/lib/dig-updater/schedule-optout")
        );
    }
}
