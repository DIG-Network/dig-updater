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
//! ## Security: the marker is honored only when it is provably PRIVILEGED-OWNED
//!
//! Suppressing auto-updates is an attack surface — a stale-pin/downgrade vector — so a
//! non-privileged process must not be able to FORGE the marker to silence the beacon. Existence
//! ALONE is not trusted: on Windows the default `%ProgramData%` DACL grants `BUILTIN\Users`
//! create-file, so an unprivileged user could otherwise plant `schedule-optout` in the state dir,
//! and the read paths (`scheduler::ensure`, the per-pass self-heal) do NOT re-harden the dir before
//! reading — nor would re-hardening delete a pre-planted file. So the marker is honored ONLY when it
//! is provably OWNED by a privileged identity ([`crate::secure::path_is_privileged_owned`]):
//!
//! - [`set_opted_out`] writes the marker, re-hardens it Admin/SYSTEM-only, AND claims privileged
//!   OWNERSHIP of it ([`crate::secure::claim_privileged_ownership`] — Administrators on Windows,
//!   root on Unix). Assigning that ownership requires the same privilege `schedule uninstall`
//!   already demands, so an unprivileged user cannot reproduce it.
//! - [`is_opted_out`] VERIFIES ownership before honoring the marker. Ownership (not the DACL) is the
//!   discriminator, because a planted file's creator-owner retains `WRITE_DAC` and could otherwise
//!   re-restrict its DACL to look hardened.
//!
//! ## Fail-OPEN toward availability
//!
//! [`is_opted_out`] answers `true` ONLY for a marker that provably exists AND is privileged-owned.
//! A missing marker, an unreadable one, one whose ownership can't be determined, OR one owned by a
//! non-privileged identity all answer `false` (NOT opted out = re-arm). Auto-updates staying alive
//! is the safe failure: only a present, privileged-owned marker suppresses the self-heal.

use std::path::{Path, PathBuf};

use crate::error::BrokerError;
use crate::secure::{claim_privileged_ownership, harden_state_dir, path_is_privileged_owned};

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
/// wrote a privileged-owned sentinel into `state_dir`).
///
/// FAIL-OPEN + UN-FORGEABLE: answers `true` only for a marker that provably exists AND is owned by a
/// privileged identity ([`path_is_privileged_owned`]); a missing marker, an unreadable one, or one
/// owned by a non-privileged identity (e.g. a file an unprivileged user planted in the state dir)
/// answers `false` (re-arm). See the module doc for why availability is the safe failure and why
/// ownership — not mere existence — is the un-forgeability anchor.
#[must_use]
pub fn is_opted_out(state_dir: &Path) -> bool {
    path_is_privileged_owned(&marker_path(state_dir))
}

/// Record a DELIBERATE opt-out: write the sentinel into `state_dir` and harden it Admin/SYSTEM-only.
///
/// Idempotent — re-writing an already-present marker succeeds. The state directory is created if
/// missing (it is the Admin-only default in production), so `schedule uninstall` sets the opt-out
/// even on a machine where a pass never created the state dir.
///
/// # Errors
///
/// [`BrokerError::Io`] if the state dir cannot be created, the marker cannot be written, its
/// Admin/SYSTEM-only ACL cannot be applied, or its privileged ownership cannot be claimed
/// (fail-closed — a marker that is not hardened AND privileged-owned would not verify, so writing
/// it must not silently "succeed").
pub fn set_opted_out(state_dir: &Path) -> Result<(), BrokerError> {
    std::fs::create_dir_all(state_dir).map_err(|e| BrokerError::Io(e.to_string()))?;
    let path = marker_path(state_dir);
    std::fs::write(&path, OPTOUT_MARKER_NOTE).map_err(|e| BrokerError::Io(e.to_string()))?;
    harden_state_dir(&path)?;
    // Ownership — not the DACL — is what makes the marker un-forgeable ([`is_opted_out`]).
    claim_privileged_ownership(&path)
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

    /// Whether `set_opted_out` can succeed HERE: on Windows it claims Administrators ownership
    /// (`icacls /setowner`), which needs elevation, so a non-elevated Windows dev run must skip the
    /// tests that write a marker. On Unix the ownership claim is a no-op, so any run can write one.
    fn can_write_marker() -> bool {
        !cfg!(windows) || crate::elevation::is_elevated()
    }

    #[test]
    fn a_fresh_state_dir_is_not_opted_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            !is_opted_out(dir.path()),
            "no marker present => not opted out => re-arm"
        );
    }

    #[test]
    fn a_non_privileged_owned_marker_is_not_honored() {
        // THE forgery guard (loop-security HIGH): a marker that EXISTS but was created by an
        // ordinary (non-privileged) identity — i.e. this test process, which is NOT SYSTEM/root and
        // owns files under its own SID/uid — must NOT be honored, or an unprivileged local user
        // could plant `schedule-optout` in the state dir to permanently suppress auto-updates. We
        // write the file WITHOUT `set_opted_out`'s privileged-ownership claim, mimicking a plant.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(marker_path(dir.path()), b"planted").expect("plant a marker");
        assert!(
            !is_opted_out(dir.path()),
            "a marker not owned by a privileged identity must be treated as NOT opted out (re-arm)"
        );
    }

    #[test]
    fn clear_opted_out_removes_the_marker_file() {
        // Existence-level round trip: `set_opted_out` creates the marker file and `clear_opted_out`
        // removes it. (Writing needs privilege on Windows — see `can_write_marker`.)
        if !can_write_marker() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        set_opted_out(dir.path()).expect("write the opt-out marker");
        assert!(
            marker_path(dir.path()).exists(),
            "the marker file is written"
        );
        clear_opted_out(dir.path()).expect("clear the opt-out marker");
        assert!(
            !marker_path(dir.path()).exists(),
            "the marker file is gone after clear"
        );
        assert!(
            !is_opted_out(dir.path()),
            "a cleared marker reads as not opted out"
        );
    }

    #[test]
    fn set_opted_out_is_idempotent() {
        if !can_write_marker() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        set_opted_out(dir.path()).expect("first write");
        set_opted_out(dir.path()).expect("re-writing an existing marker succeeds");
        assert!(marker_path(dir.path()).exists());
    }

    #[test]
    fn clear_opted_out_on_an_absent_marker_is_a_no_op_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        clear_opted_out(dir.path()).expect("clearing an absent marker is success, not an error");
    }

    #[test]
    fn set_opted_out_creates_a_missing_state_dir() {
        // `schedule uninstall` must set the opt-out even when no pass ever created the state dir.
        if !can_write_marker() {
            return;
        }
        let parent = tempfile::tempdir().expect("tempdir");
        let state_dir = parent.path().join("never-created").join("updater");
        set_opted_out(&state_dir).expect("creates the state dir on the way to writing the marker");
        assert!(marker_path(&state_dir).exists());
    }

    #[test]
    #[ignore = "requires Administrator/root to claim + verify privileged ownership — run via \
                `-- --ignored` in the elevated scheduler CI job"]
    fn a_privileged_owned_marker_is_honored() {
        // The positive side of the un-forgeability check: a marker written by `set_opted_out` (which
        // CLAIMS privileged ownership) IS honored, and clearing it flips it back. Producing (and
        // verifying) privileged ownership requires actually being privileged — Administrators on
        // Windows, root on Unix — so this runs in the elevated CI job (Windows Administrator / Unix
        // sudo), like the scheduler integration tests. The NON-privileged (forgery) side is covered
        // cross-platform by `a_non_privileged_owned_marker_is_not_honored`.
        let dir = tempfile::tempdir().expect("tempdir");
        set_opted_out(dir.path()).expect("write a privileged-owned marker");
        assert!(
            is_opted_out(dir.path()),
            "a privileged-owned marker must be honored as a deliberate opt-out"
        );
        clear_opted_out(dir.path()).expect("clear");
        assert!(!is_opted_out(dir.path()), "cleared => not opted out");
    }

    #[cfg(unix)]
    #[test]
    fn the_marker_is_hardened_admin_only() {
        use std::os::unix::fs::PermissionsExt;
        // Unix: the ownership claim is a no-op, so this always runs (`can_write_marker` is true).
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
