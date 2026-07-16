//! Replacing the beacon's OWN running image — always the LAST act of a pass (SPEC §8.1, #504-F).
//!
//! The beacon is transient: it wakes, runs one pass, and exits. That makes self-replacement safe
//! by construction, PROVIDED it happens strictly after every other tracked component has already
//! installed, health-gated, and (if needed) rolled back — a self-swap that raced ahead of the rest
//! of the pass could leave another component's in-flight install inconsistent if this process then
//! died mid-swap. [`crate::pass::Installer::apply`] enforces that ordering by carving the beacon's
//! own component out of the main loop and calling [`apply_self_update`] only once everything else
//! is settled; this module supplies just the platform-specific INSTALL step — staging, hashing,
//! snapshotting, health-gating, and rollback are the same shared machinery every other component
//! goes through (see `Installer::apply_component`).
//!
//! - **Unix** replaces the running executable's directory entry: the kernel keeps the OLD inode
//!   open for whichever process is still executing it, so the swap is invisible to that process and
//!   takes effect only for the NEXT invocation of the path.
//! - **Windows** cannot overwrite a loaded image's bytes in place (a direct replace on the
//!   currently-executing path routinely fails with a sharing violation), but CAN rename it out of
//!   the way — the loader shares delete/rename access on the running file, which is exactly the
//!   technique long-lived self-updating Windows programs use: the running image moves aside to a
//!   `.old` sibling, then the already-verified private copy takes its name, undoing itself on a
//!   failed second rename so the beacon is never left without a working binary.
//!
//! Both are the SAME running-target-safe swap every raw-binary component now goes through
//! ([`crate::install::rename_into_place`], generalized for #558 from this module's original
//! self-update-only move-aside), so the self-update carries no bespoke replace logic of its own.

use std::path::Path;

use crate::install::{rename_into_place, InstallOutcome, RetryPolicy};

/// Apply the beacon's own verified `private` copy over its running image at `dest`.
///
/// Called ONLY after every other actionable component in the pass has already been applied (see
/// the module doc) — `private` has already passed the same digest re-verification every other
/// component's staged artifact does ([`crate::install::stage_and_verify_private`]). The replace
/// itself is the shared, running-target-safe [`rename_into_place`]: replacing the beacon's own
/// running image is exactly the running-peer case that path already handles (#558).
#[must_use]
pub fn apply_self_update(private: &Path, dest: &Path, policy: &RetryPolicy) -> InstallOutcome {
    rename_into_place(private, dest, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn no_backoff() -> RetryPolicy {
        RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        }
    }

    #[test]
    fn a_fresh_self_install_with_no_prior_binary_just_places_the_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-updater");
        let private = dir.path().join("dig-updater.dig-updater-verified");
        std::fs::write(&private, b"brand-new-beacon").unwrap();

        let outcome = apply_self_update(&private, &dest, &no_backoff());
        assert_eq!(outcome, InstallOutcome::Installed);
        assert_eq!(std::fs::read(&dest).unwrap(), b"brand-new-beacon");
        assert!(
            !private.exists(),
            "the private copy is consumed, not left behind"
        );
    }

    #[test]
    fn a_self_update_over_an_existing_binary_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-updater");
        std::fs::write(&dest, b"old-beacon-bytes").unwrap();
        let private = dir.path().join("dig-updater.dig-updater-verified");
        std::fs::write(&private, b"new-beacon-bytes").unwrap();

        let outcome = apply_self_update(&private, &dest, &no_backoff());
        assert_eq!(outcome, InstallOutcome::Installed);
        assert_eq!(std::fs::read(&dest).unwrap(), b"new-beacon-bytes");
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_swap_leaves_no_old_sibling_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-updater.exe");
        std::fs::write(&dest, b"old").unwrap();
        let private = dir.path().join("dig-updater.exe.dig-updater-verified");
        std::fs::write(&private, b"new").unwrap();

        let outcome = apply_self_update(&private, &dest, &no_backoff());
        assert_eq!(outcome, InstallOutcome::Installed);
        assert!(
            !dest.with_extension("dig-updater-old").exists(),
            "the superseded .old copy is cleaned up once the swap succeeds"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_swap_restores_the_running_image_if_the_second_rename_fails() {
        // Simulate the second rename failing by never staging `private` at all (its containing
        // directory does not even exist) — the running image at `dest` must still be intact
        // afterward, not left renamed-away with nothing put back in its place.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-updater.exe");
        std::fs::write(&dest, b"still-running-old-bytes").unwrap();
        let private = dir
            .path()
            .join("no-such-dir")
            .join("dig-updater.exe.dig-updater-verified");

        let outcome = apply_self_update(&private, &dest, &no_backoff());
        assert!(matches!(outcome, InstallOutcome::Deferred { .. }));
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"still-running-old-bytes",
            "a failed swap must restore the pre-swap running image, never leave dest missing"
        );
    }
}
