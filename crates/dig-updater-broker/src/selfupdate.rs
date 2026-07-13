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
//! - **Unix** replaces the running executable with a single atomic rename. The kernel keeps the
//!   OLD inode open for whichever process is still executing it — renaming its directory entry
//!   away is invisible to that process and takes effect only for the NEXT invocation of the path.
//!   This is exactly [`crate::install`]'s existing raw-binary replace, reused verbatim.
//! - **Windows** cannot overwrite a loaded image's bytes in place (a direct replace on the
//!   currently-executing path routinely fails with a sharing violation), but CAN rename it out of
//!   the way — the loader shares delete/rename access on the running file, which is exactly the
//!   technique long-lived self-updating Windows programs use. So this stages the swap as two
//!   plain renames: the running image moves aside to a `.old` sibling, then the already-verified
//!   private copy takes its name. If either half fails, the swap is undone rather than left
//!   half-applied — never mid-pass, never a beacon left unable to start.

use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use crate::install::{InstallOutcome, RetryPolicy};

/// Apply the beacon's own verified `private` copy over its running image at `dest`.
///
/// Called ONLY after every other actionable component in the pass has already been applied (see
/// the module doc) — `private` has already passed the same digest re-verification every other
/// component's staged artifact does ([`crate::install::stage_and_verify_private`]).
#[must_use]
pub fn apply_self_update(private: &Path, dest: &Path, policy: &RetryPolicy) -> InstallOutcome {
    #[cfg(windows)]
    {
        windows_swap(private, dest, policy)
    }
    #[cfg(not(windows))]
    {
        // Unix permits replacing a running executable's directory entry outright — no dance
        // needed, so this is precisely the raw-binary path every other component already uses.
        crate::install::rename_into_place(private, dest, policy)
    }
}

/// The Windows two-rename swap: move the running image aside, then place the verified copy in
/// its name. Undoes itself on a failed second rename, so the beacon is never left without a
/// working binary at `dest`.
#[cfg(windows)]
fn windows_swap(private: &Path, dest: &Path, policy: &RetryPolicy) -> InstallOutcome {
    let old = superseded_sibling(dest);
    // Best-effort: a `.old` left behind by a pass that could not yet delete it (still locked by
    // that pass's own then-running image) may have unlocked by now — clear it opportunistically
    // so it never accumulates across many passes. Its continued presence is harmless either way.
    let _ = std::fs::remove_file(&old);

    if dest.exists() {
        if let Err(e) = rename_with_retry(dest, &old, policy) {
            let _ = std::fs::remove_file(private);
            return InstallOutcome::Deferred {
                reason: format!(
                    "the running image at {} is locked after retries: {e}",
                    dest.display()
                ),
            };
        }
    }

    match rename_with_retry(private, dest, policy) {
        Ok(()) => {
            // The running process is still executing from the (renamed-away) `old` file object —
            // renaming a file does not relocate an already-open image mapping — so `old` is
            // ordinary, non-executing content by the time we get here and usually deletes cleanly.
            let _ = std::fs::remove_file(&old);
            InstallOutcome::Installed
        }
        Err(e) => {
            // Put the running image back so the beacon is left WORKING, never half-swapped.
            let _ = std::fs::rename(&old, dest);
            let _ = std::fs::remove_file(private);
            InstallOutcome::Deferred {
                reason: format!("could not place the new image at {}: {e}", dest.display()),
            }
        }
    }
}

/// The `.old` sibling a superseded self-image is renamed to, so it never collides with a peer
/// component's own private-copy naming convention.
#[cfg(windows)]
fn superseded_sibling(dest: &Path) -> PathBuf {
    dest.with_extension("dig-updater-old")
}

/// Retry a plain rename with `policy`'s backoff, surfacing the last error on give-up.
#[cfg(windows)]
fn rename_with_retry(from: &Path, to: &Path, policy: &RetryPolicy) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..policy.attempts.max(1) {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                if attempt + 1 < policy.attempts && !policy.backoff.is_zero() {
                    std::thread::sleep(policy.backoff * (attempt + 1));
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no attempts made")))
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
            !superseded_sibling(&dest).exists(),
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
