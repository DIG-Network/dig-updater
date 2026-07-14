//! Filesystem locations the broker uses: the Admin/SYSTEM-only state directory, its WORLD-READABLE
//! status sibling, and the sibling `dig-updater-worker` binary.

use std::path::{Path, PathBuf};

use crate::error::BrokerError;

/// The default state directory for the beacon.
///
/// - **Windows:** `%ProgramData%\DIG\updater` (DACL'd to Administrators + SYSTEM by
///   [`crate::secure::harden_state_dir`]).
/// - **Unix:** `/var/lib/dig-updater` (root-owned, mode `0700`).
///
/// This is where the persisted [`TrustState`](dig_updater_trust::TrustState) and
/// [`UpdaterConfig`](crate::config::UpdaterConfig) live, so an unprivileged process cannot roll
/// either back (SPEC §6, §9.3, §13.1).
#[must_use]
pub fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let program_data =
            std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(program_data).join("DIG").join("updater")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/dig-updater")
    }
}

/// The default WORLD-READABLE status directory — [`sibling_status_dir`] of [`default_state_dir`].
#[must_use]
pub fn default_status_dir() -> PathBuf {
    sibling_status_dir(&default_state_dir())
}

/// The `status.json` directory that mirrors `state_dir`: the SAME parent, with `-status`
/// appended to the directory's own name (`/var/lib/dig-updater` → `/var/lib/dig-updater-status`;
/// `%ProgramData%\DIG\updater` → `%ProgramData%\DIG\updater-status`).
///
/// It must be a SIBLING, never a subdirectory of `state_dir`: [`crate::secure::harden_state_dir`]
/// applies a recursive Admin/SYSTEM-only ACL to `state_dir` (Windows `(OI)(CI)` inheritance;
/// Unix `0700`), so anything nested inside it would inherit that lock-down and stop being
/// world-readable (SPEC §13.2). Deriving it from `state_dir` — rather than a second hard-coded
/// constant — keeps a test's custom `state_dir` (`Broker::with_paths`) and the real default in
/// permanent lockstep, with no second path to keep in sync.
#[must_use]
pub fn sibling_status_dir(state_dir: &Path) -> PathBuf {
    let mut sibling_name = state_dir.file_name().unwrap_or_default().to_os_string();
    sibling_name.push("-status");
    state_dir.with_file_name(sibling_name)
}

/// Resolve the `dig-updater-worker` binary that sits alongside the current executable.
///
/// The beacon ships the broker (or CLI) and the worker in the same directory, so the worker is
/// found next to `current_exe()`. This keeps the two halves of a pass on the same installed
/// version.
///
/// # Errors
///
/// [`BrokerError::Io`] if the current executable path cannot be determined.
pub fn sibling_worker_binary() -> Result<PathBuf, BrokerError> {
    let exe = std::env::current_exe().map_err(|e| BrokerError::Io(e.to_string()))?;
    let dir = exe
        .parent()
        .ok_or_else(|| BrokerError::Io("current executable has no parent directory".into()))?;
    Ok(dir.join(worker_file_name()))
}

/// The platform file name of the worker binary.
#[must_use]
pub fn worker_file_name() -> &'static str {
    if cfg!(windows) {
        "dig-updater-worker.exe"
    } else {
        "dig-updater-worker"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_is_admin_scoped_per_os() {
        let dir = default_state_dir();
        if cfg!(windows) {
            assert!(dir.ends_with(r"DIG\updater") || dir.ends_with("DIG/updater"));
        } else {
            assert_eq!(dir, PathBuf::from("/var/lib/dig-updater"));
        }
    }

    #[test]
    fn worker_file_name_has_exe_suffix_on_windows() {
        let name = worker_file_name();
        assert_eq!(name.ends_with(".exe"), cfg!(windows));
    }

    #[test]
    fn status_dir_is_a_sibling_of_state_dir_not_nested_inside_it() {
        let state_dir = PathBuf::from("/var/lib/dig-updater");
        let status_dir = sibling_status_dir(&state_dir);
        assert_eq!(status_dir, PathBuf::from("/var/lib/dig-updater-status"));
        assert_eq!(
            status_dir.parent(),
            state_dir.parent(),
            "must share the SAME parent, never nest under the hardened state dir"
        );
    }

    #[test]
    fn default_status_dir_derives_from_default_state_dir() {
        assert_eq!(
            default_status_dir(),
            sibling_status_dir(&default_state_dir())
        );
    }

    #[test]
    fn sibling_status_dir_preserves_an_arbitrary_test_state_dir_name() {
        // A test's tempdir has a unique, arbitrary name (not "dig-updater") — the derivation must
        // still produce a distinct, non-nested sibling for it.
        let state_dir = PathBuf::from("/tmp/abc123");
        assert_eq!(
            sibling_status_dir(&state_dir),
            PathBuf::from("/tmp/abc123-status")
        );
    }
}
