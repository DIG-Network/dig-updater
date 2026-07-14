//! Filesystem locations the broker uses: the Admin/SYSTEM-only state directory, its WORLD-READABLE
//! status sibling, and the sibling `dig-updater-worker` binary.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::BrokerError;

/// The environment variable that relocates the state directory FOR A DRY CHECK ONLY
/// ([`dry_check_state_dir`]). It exists so an unprivileged operator — or CI, such as the signed
/// feed's end-to-end keystone (#540) — can run `dig-updater check` without write access to the
/// Admin/SYSTEM-only default state dir. It deliberately does NOT relocate the install/full-pass
/// state dir ([`default_state_dir`]): the anti-rollback trust state MUST stay in the hardened
/// default so an unprivileged process can never point the beacon at a state it can roll back
/// (SPEC §6, §9.3).
pub const STATE_DIR_ENV: &str = "DIG_UPDATER_STATE_DIR";

/// The default state directory for the beacon.
///
/// - **Windows:** `%ProgramData%\DIG\updater` (DACL'd to Administrators + SYSTEM by
///   [`crate::secure::harden_state_dir`]).
/// - **Unix:** `/var/lib/dig-updater` (root-owned, mode `0700`).
///
/// This is where the persisted [`TrustState`](dig_updater_trust::TrustState) and
/// [`UpdaterConfig`](crate::config::UpdaterConfig) live, so an unprivileged process cannot roll
/// either back (SPEC §6, §9.3, §13.1). The full-pass/install path ALWAYS uses this — it is never
/// overridable, so relocating it can never defeat anti-rollback.
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

/// The state directory a DRY check uses: [`STATE_DIR_ENV`] when set to a non-empty path, else
/// [`default_state_dir`]. A dry check neither installs nor advances the trust state (it only reads
/// state for freshness context and writes the informational status mirror), so relocating it to a
/// writable directory is safe — unlike the install path, which is never overridable.
#[must_use]
pub fn dry_check_state_dir() -> PathBuf {
    resolve_dry_check_state_dir(std::env::var_os(STATE_DIR_ENV))
}

/// Pure resolver behind [`dry_check_state_dir`]: a non-empty override wins; an unset or empty
/// value falls back to the hardened OS default. Split out so the precedence is unit-testable
/// without mutating the process environment.
fn resolve_dry_check_state_dir(override_dir: Option<OsString>) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => default_state_dir(),
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
    fn dry_check_state_dir_prefers_a_non_empty_env_override() {
        // #540: the signed-feed keystone runs `check` UNELEVATED, so it must be able to point the
        // dry check at a writable dir instead of the Admin-only default.
        let override_dir = OsString::from(if cfg!(windows) {
            r"C:\tmp\dig-updater-ci"
        } else {
            "/tmp/dig-updater-ci"
        });
        assert_eq!(
            resolve_dry_check_state_dir(Some(override_dir.clone())),
            PathBuf::from(override_dir)
        );
    }

    #[test]
    fn dry_check_state_dir_falls_back_to_the_default_when_unset_or_empty() {
        // Unset and empty both mean "no override" — never a surprise empty-path state dir.
        assert_eq!(resolve_dry_check_state_dir(None), default_state_dir());
        assert_eq!(
            resolve_dry_check_state_dir(Some(OsString::new())),
            default_state_dir()
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
