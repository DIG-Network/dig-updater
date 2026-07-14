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

/// The state directory a DRY check uses: [`STATE_DIR_ENV`] when set to a non-empty path; else the
/// hardened [`default_state_dir`] when this process can actually use it (Administrator/root, and
/// the directory really is writable); else a [`per_user_state_dir`] fallback. A dry check neither
/// installs nor advances the trust state (it only reads state for freshness context and writes the
/// informational status mirror), so relocating it to a writable directory is safe — unlike the
/// install path, which is never overridable.
///
/// The fallback matters for an everyday unprivileged `dig-updater check` (#582): without it, the
/// worker's staging `create_dir_all` hits the pre-existing Admin/SYSTEM-owned default, Windows
/// reports `ERROR_ALREADY_EXISTS` for a directory this identity cannot even query the metadata of,
/// and the check fails with a bare, cryptic `os error 183` instead of ever fetching + verifying the
/// feed.
#[must_use]
pub fn dry_check_state_dir() -> PathBuf {
    resolve_dry_check_state_dir(std::env::var_os(STATE_DIR_ENV), default_dir_is_usable)
}

/// Pure resolver behind [`dry_check_state_dir`]: a non-empty override wins; otherwise
/// `default_dir_usable` (injected so both branches are unit-testable without mutating the process
/// environment or real elevation) decides between the hardened default and the per-user fallback.
fn resolve_dry_check_state_dir(
    override_dir: Option<OsString>,
    default_dir_usable: impl FnOnce() -> bool,
) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ if default_dir_usable() => default_state_dir(),
        _ => per_user_state_dir(),
    }
}

/// Whether [`default_state_dir`] is actually usable by THIS process right now: elevation
/// (Administrator/root) is checked first as a cheap short-circuit — an unelevated caller has no
/// realistic path to the Admin/SYSTEM-owned default, so there is no reason to touch the
/// filesystem to find that out — and only when elevated is the directory actually probed for
/// writability, since an "elevated" console can still be denied by an unusual ACL.
fn default_dir_is_usable() -> bool {
    crate::elevation::is_elevated() && is_dir_writable(&default_state_dir())
}

/// Whether `dir` can be created (if missing) and written into by this process. Creating it here
/// when the answer is "yes" costs nothing extra — the dry check needs it created anyway — and
/// tolerates the exact `AlreadyExists`-on-an-inaccessible-directory quirk that made this
/// unreliable to determine via `Path::is_dir()` alone (see [`dry_check_state_dir`]'s doc).
fn is_dir_writable(dir: &Path) -> bool {
    if let Err(e) = std::fs::create_dir_all(dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return false;
        }
    }
    let probe = dir.join(".dig-updater-write-probe");
    let writable = std::fs::write(&probe, []).is_ok();
    let _ = std::fs::remove_file(&probe);
    writable
}

/// A per-user writable location a DRY check relocates to when [`default_state_dir`] is unusable
/// ([`dry_check_state_dir`]) — NEVER used by the install/full-pass path, which stays pinned to the
/// hardened default so anti-rollback can never be relocated.
///
/// - **Windows:** `%LOCALAPPDATA%\DIG\updater`.
/// - **Unix:** `$XDG_CACHE_HOME/dig-updater`, or `$HOME/.cache/dig-updater`, or the OS temp dir as
///   a last resort — so this always resolves a usable path, even in a stripped-down container with
///   none of those variables set.
#[must_use]
pub fn per_user_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .unwrap_or_else(|| std::env::temp_dir().into_os_string());
        PathBuf::from(local_app_data).join("DIG").join("updater")
    }
    #[cfg(unix)]
    {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap_or_else(std::env::temp_dir)
            .join("dig-updater")
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
    fn dry_check_state_dir_prefers_a_non_empty_env_override_regardless_of_usability() {
        // #540: the signed-feed keystone runs `check` UNELEVATED, so it must be able to point the
        // dry check at a writable dir instead of the Admin-only default. The override wins even
        // when the default WOULD have been reported usable — an explicit choice is never overridden.
        let override_dir = std::env::temp_dir().join("dig-updater-ci");
        for default_dir_usable in [true, false] {
            assert_eq!(
                resolve_dry_check_state_dir(Some(override_dir.clone().into_os_string()), || {
                    default_dir_usable
                }),
                override_dir
            );
        }
    }

    #[test]
    fn dry_check_state_dir_uses_the_hardened_default_when_it_is_usable() {
        // Unset and empty both mean "no override" — never a surprise empty-path state dir. When the
        // default is reported usable (elevated AND writable), it wins over the per-user fallback.
        assert_eq!(
            resolve_dry_check_state_dir(None, || true),
            default_state_dir()
        );
        assert_eq!(
            resolve_dry_check_state_dir(Some(OsString::new()), || true),
            default_state_dir()
        );
    }

    #[test]
    fn dry_check_state_dir_relocates_to_the_per_user_dir_when_the_default_is_not_usable() {
        // #582: an everyday unprivileged `dig-updater check` must not even ATTEMPT the
        // Admin/SYSTEM-owned default — it relocates to a per-user writable location instead of
        // surfacing the worker's staging `create_dir_all` failure as a bare `os error 183`.
        assert_eq!(
            resolve_dry_check_state_dir(None, || false),
            per_user_state_dir()
        );
        assert_eq!(
            resolve_dry_check_state_dir(Some(OsString::new()), || false),
            per_user_state_dir()
        );
    }

    #[test]
    fn per_user_state_dir_always_resolves_a_non_empty_path() {
        // Whatever the host's environment looks like, this must never panic or hand back an empty
        // path — it is the last-resort location an unprivileged dry check relies on.
        assert_ne!(per_user_state_dir(), PathBuf::new());
    }

    #[test]
    fn per_user_state_dir_is_distinct_from_the_hardened_default() {
        // The whole point of the fallback is that it is somewhere an unprivileged process can
        // actually write — which the Admin/SYSTEM-only default, by construction, is not.
        assert_ne!(per_user_state_dir(), default_state_dir());
    }

    #[test]
    fn is_dir_writable_is_true_for_a_fresh_or_pre_existing_writable_directory() {
        let tmp = tempfile::tempdir().expect("scratch dir");
        let dir = tmp.path().join("state");
        assert!(is_dir_writable(&dir), "a fresh directory must be usable");
        assert!(
            is_dir_writable(&dir),
            "an already-existing, still-writable directory must be tolerated, not rejected"
        );
    }

    #[test]
    fn is_dir_writable_is_false_when_the_path_is_occupied_by_a_plain_file() {
        // A deterministic, cross-platform stand-in for "this identity cannot use the directory":
        // occupying the exact path with a plain file reproduces the same `AlreadyExists` outcome an
        // ACL-denied SYSTEM-owned directory produces, without needing real elevation to set up.
        let tmp = tempfile::tempdir().expect("scratch dir");
        let occupied = tmp.path().join("state");
        std::fs::write(&occupied, b"not a directory").expect("occupy the path with a file");
        assert!(!is_dir_writable(&occupied));
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
