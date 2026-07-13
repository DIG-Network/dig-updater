//! Filesystem locations the broker uses: the Admin/SYSTEM-only state directory and the sibling
//! `dig-updater-worker` binary.

use std::path::PathBuf;

use crate::error::BrokerError;

/// The default state directory for the beacon.
///
/// - **Windows:** `%ProgramData%\DIG\updater` (DACL'd to Administrators + SYSTEM by
///   [`crate::secure::harden_state_dir`]).
/// - **Unix:** `/var/lib/dig-updater` (root-owned, mode `0700`).
///
/// This is where the persisted [`TrustState`](dig_updater_trust::TrustState) lives, so an
/// unprivileged process cannot roll it back to re-enable a downgrade (SPEC §6, §9.3).
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
}
