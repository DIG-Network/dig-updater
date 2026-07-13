//! Locking the state directory down to privileged identities only.
//!
//! The persisted trust state is the beacon's anti-rollback memory; if an unprivileged process
//! could rewrite it, it could lower the high-water-marks and re-enable a downgrade (SPEC §6,
//! §9.3). So the directory is restricted to Administrators + SYSTEM (Windows) / root, mode `0700`
//! (Unix). This module contains NO `unsafe` — Unix uses the safe `PermissionsExt`; Windows shells
//! out to the built-in `icacls`.

use std::path::Path;

use crate::error::BrokerError;

/// Restrict `dir` so only privileged identities can read or write it (and, by inheritance, the
/// files inside it).
///
/// - **Unix:** `chmod 0700` — owner-only. When the broker runs as root this is root-only.
/// - **Windows:** `icacls` removes inheritance and grants Full Control to *only* the
///   Administrators (`S-1-5-32-544`) and Local System (`S-1-5-18`) SIDs, so the DACL matches the
///   "Admin + SYSTEM only" requirement and child files inherit it.
///
/// # Errors
///
/// [`BrokerError::Io`] if the permissions could not be applied (fail-closed — the beacon must not
/// proceed with a world-writable trust store).
pub fn harden_state_dir(dir: &Path) -> Result<(), BrokerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms).map_err(|e| BrokerError::Io(e.to_string()))
    }
    #[cfg(windows)]
    {
        harden_windows_dir(dir)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Apply an Administrators + SYSTEM-only DACL to `dir` via `icacls`.
#[cfg(windows)]
fn harden_windows_dir(dir: &Path) -> Result<(), BrokerError> {
    use std::process::Command;
    let status = Command::new("icacls")
        .arg(dir)
        .arg("/inheritance:r")
        .args(["/grant:r", "*S-1-5-32-544:(OI)(CI)F"]) // Administrators, full, inherited by children
        .args(["/grant:r", "*S-1-5-18:(OI)(CI)F"]) // Local System, full, inherited by children
        .output()
        .map_err(|e| BrokerError::Io(format!("could not run icacls: {e}")))?;
    if !status.status.success() {
        return Err(BrokerError::Io(format!(
            "icacls failed to harden {}: {}",
            dir.display(),
            String::from_utf8_lossy(&status.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_succeeds_on_an_owned_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Hardening a directory we own must succeed on every platform (owner/admin retains
        // access — 0700 keeps the owner; the Windows CI runner is an Administrator).
        harden_state_dir(tmp.path()).expect("harden owned dir");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "state dir must be owner-only");
        }
    }
}
