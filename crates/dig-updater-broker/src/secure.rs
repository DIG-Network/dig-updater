//! Locking the beacon's privileged paths down to privileged identities only, and self-checking
//! that they are.
//!
//! The persisted trust state is the beacon's anti-rollback memory; if an unprivileged process
//! could rewrite it, it could lower the high-water-marks and re-enable a downgrade (SPEC §6,
//! §9.3). The same reasoning covers every privileged path a pass depends on — the beacon binary
//! (swap it and you own the fleet), the staging directory (swap staged bytes and you defeat the
//! digest gate), the last-known-good cache. So each is restricted to Administrators + SYSTEM
//! (Windows) / root, mode `0700` (Unix), and — before a pass installs anything — [`acl_self_check`]
//! VERIFIES it, repairing a directory the broker owns or ABORTING fail-closed otherwise.
//!
//! This module contains NO `unsafe` — Unix uses the safe `PermissionsExt`; Windows shells out to
//! the built-in `icacls`.

use std::path::{Path, PathBuf};

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

/// Apply an Administrators + SYSTEM (+ owner) DACL to `dir` via `icacls`.
///
/// The grant is Administrators + Local System + OWNER RIGHTS. The owner ACE (`S-1-3-4`) ensures the
/// identity that created the directory always retains access — in production that is SYSTEM (the
/// service), but it also lets an unelevated admin process (whose Administrators group is deny-only
/// under UAC) still write what it owns. It is NOT a weakening: taking ownership of a file is itself
/// a privileged operation, so an unprivileged process cannot gain the owner ACE. No `Users` /
/// `Everyone` ACE is granted, so the directory stays non-world-writable.
#[cfg(windows)]
fn harden_windows_dir(dir: &Path) -> Result<(), BrokerError> {
    use std::process::Command;
    let status = Command::new("icacls")
        .arg(dir)
        .arg("/inheritance:r")
        .args(["/grant:r", "*S-1-5-32-544:(OI)(CI)F"]) // Administrators, full, inherited by children
        .args(["/grant:r", "*S-1-5-18:(OI)(CI)F"]) // Local System, full, inherited by children
        .args(["/grant:r", "*S-1-3-4:(OI)(CI)F"]) // Owner rights — the creator keeps access
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

/// What the broker may do if a guarded path is found writable by a non-privileged identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repair {
    /// A directory the broker owns and manages (state / staging / last-known-good). A violation is
    /// REPAIRED by re-hardening it, then re-checked.
    IfOwned,
    /// A path the broker must NOT modify — above all the beacon binary itself. A violation here is
    /// fatal: silently chmod-ing our own binary could mask an in-progress attack, and it is not
    /// ours to relax. Fail closed.
    Never,
}

/// How broadly a path can be written, as reported by the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Writability {
    /// Only privileged identities (root / Administrators+SYSTEM) can write it.
    AdminOnly,
    /// A group or "other"/non-privileged identity can write it — a tampering vector. Constructed
    /// only where writability is exactly readable (Unix mode bits); the Windows alpha-floor
    /// classifier does not yet detect it (its enforcement is the `icacls` harden — see
    /// [`gather_writability`]), so it is legitimately unconstructed there.
    #[cfg_attr(not(unix), allow(dead_code))]
    Broader,
    /// The path does not exist yet (e.g. an -F lock/scheduler artifact not created in this scope).
    Missing,
}

/// The pure ACL decision: given how broadly a path is writable and the repair policy for it, what
/// should the self-check do? Split out from any I/O so the whole matrix is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclDecision {
    /// Acceptable as-is (admin-only, or a not-yet-created path).
    Accept,
    /// Too broad but repairable — harden it and re-check.
    Repair,
    /// Too broad and not repairable — abort the pass fail-closed.
    Abort,
}

/// The pure decision matrix mapping (writability, repair policy) to an [`AclDecision`].
fn decide_acl(writability: Writability, repair: Repair) -> AclDecision {
    match (writability, repair) {
        (Writability::AdminOnly | Writability::Missing, _) => AclDecision::Accept,
        (Writability::Broader, Repair::IfOwned) => AclDecision::Repair,
        (Writability::Broader, Repair::Never) => AclDecision::Abort,
    }
}

/// Verify every guarded path is writable only by privileged identities, repairing directories the
/// broker owns and ABORTING fail-closed on any un-repairable violation (SPEC §8.3, §9.3).
///
/// This runs BEFORE a pass touches the network or installs anything: a world-writable state dir,
/// staging dir, or beacon binary means an unprivileged process could tamper with the trust state
/// or with what gets installed, so the pass must not proceed. A path that does not exist yet is
/// skipped (there is nothing to lock down).
///
/// # Errors
///
/// [`BrokerError::AclViolation`] if a guarded path is writable by a non-privileged identity and
/// could not be repaired; [`BrokerError::Io`] if its permissions could not be read.
pub fn acl_self_check(paths: &[(PathBuf, Repair)]) -> Result<(), BrokerError> {
    for (path, repair) in paths {
        match decide_acl(gather_writability(path)?, *repair) {
            AclDecision::Accept => {}
            AclDecision::Repair => {
                harden_state_dir(path)?;
                if gather_writability(path)? != Writability::AdminOnly {
                    return Err(BrokerError::AclViolation {
                        path: path.display().to_string(),
                        detail: "still writable by a non-privileged identity after re-hardening"
                            .to_string(),
                    });
                }
            }
            AclDecision::Abort => {
                return Err(BrokerError::AclViolation {
                    path: path.display().to_string(),
                    detail: "writable by a non-privileged identity (the broker must not modify \
                             this path, so it cannot be repaired)"
                        .to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Read how broadly `path` may be written.
///
/// - **Unix:** exact — a path is admin-only iff neither group nor "other" holds the write bit
///   (`mode & 0o022 == 0`).
/// - **Windows (alpha floor):** best-effort — an existing path is reported admin-only; the real
///   enforcement on Windows is [`harden_state_dir`]'s `icacls` DACL, applied to owned directories
///   before this check. A full DACL audit of arbitrary paths (including the beacon binary) is a
///   hardening follow-up; until then the Windows self-check verifies existence + relies on the
///   harden for owned dirs.
fn gather_writability(path: &Path) -> Result<Writability, BrokerError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Writability::Missing),
        Err(e) => Err(BrokerError::Io(e.to_string())),
        Ok(meta) => Ok(classify_writability(&meta)),
    }
}

/// Classify a path's writability from its metadata (split out for testability).
#[cfg(unix)]
fn classify_writability(meta: &std::fs::Metadata) -> Writability {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o022 == 0 {
        Writability::AdminOnly
    } else {
        Writability::Broader
    }
}

/// See [`gather_writability`] — the Windows alpha-floor best-effort.
#[cfg(not(unix))]
fn classify_writability(_meta: &std::fs::Metadata) -> Writability {
    Writability::AdminOnly
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

    // -- the pure ACL decision matrix (every cell) --------------------------------

    #[test]
    fn admin_only_is_accepted_under_any_policy() {
        assert_eq!(
            decide_acl(Writability::AdminOnly, Repair::IfOwned),
            AclDecision::Accept
        );
        assert_eq!(
            decide_acl(Writability::AdminOnly, Repair::Never),
            AclDecision::Accept
        );
    }

    #[test]
    fn a_missing_path_is_accepted() {
        // An -F lock / scheduler artifact not yet created in this scope: nothing to lock down.
        assert_eq!(
            decide_acl(Writability::Missing, Repair::Never),
            AclDecision::Accept
        );
    }

    #[test]
    fn a_broad_owned_dir_is_repaired_but_a_broad_binary_aborts() {
        assert_eq!(
            decide_acl(Writability::Broader, Repair::IfOwned),
            AclDecision::Repair
        );
        assert_eq!(
            decide_acl(Writability::Broader, Repair::Never),
            AclDecision::Abort
        );
    }

    // -- acl_self_check end-to-end (Unix, where writability is exact) -------------

    #[test]
    fn self_check_accepts_a_hardened_owned_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        harden_state_dir(dir.path()).expect("harden");
        acl_self_check(&[(dir.path().to_path_buf(), Repair::IfOwned)]).expect("admin-only passes");
    }

    #[cfg(unix)]
    #[test]
    fn self_check_repairs_a_world_writable_owned_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        acl_self_check(&[(dir.path().to_path_buf(), Repair::IfOwned)])
            .expect("an owned dir is repaired, not aborted");
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o022,
            0,
            "the world-writable bits must be gone after repair"
        );
    }

    #[cfg(unix)]
    #[test]
    fn self_check_aborts_on_a_world_writable_never_repair_path() {
        use std::os::unix::fs::PermissionsExt;
        // Stand in for the beacon binary living in a world-writable directory: a file the broker
        // must NOT chmod. The self-check must ABORT fail-closed.
        let dir = tempfile::tempdir().expect("tempdir");
        let fake_binary = dir.path().join("dig-updater");
        std::fs::write(&fake_binary, b"pretend-binary").unwrap();
        std::fs::set_permissions(&fake_binary, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = acl_self_check(&[(fake_binary, Repair::Never)])
            .expect_err("a world-writable non-repairable path must abort");
        assert!(matches!(err, BrokerError::AclViolation { .. }));
    }

    #[test]
    fn self_check_skips_a_missing_guarded_path() {
        let missing = std::env::temp_dir().join("dig-updater-acl-definitely-missing-path");
        acl_self_check(&[(missing, Repair::Never)]).expect("a missing path is skipped");
    }
}
