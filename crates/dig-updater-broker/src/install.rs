//! Applying a verified artifact to the host — the privileged act at the heart of a pass.
//!
//! The security spine of this module is a single invariant: **the bytes that are hashed are the
//! bytes that are installed** (SPEC §8.3). The staging directory is writable by the (privilege-
//! dropped) worker, so its contents are untrusted and can change at any moment. Rather than hash a
//! staging file and then re-open it by path to install — a TOCTOU window in which a compromised
//! worker could swap the bytes between the two opens — the broker:
//!
//! 1. [`contained_staged_path`] canonicalizes the worker-reported path and REJECTS anything that
//!    does not resolve strictly inside the broker-owned staging directory (no `/tmp/evil`, no `..`
//!    escape), before a single byte is read.
//! 2. [`stage_and_verify_private`] streams the staged bytes ONCE into a broker-private file — where
//!    the worker cannot write — feeding each chunk to the SHA-256 hasher and the private copy from
//!    the same read, then verifies that copy against the RE-VERIFIED manifest digest. A swap of the
//!    staging file AFTER this returns cannot affect the private copy, so hashed == installed by
//!    construction.
//! 3. [`install_from_private`] installs from the PRIVATE copy: a raw binary is renamed into place
//!    (an atomic same-directory rename), and a native package is handed to its OS installer —
//!    always invoked by its ABSOLUTE, trusted path (never a bare name resolved through `PATH`).
//!
//! Silent + per-OS (SPEC §9.5): a native package installs quietly through the OS installer
//! (`msiexec /qn`, `installer -pkg`, `dpkg -i`); a raw binary is replaced in place with the
//! resilient, running-target-safe swap in [`rename_into_place`], DEFERRING to the next pass rather
//! than failing hard if the target stays locked.
//!
//! **Replacing a RUNNING binary (#558, same os-error-32 class as #544).** A raw-binary component
//! can be a currently-RUNNING service (e.g. dig-dns) or the beacon's own image, whose executable
//! the OS holds open. On Windows a direct overwrite/rename ONTO that open image fails with
//! ERROR_SHARING_VIOLATION (32) or ERROR_LOCK_VIOLATION (33); on unix an open-for-exec target can
//! raise ETXTBSY (26). A naive rename therefore deferred forever and the running peer never
//! updated. [`rename_into_place`] instead uses the move-aside swap the beacon's own self-update
//! proved (SPEC §8.1): the running image is RENAMED aside to a `.dig-updater-old` sibling (permitted
//! even while it executes — the loader shares delete/rename access), then the verified copy takes
//! its name. If the second rename fails the swap is undone (retried, not best-effort) so the target is
//! never left half-written — and if that undo ALSO fails, the outcome is `Failed` so the caller's
//! last-known-good rollback restores the target rather than leaving it missing; if the target stays
//! locked through the retry budget the pass DEFERS (SPEC §9.5). The new bytes
//! take effect on the service's next restart; the health probe re-reads the on-disk version to
//! confirm. This single resilient path is shared by every raw-binary component AND the self-update
//! ([`crate::selfupdate`]), so there is one implementation of the running-replace, not two.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use dig_updater_trust::verify_sha256;

use crate::error::BrokerError;
use crate::hashing::open_no_symlink;
use crate::plan::{InstallMethod, PlannedComponent};
use crate::proc::HideConsole;

/// The extension of the broker-private raw-binary copy that is renamed over `dest`. It lives in the
/// (root-owned) destination directory so the final install is an atomic same-filesystem rename.
const VERIFIED_RAW_EXT: &str = "dig-updater-verified";

/// The extension of the `.old` sibling a running/locked raw binary is moved aside to, so the
/// verified copy can take its name (#558). Distinct from [`VERIFIED_RAW_EXT`] so the move-aside and
/// the verified-copy staging never collide on the same path.
const SUPERSEDED_EXT: &str = "dig-updater-old";

/// Read granularity while copying + hashing a (possibly large) staged artifact.
const CHUNK_BYTES: usize = 64 * 1024;

/// How many times to retry replacing a locked raw binary, and how long to back off between tries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts before giving up and deferring to the next pass.
    pub attempts: u32,
    /// Base backoff, multiplied by the attempt index (linear backoff).
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 5,
            backoff: Duration::from_millis(250),
        }
    }
}

/// The outcome of applying one component's artifact. Per-component failures are values, not
/// errors, so one stuck component never aborts the whole pass (the pass just declines to advance
/// the trust state until every actionable component installs cleanly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The artifact was applied.
    Installed,
    /// The target was locked and could not be replaced within the retry budget — retry next pass
    /// (SPEC §9.5). Notably how the beacon's OWN image is handled: it is busy during its pass, so
    /// its self-update defers to the next wake (SPEC §8.1).
    Deferred {
        /// Why the install was deferred.
        reason: String,
    },
    /// The install command or replace failed outright; the caller rolls the component back.
    Failed {
        /// The failure detail.
        detail: String,
    },
}

/// Resolve the worker-reported `staged_path` and require it to sit strictly inside `staging_dir`.
///
/// Both sides are canonicalized so symlinks and `..` cannot smuggle the target out of the
/// broker-owned staging area; the returned canonical path is what the caller then hashes + copies.
/// A worker that reports `/tmp/evil` or `<staging>/../evil` is refused here, BEFORE any byte is
/// read (SPEC §8.3 — the worker is untrusted input).
///
/// # Errors
///
/// [`BrokerError::StagedPathEscapesStaging`] if the path cannot be canonicalized (e.g. it does not
/// exist) or resolves outside `staging_dir`; [`BrokerError::Io`] if `staging_dir` itself cannot be
/// canonicalized.
pub fn contained_staged_path(
    staged_path: &Path,
    staging_dir: &Path,
    component: &str,
) -> Result<PathBuf, BrokerError> {
    let staging_root = staging_dir.canonicalize().map_err(|e| {
        BrokerError::Io(format!(
            "staging dir {} cannot be canonicalized: {e}",
            staging_dir.display()
        ))
    })?;
    let resolved =
        staged_path
            .canonicalize()
            .map_err(|e| BrokerError::StagedPathEscapesStaging {
                component: component.to_string(),
                detail: format!("{} cannot be canonicalized: {e}", staged_path.display()),
            })?;
    if !resolved.starts_with(&staging_root) {
        return Err(BrokerError::StagedPathEscapesStaging {
            component: component.to_string(),
            detail: format!(
                "{} resolves to {}, outside the staging dir {}",
                staged_path.display(),
                resolved.display(),
                staging_root.display()
            ),
        });
    }
    Ok(resolved)
}

/// The broker-private file the verified bytes are copied into before install.
///
/// - **Raw binary:** a sibling of `dest` (in the root-owned destination directory), so the final
///   install is an atomic same-filesystem `rename`.
/// - **Native package:** a file in the broker-owned `apply_dir`, named with the package's extension
///   so the OS installer recognises it. Never the worker-writable staging path.
#[must_use]
pub fn private_target(pc: &PlannedComponent, apply_dir: &Path) -> PathBuf {
    match pc.method {
        InstallMethod::RawBinary => pc.dest.with_extension(VERIFIED_RAW_EXT),
        InstallMethod::WindowsMsi => apply_dir.join(format!("{}.msi", pc.name)),
        InstallMethod::MacosPkg => apply_dir.join(format!("{}.pkg", pc.name)),
        InstallMethod::LinuxDeb => apply_dir.join(format!("{}.deb", pc.name)),
    }
}

/// Copy the staged artifact into the broker-private `private` file and verify THAT copy against the
/// re-verified `expected_digest` — the crux of the hashed-is-installed invariant.
///
/// The staged file is read exactly once (symlink-safe); each chunk is written to `private` AND fed
/// to the hasher from the same buffer, so the bytes on disk in `private` are precisely the bytes
/// the digest is computed over. `private` lives where the worker cannot write, so a later swap of
/// the staging file has no effect on what gets installed. On a digest mismatch the private copy is
/// removed and the pass aborts fail-closed. When `executable`, the private copy is marked `0755`
/// (raw-binary replaces run it; native-package files do not need it).
///
/// # Errors
///
/// [`BrokerError::StagingReverifyFailed`] if the copied bytes do not match `expected_digest` (a
/// TOCTOU swap or a lying worker); [`BrokerError::Io`] on any read/write error.
pub fn stage_and_verify_private(
    staged: &Path,
    private: &Path,
    expected_digest: &str,
    component: &str,
    executable: bool,
) -> Result<(), BrokerError> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    if let Some(parent) = private.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BrokerError::Io(e.to_string()))?;
    }
    let mut src = open_no_symlink(staged)?;
    let mut out = std::fs::File::create(private).map_err(|e| BrokerError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        let n = src
            .read(&mut buf)
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .map_err(|e| BrokerError::Io(e.to_string()))?;
    }
    out.sync_all().map_err(|e| BrokerError::Io(e.to_string()))?;
    if executable {
        set_executable(private)?;
    }

    let computed: [u8; 32] = hasher.finalize().into();
    if let Err(e) = verify_sha256(expected_digest, &computed) {
        // The private copy failed the gate — leave nothing installable behind.
        let _ = std::fs::remove_file(private);
        return Err(BrokerError::StagingReverifyFailed {
            component: component.to_string(),
            detail: e.to_string(),
        });
    }
    Ok(())
}

/// Install a component from its already-verified broker-private copy `private` (produced by
/// [`stage_and_verify_private`]). A raw binary is renamed into place; a native package is handed to
/// its OS installer at an absolute, trusted path.
#[must_use]
pub fn install_from_private(
    pc: &PlannedComponent,
    private: &Path,
    policy: &RetryPolicy,
) -> InstallOutcome {
    match pc.method {
        InstallMethod::RawBinary => install_raw_binary_set(pc, private, policy),
        InstallMethod::WindowsMsi => run_native_installer(private, msiexec_argv(private)),
        InstallMethod::MacosPkg => run_native_installer(private, installer_argv(private)),
        InstallMethod::LinuxDeb => run_native_installer(private, dpkg_argv(private)),
    }
}

/// Replace the primary raw binary AND re-derive every byte-identical alias in the component's set
/// (#666 Bug A). The primary is renamed into place from the verified private copy; then each alias
/// is refreshed by COPYING the just-placed VERIFIED bytes (now at `pc.dest`) into the alias through
/// the SAME resilient move-aside — never a re-download or a re-fetch, so an alias can never diverge
/// from the verified primary and no extra feed asset is needed.
///
/// If the PRIMARY replace does not land (`Deferred`/`Failed`), the aliases are left untouched and
/// that outcome is returned as-is — the component is not `Installed`, so the health gate (which
/// checks every binary in the set) will see the stale alias and the pass declines to advance. If an
/// ALIAS replace does not land, the whole component is reported non-`Installed` for the same reason.
fn install_raw_binary_set(
    pc: &PlannedComponent,
    private: &Path,
    policy: &RetryPolicy,
) -> InstallOutcome {
    let primary = rename_into_place(private, &pc.dest, policy);
    if primary != InstallOutcome::Installed {
        return primary;
    }
    for alias in &pc.aliases {
        // Stage the alias's own verified copy beside it from the bytes just verified-and-placed at
        // the primary dest, then move it into place with the same running-target-safe swap.
        let alias_private = alias.with_extension(VERIFIED_RAW_EXT);
        if let Err(e) = copy_verified_bytes(&pc.dest, &alias_private) {
            return InstallOutcome::Failed {
                detail: format!(
                    "could not derive alias {} from the verified primary {}: {e}",
                    alias.display(),
                    pc.dest.display()
                ),
            };
        }
        match rename_into_place(&alias_private, alias, policy) {
            InstallOutcome::Installed => {}
            other => return other,
        }
    }
    InstallOutcome::Installed
}

/// Copy the verified bytes at `source` into the broker-private `dest_private` file (a sibling of an
/// alias destination), marking it executable. The source is the primary binary the caller has just
/// verified-and-installed, so the copied bytes are the verified bytes by construction.
fn copy_verified_bytes(source: &Path, dest_private: &Path) -> Result<(), BrokerError> {
    if let Some(parent) = dest_private.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BrokerError::Io(e.to_string()))?;
    }
    std::fs::copy(source, dest_private).map_err(|e| BrokerError::Io(e.to_string()))?;
    set_executable(dest_private)
}

/// Resiliently replace `dest` with the verified private copy, safe against a RUNNING/locked target
/// (#558, the same os-error-32/33 class as #544). This is the SINGLE raw-binary replace shared by
/// every ordinary component AND the beacon's OWN self-update ([`crate::selfupdate`]).
///
/// A running executable holds its own image open, so a direct rename ONTO `dest` fails with a
/// sharing/lock violation on Windows (32/33) and could hit ETXTBSY (26) on unix. The replace
/// therefore MOVES the existing target aside to a `.dig-updater-old` sibling first — permitted even
/// while it runs — then renames the verified copy into `dest`. Each rename retries the file-in-use
/// class with backoff; if the target stays locked through the budget the pass DEFERS (SPEC §9.5).
/// If the second rename fails, the moved-aside original is restored so `dest` is never left
/// half-written; the private copy is cleaned up on any give-up.
pub(crate) fn rename_into_place(
    private: &Path,
    dest: &Path,
    policy: &RetryPolicy,
) -> InstallOutcome {
    rename_into_place_with(private, dest, policy, retry_rename)
}

/// The [`rename_into_place`] body, with the rename primitive INJECTED so the rare double-rename-fault
/// branch — where placing the verified copy fails AND undoing the move-aside also fails — is
/// deterministically testable (a real filesystem makes that double fault practically impossible to
/// stage). Production passes [`retry_rename`]; the behaviour is otherwise identical.
fn rename_into_place_with(
    private: &Path,
    dest: &Path,
    policy: &RetryPolicy,
    rename: impl Fn(&RetryPolicy, &Path, &Path) -> std::io::Result<()>,
) -> InstallOutcome {
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            let _ = std::fs::remove_file(private);
            return InstallOutcome::Failed {
                detail: format!("could not create {}: {e}", parent.display()),
            };
        }
    }

    let superseded = dest.with_extension(SUPERSEDED_EXT);
    // Clear any `.old` a prior pass could not yet delete (it may have unlocked since); its lingering
    // presence is harmless either way.
    let _ = std::fs::remove_file(&superseded);

    // Move the (possibly-running) existing target aside so the verified copy can take its name — a
    // rename of a running image is allowed where an overwrite is not.
    let moved_aside = dest.exists();
    if moved_aside {
        if let Err(e) = rename(policy, dest, &superseded) {
            let _ = std::fs::remove_file(private);
            return InstallOutcome::Deferred {
                reason: format!("target {} locked after retries: {e}", dest.display()),
            };
        }
    }

    match rename(policy, private, dest) {
        Ok(()) => {
            // The old bytes are now ordinary (non-executing) content under the `.old` name and
            // usually delete cleanly; a still-locked one is left for a later pass to sweep.
            let _ = std::fs::remove_file(&superseded);
            InstallOutcome::Installed
        }
        Err(place_err) => {
            let _ = std::fs::remove_file(private);
            if !moved_aside {
                // No target was moved aside (a fresh install with no prior binary): `dest` was never
                // present, so there is nothing to leave missing — defer to the next pass.
                return InstallOutcome::Deferred {
                    reason: format!(
                        "could not place the new binary at {}: {place_err}",
                        dest.display()
                    ),
                };
            }
            // The move-aside DID happen, so `dest` is currently absent. Restore the original through
            // the SAME retried rename (not a swallowed one-shot) so `dest` is left byte-intact.
            match rename(policy, &superseded, dest) {
                Ok(()) => InstallOutcome::Deferred {
                    reason: format!(
                        "could not place the new binary at {}: {place_err}",
                        dest.display()
                    ),
                },
                // Double fault: the restore ALSO failed, so `dest` is missing. Escalate to Failed so
                // the caller's last-known-good rollback (SPEC §9.5) reinstates it — never a missing dest.
                Err(undo_err) => InstallOutcome::Failed {
                    detail: format!(
                        "could not place the new binary at {} ({place_err}) and restoring the \
                         original also failed ({undo_err}); dest left for the last-known-good rollback",
                        dest.display()
                    ),
                },
            }
        }
    }
}

/// Rename `from` → `to`, retrying ONLY the file-in-use class (Windows 32/33, unix ETXTBSY) with
/// `policy`'s backoff. A non-file-in-use error (e.g. a missing source directory) is terminal and
/// returns at once rather than burning the whole retry budget on an error that will never clear.
fn retry_rename(policy: &RetryPolicy, from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..policy.attempts.max(1) {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if is_file_in_use(&e) => {
                last = Some(e);
                if attempt + 1 < policy.attempts && !policy.backoff.is_zero() {
                    std::thread::sleep(policy.backoff * (attempt + 1));
                }
            }
            // A non-lock error will not clear by waiting — surface it immediately.
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no attempts made")))
}

/// Is `e` the "target file is in use by a running process" class the resilient replace retries +
/// defers on (#558)? Windows: ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33), or
/// ERROR_USER_MAPPED_FILE (1224) — a loaded/memory-mapped image cannot be overwritten/renamed-onto
/// while it runs, and a scanner/backup mapping the image raises 1224. Unix: ETXTBSY (26) — text file
/// busy. Ambiguous access errors (Windows ERROR_ACCESS_DENIED 5, unix EACCES 13) are deliberately
/// NOT in the class: they usually signal a permission/ownership fault that will not clear by waiting,
/// so they stay terminal rather than burning the retry budget.
fn is_file_in_use(e: &std::io::Error) -> bool {
    match e.raw_os_error() {
        #[cfg(windows)]
        Some(32 | 33 | 1224) => true,
        #[cfg(unix)]
        Some(26) => true,
        _ => false,
    }
}

/// Run a native installer over the verified private package copy, then remove that copy. `argv` is
/// the pre-resolved command whose program (index 0) is an ABSOLUTE, trusted installer path; an
/// unresolvable trusted installer is a `Failed` outcome (which the caller rolls back).
fn run_native_installer(private: &Path, argv: Result<Vec<String>, String>) -> InstallOutcome {
    let outcome = match argv {
        Ok(argv) => run_installer(&argv),
        Err(detail) => InstallOutcome::Failed {
            detail: format!("no trusted installer available: {detail}"),
        },
    };
    // The staged package copy is transient — the OS installer has read it (or we failed early).
    let _ = std::fs::remove_file(private);
    outcome
}

/// The silent-install argv for a Windows MSI, using the absolute `msiexec.exe`:
/// `<SystemRoot>\System32\msiexec.exe /i <pkg> /qn /norestart`.
///
/// # Errors
///
/// A detail string if a trusted absolute `msiexec.exe` cannot be resolved on this host.
pub fn msiexec_argv(pkg: &Path) -> Result<Vec<String>, String> {
    let program = msiexec_program()?;
    Ok(vec![
        program.display().to_string(),
        "/i".into(),
        pkg.display().to_string(),
        "/qn".into(),
        "/norestart".into(),
    ])
}

/// The silent-install argv for a macOS flat package, using the absolute `installer`:
/// `/usr/sbin/installer -pkg <pkg> -target /`.
///
/// # Errors
///
/// A detail string if the trusted absolute `installer` cannot be resolved on this host.
pub fn installer_argv(pkg: &Path) -> Result<Vec<String>, String> {
    let program = installer_program()?;
    Ok(vec![
        program.display().to_string(),
        "-pkg".into(),
        pkg.display().to_string(),
        "-target".into(),
        "/".into(),
    ])
}

/// The install argv for a Debian package, using the absolute `dpkg`: `/usr/bin/dpkg -i <pkg>`.
///
/// # Errors
///
/// A detail string if a trusted absolute `dpkg` cannot be resolved on this host.
pub fn dpkg_argv(pkg: &Path) -> Result<Vec<String>, String> {
    let program = dpkg_program()?;
    Ok(vec![
        program.display().to_string(),
        "-i".into(),
        pkg.display().to_string(),
    ])
}

/// Resolve the trusted absolute path to the Windows Installer (`%SystemRoot%\System32\msiexec.exe`).
/// Pinning the absolute path denies a `PATH`/CWD-planted `msiexec` root/SYSTEM code execution.
fn msiexec_program() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("windir"))
            .ok_or_else(|| "neither %SystemRoot% nor %windir% is set".to_string())?;
        trusted_absolute(
            PathBuf::from(system_root)
                .join("System32")
                .join("msiexec.exe"),
        )
    }
    #[cfg(not(windows))]
    {
        Err("msiexec is only available on Windows".to_string())
    }
}

/// Resolve the trusted absolute path to the macOS package installer (`/usr/sbin/installer`).
fn installer_program() -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        trusted_absolute(PathBuf::from("/usr/sbin/installer"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("the flat-package installer is only available on macOS".to_string())
    }
}

/// Resolve a trusted absolute path to `dpkg` (`/usr/bin/dpkg`, falling back to `/bin/dpkg`).
fn dpkg_program() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    {
        first_trusted(&["/usr/bin/dpkg", "/bin/dpkg"])
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("dpkg is only available on Linux".to_string())
    }
}

/// Return `path` iff it is absolute and names an existing regular file — otherwise reject it, so a
/// missing/relocated system installer never silently falls through to a `PATH` search.
///
/// `pub(crate)`: [`crate::scheduler`] reuses this to resolve `schtasks.exe`/`systemctl`/
/// `launchctl` by absolute path too — the same "never a bare name resolved through `PATH`"
/// discipline this module applies to `msiexec`/`installer`/`dpkg`.
#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) fn trusted_absolute(path: PathBuf) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(path),
        Ok(_) => Err(format!("{} is not a regular file", path.display())),
        Err(e) => Err(format!(
            "trusted installer not found at {}: {e}",
            path.display()
        )),
    }
}

/// The first of `candidates` that passes [`trusted_absolute`], or an error listing them all.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn first_trusted(candidates: &[&str]) -> Result<PathBuf, String> {
    for candidate in candidates {
        if let Ok(path) = trusted_absolute(PathBuf::from(candidate)) {
            return Ok(path);
        }
    }
    Err(format!(
        "no trusted installer found at any of: {}",
        candidates.join(", ")
    ))
}

/// Run a native installer argv (absolute program at index 0), mapping its exit status to an outcome.
fn run_installer(argv: &[String]) -> InstallOutcome {
    let Some((program, args)) = argv.split_first() else {
        return InstallOutcome::Failed {
            detail: "empty install command".to_string(),
        };
    };
    match Command::new(program).args(args).hide_console().status() {
        Ok(status) if status.success() => InstallOutcome::Installed,
        Ok(status) => InstallOutcome::Failed {
            detail: format!("{program} exited with {status}"),
        },
        Err(e) => InstallOutcome::Failed {
            detail: format!("could not run {program}: {e}"),
        },
    }
}

/// Mark `path` executable (`0755`) on Unix; a no-op elsewhere.
fn set_executable(path: &Path) -> Result<(), BrokerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| BrokerError::Io(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::InstallMethod;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn planned(dest: PathBuf, method: InstallMethod, digest: &str) -> PlannedComponent {
        PlannedComponent {
            name: "digstore".into(),
            method,
            dest,
            aliases: vec![],
            version: "0.15.0".into(),
            build: 15_000,
            expected_digest: digest.into(),
            staged_path: PathBuf::new(),
            action: dig_release_resolver::UpdateAction::Install,
            summary: String::new(),
            installed_build: None,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // -- staged-path containment (fix: worker-supplied path must stay inside staging) ----------

    #[test]
    fn a_staged_path_inside_staging_is_accepted() {
        let staging = tempfile::tempdir().unwrap();
        let staged = staging.path().join("artifact");
        std::fs::write(&staged, b"bytes").unwrap();
        let resolved = contained_staged_path(&staged, staging.path(), "digstore").unwrap();
        assert!(resolved.starts_with(staging.path().canonicalize().unwrap()));
    }

    #[test]
    fn a_staged_path_outside_staging_is_rejected() {
        let staging = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let evil = elsewhere.path().join("evil");
        std::fs::write(&evil, b"malicious").unwrap();
        // A worker pointing the broker at a file OUTSIDE its staging dir (e.g. /tmp/evil).
        let err = contained_staged_path(&evil, staging.path(), "digstore")
            .expect_err("a path outside staging must be refused");
        assert!(matches!(err, BrokerError::StagedPathEscapesStaging { .. }));
    }

    #[test]
    fn a_dotdot_escape_from_staging_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"malicious").unwrap();
        // `<staging>/../outside` resolves out of the staging dir and must be refused.
        let escape = staging.join("..").join("outside");
        let err = contained_staged_path(&escape, &staging, "digstore")
            .expect_err("a `..` escape must be refused");
        assert!(matches!(err, BrokerError::StagedPathEscapesStaging { .. }));
    }

    // -- stage_and_verify_private (the copy == hash == install gate) ----------------------------

    #[test]
    fn verify_accepts_matching_bytes_and_leaves_the_private_copy() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"artifact").unwrap();
        let private = dir.path().join("dest.dig-updater-verified");
        let digest = hex(&Sha256::digest(b"artifact"));
        stage_and_verify_private(&staged, &private, &digest, "digstore", true).unwrap();
        assert_eq!(std::fs::read(&private).unwrap(), b"artifact");
    }

    #[test]
    fn verify_rejects_swapped_bytes_and_removes_the_private_copy() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        // The digest commits to "honest", but the staged file holds "evil" (a lying worker).
        std::fs::write(&staged, b"evil").unwrap();
        let private = dir.path().join("dest.dig-updater-verified");
        let digest = hex(&Sha256::digest(b"honest"));
        let err = stage_and_verify_private(&staged, &private, &digest, "digstore", true)
            .expect_err("swapped bytes must be rejected");
        assert!(matches!(err, BrokerError::StagingReverifyFailed { .. }));
        assert!(
            !private.exists(),
            "a failed verify leaves nothing installable"
        );
    }

    /// The heart of the TOCTOU fix: once the private copy is verified, mutating the STAGING file has
    /// NO effect on what is installed — the install reads the private copy, so installed == hashed.
    #[test]
    fn a_swap_of_staging_after_verify_does_not_change_the_installed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let honest = b"the-honest-verified-bytes";
        std::fs::write(&staged, honest).unwrap();

        let dest = dir.path().join("bin").join("digstore");
        let digest = hex(&Sha256::digest(honest));
        let pc = planned(dest.clone(), InstallMethod::RawBinary, &digest);
        let private = private_target(&pc, dir.path());

        // Verify + copy the honest bytes into the broker-private file.
        stage_and_verify_private(&staged, &private, &digest, "digstore", true).unwrap();

        // A compromised worker now swaps the STAGING bytes — after the hash, before the install.
        std::fs::write(&staged, b"malicious-substituted-bytes").unwrap();

        // The install reads the PRIVATE copy, so the swap has no effect: installed == verified.
        let outcome = install_from_private(
            &pc,
            &private,
            &RetryPolicy {
                attempts: 2,
                backoff: Duration::ZERO,
            },
        );
        assert_eq!(outcome, InstallOutcome::Installed);
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            honest,
            "installed bytes are the hashed bytes, not the post-hash swap"
        );
    }

    // -- raw-binary install-from-private --------------------------------------------------------

    #[test]
    fn install_from_private_renames_the_verified_copy_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("bin").join("digstore");
        let pc = planned(dest.clone(), InstallMethod::RawBinary, "unused-here");
        let private = private_target(&pc, dir.path());
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&private, b"new-binary-bytes").unwrap();

        let outcome = install_from_private(&pc, &private, &RetryPolicy::default());
        assert_eq!(outcome, InstallOutcome::Installed);
        assert_eq!(std::fs::read(&dest).unwrap(), b"new-binary-bytes");
        assert!(
            !private.exists(),
            "the private copy is renamed away, not left behind"
        );
    }

    /// #666 Bug A: a raw-binary component with aliases refreshes EVERY alias from the VERIFIED
    /// bytes just placed at the primary — never a re-fetch — so an alias can never diverge.
    #[test]
    fn install_refreshes_every_alias_from_the_verified_primary_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let primary = bin.join("dig-dns");
        let alias_a = bin.join("digd");
        let alias_b = bin.join("digd2");
        std::fs::write(&primary, b"old").unwrap();
        std::fs::write(&alias_a, b"old").unwrap();
        std::fs::write(&alias_b, b"old").unwrap();

        let new_bytes = b"new-verified-0.14.0";
        let mut pc = planned(primary.clone(), InstallMethod::RawBinary, "unused");
        pc.aliases = vec![alias_a.clone(), alias_b.clone()];
        let private = private_target(&pc, dir.path());
        std::fs::write(&private, new_bytes).unwrap();

        assert_eq!(
            install_from_private(&pc, &private, &RetryPolicy::default()),
            InstallOutcome::Installed
        );
        for p in [&primary, &alias_a, &alias_b] {
            assert_eq!(std::fs::read(p).unwrap(), new_bytes, "{p:?} refreshed");
        }
    }

    #[test]
    fn private_target_is_a_dest_sibling_for_raw_binaries() {
        let pc = planned(
            PathBuf::from("/opt/dig/digstore"),
            InstallMethod::RawBinary,
            "d",
        );
        let private = private_target(&pc, Path::new("/var/lib/dig-updater/apply"));
        assert_eq!(
            private,
            PathBuf::from("/opt/dig/digstore.dig-updater-verified"),
            "a raw binary stages beside its dest for an atomic rename"
        );
    }

    #[test]
    fn private_target_is_in_the_apply_dir_for_packages() {
        let pc = planned(
            PathBuf::from("/usr/local/bin/dig-node"),
            InstallMethod::LinuxDeb,
            "d",
        );
        let private = private_target(&pc, Path::new("/var/lib/dig-updater/apply"));
        assert_eq!(
            private,
            PathBuf::from("/var/lib/dig-updater/apply/digstore.deb")
        );
    }

    // -- native-package install-from-private (cross-platform, no real system installer) --------

    #[test]
    fn run_native_installer_maps_an_unresolvable_installer_to_failed_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("dig-node.deb");
        std::fs::write(&private, b"package-bytes").unwrap();
        // No trusted installer could be resolved for this OS.
        let outcome = run_native_installer(&private, Err("no trusted dpkg".to_string()));
        assert!(matches!(outcome, InstallOutcome::Failed { .. }));
        assert!(!private.exists(), "the transient package copy is removed");
    }

    #[test]
    fn run_native_installer_runs_the_resolved_program_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("dig-node.deb");
        std::fs::write(&private, b"package-bytes").unwrap();
        // A resolved-but-bogus absolute program: run_installer reports Failed, and either way the
        // transient package copy is cleaned up.
        let argv = Ok(vec![
            "/definitely/not/a/real/installer-xyz".to_string(),
            "-i".to_string(),
            private.display().to_string(),
        ]);
        let outcome = run_native_installer(&private, argv);
        assert!(matches!(outcome, InstallOutcome::Failed { .. }));
        assert!(!private.exists(), "the transient package copy is removed");
    }

    #[test]
    fn install_from_private_dispatches_a_package_method_through_the_native_installer() {
        // A package method routes to the native-installer path. We assert it does NOT rename into
        // place (that is the raw-binary path) — the dest is never touched by the package arm here.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-node");
        let pc = planned(dest.clone(), InstallMethod::LinuxDeb, "unused");
        let private = dir.path().join("dig-node.deb");
        std::fs::write(&private, b"not-a-real-deb").unwrap();
        // On a non-Linux host dpkg cannot be resolved → Failed; on Linux dpkg rejects the bogus
        // package → Failed. Either way the raw-binary dest is never created by this arm.
        let outcome = install_from_private(&pc, &private, &RetryPolicy::default());
        assert!(matches!(outcome, InstallOutcome::Failed { .. }));
        assert!(
            !dest.exists(),
            "a package install never renames into the raw-binary dest"
        );
    }

    // -- native-installer argv: an ABSOLUTE, trusted program (never a bare name) ----------------

    #[test]
    fn trusted_absolute_rejects_a_relative_or_missing_program() {
        assert!(
            trusted_absolute(PathBuf::from("msiexec")).is_err(),
            "bare name refused"
        );
        assert!(
            trusted_absolute(PathBuf::from("/definitely/not/here/installer")).is_err(),
            "a missing absolute path is refused"
        );
    }

    #[test]
    fn trusted_absolute_accepts_an_existing_absolute_file() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("fake-installer");
        std::fs::write(&program, b"#!/bin/sh").unwrap();
        assert_eq!(trusted_absolute(program.clone()).unwrap(), program);
    }

    #[cfg(windows)]
    #[test]
    fn msiexec_resolves_to_an_absolute_system32_path() {
        let argv = msiexec_argv(Path::new(r"C:\apply\dig-node.msi")).expect("msiexec resolves");
        assert!(
            Path::new(&argv[0]).is_absolute(),
            "the installer program is an absolute path"
        );
        assert!(argv[0].to_lowercase().ends_with(r"system32\msiexec.exe"));
        assert!(argv.contains(&"/qn".to_string()) && argv.contains(&"/norestart".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dpkg_resolves_to_an_absolute_path_when_present() {
        // dpkg is present on the Debian/Ubuntu CI runner; if absent the resolution errors rather
        // than falling back to a bare-name PATH lookup.
        match dpkg_argv(Path::new("/var/lib/dig-updater/apply/dig-node.deb")) {
            Ok(argv) => {
                assert!(Path::new(&argv[0]).is_absolute());
                assert!(argv[0].ends_with("dpkg"));
                assert_eq!(argv[1], "-i");
            }
            Err(detail) => assert!(detail.contains("dpkg")),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn installer_resolves_to_the_absolute_usr_sbin_path() {
        let argv = installer_argv(Path::new("/var/lib/dig-updater/apply/dig-node.pkg"))
            .expect("installer");
        assert_eq!(argv[0], "/usr/sbin/installer");
        assert!(argv.contains(&"-pkg".to_string()));
    }

    // -- retry_rename (deterministic, zero backoff) ---------------------------------------------

    #[test]
    fn retry_rename_places_a_file_when_the_target_is_free() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("from");
        let to = dir.path().join("to");
        std::fs::write(&from, b"bytes").unwrap();
        retry_rename(
            &RetryPolicy {
                attempts: 3,
                backoff: Duration::ZERO,
            },
            &from,
            &to,
        )
        .expect("a free target renames on the first try");
        assert_eq!(std::fs::read(&to).unwrap(), b"bytes");
        assert!(!from.exists());
    }

    #[test]
    fn retry_rename_fails_fast_on_a_terminal_non_lock_error() {
        // A missing SOURCE is a terminal error (NotFound), not the file-in-use class — it must
        // return at once, not burn the whole retry budget waiting for a lock that will never clear.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-source");
        let to = dir.path().join("to");
        let err = retry_rename(
            &RetryPolicy {
                attempts: 5,
                backoff: Duration::from_secs(30), // would hang for minutes if it retried
            },
            &missing,
            &to,
        )
        .expect_err("a missing source is terminal");
        assert!(
            !is_file_in_use(&err),
            "a NotFound is not the file-in-use class"
        );
    }

    #[test]
    fn run_installer_reports_a_missing_program_as_failed() {
        let outcome = run_installer(&[
            "/definitely-not-a-real-installer-binary-xyz".to_string(),
            "-x".to_string(),
        ]);
        assert!(matches!(outcome, InstallOutcome::Failed { .. }));
    }

    // -- #558: resilient replace-a-running-binary (os error 32/33 class, same as #544) ----------

    /// #558: the file-in-use classification MUST cover BOTH Windows sharing-violation arms
    /// (ERROR_SHARING_VIOLATION 32 AND ERROR_LOCK_VIOLATION 33) and the unix ETXTBSY (26) arm — the
    /// error class a running/locked target raises, which the replace must retry + resiliently handle
    /// rather than fail hard on.
    #[test]
    fn file_in_use_covers_both_windows_arms_and_unix_etxtbsy_558() {
        #[cfg(windows)]
        {
            assert!(is_file_in_use(&std::io::Error::from_raw_os_error(32)));
            assert!(is_file_in_use(&std::io::Error::from_raw_os_error(33)));
            assert!(is_file_in_use(&std::io::Error::from_raw_os_error(1224))); // ERROR_USER_MAPPED_FILE
            assert!(!is_file_in_use(&std::io::Error::from_raw_os_error(5))); // ACCESS_DENIED stays terminal
        }
        #[cfg(unix)]
        {
            assert!(is_file_in_use(&std::io::Error::from_raw_os_error(26))); // ETXTBSY
            assert!(!is_file_in_use(&std::io::Error::from_raw_os_error(13))); // EACCES stays terminal
        }
    }

    /// #558 (the bug repro, same os-error-32 class as #544): a locked/in-use target — a running
    /// service (e.g. dig-dns) holding its own image — makes a rename onto it fail with the file-in-use
    /// class (Windows ERROR_SHARING_VIOLATION 32 / ERROR_LOCK_VIOLATION 33). The resilient replace
    /// MUST NOT fail hard on that class: it retries, then DEFERS to the next pass (SPEC §9.5),
    /// leaving the ORIGINAL target byte-intact (never a half-write) and cleaning up the private copy.
    #[cfg(windows)]
    #[test]
    fn a_locked_target_defers_cleanly_with_no_half_write_558() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-dns.exe");
        std::fs::write(&dest, b"original-running-bytes").unwrap();
        let private = dest.with_extension(VERIFIED_RAW_EXT);
        std::fs::write(&private, b"new-verified-bytes").unwrap();

        // Hold the target open FILE_SHARE_READ but WITHOUT share-delete — the way a scanner/backup
        // (or an older loader) holds a file in use. Moving such a target aside fails with
        // ERROR_SHARING_VIOLATION (32), the exact #544 class the resilient replace retries + defers.
        let _locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001) // FILE_SHARE_READ only
            .open(&dest)
            .expect("open the target held in use without share-delete");

        // The resilient replace retries the lock, then defers — never a hard failure, never a
        // half-write: the original is untouched and the private copy is cleaned up.
        let outcome = rename_into_place(
            &private,
            &dest,
            &RetryPolicy {
                attempts: 3,
                backoff: Duration::ZERO,
            },
        );
        assert!(
            matches!(outcome, InstallOutcome::Deferred { .. }),
            "a locked target defers to the next pass, got {outcome:?}"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"original-running-bytes",
            "a deferred replace leaves the original target byte-intact"
        );
        assert!(
            !dest.with_extension(SUPERSEDED_EXT).exists(),
            "no orphan .old sibling is left after a deferred swap"
        );
        assert!(!private.exists(), "the private copy is cleaned up on defer");
    }

    /// #558: the no-half-write invariant on the move-aside path — if the SECOND rename (placing the
    /// verified copy) fails after the existing target was already moved aside, the swap MUST undo
    /// itself so `dest` is left with its original bytes, never missing. Simulated by pointing
    /// `private` at a non-existent source so the second rename cannot succeed. Cross-platform: the
    /// move-aside runs on every OS.
    #[test]
    fn a_failed_second_rename_restores_the_original_target_no_half_write_558() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("dig-dns");
        std::fs::write(&dest, b"original-bytes").unwrap();
        let private = dir
            .path()
            .join("no-such-dir")
            .join("dig-dns.dig-updater-verified");

        let outcome = rename_into_place(
            &private,
            &dest,
            &RetryPolicy {
                attempts: 2,
                backoff: Duration::ZERO,
            },
        );
        assert!(matches!(outcome, InstallOutcome::Deferred { .. }));
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"original-bytes",
            "a failed second rename must restore the original target, never leave it missing"
        );
        assert!(
            !dest.with_extension(SUPERSEDED_EXT).exists(),
            "no orphan .old sibling is left after the swap is undone"
        );
    }

    /// #558 (the adversarial double-fault gap): if the target was moved aside, the second rename
    /// fails, AND the undo (restoring the original) ALSO fails, `dest` is genuinely left MISSING. The
    /// replace MUST then return `Failed` (not `Deferred`) so the caller's last-known-good rollback
    /// fires and restores `dest` — proving the SPEC §9.5 invariant "dest is never left missing" holds
    /// on EVERY branch. The rename primitive is injected to stage the double fault deterministically:
    /// the move-aside runs for real, then every rename whose TARGET is `dest` is forced to fail.
    #[test]
    fn a_double_rename_fault_escalates_to_failed_and_the_lkg_rollback_restores_dest_558() {
        use crate::rollback::LkgCache;

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("bin").join("dig-dns");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"original-running-bytes").unwrap();

        // The pass snapshots the good original BEFORE the replace — this is the LKG rollback source.
        let lkg = LkgCache::at(dir.path().join("lkg"));
        let snapshot = lkg
            .snapshot("dig-dns", &dest, Some(15_000))
            .unwrap()
            .expect("the original target is snapshotted");

        let private = dest.with_extension(VERIFIED_RAW_EXT);
        std::fs::write(&private, b"new-verified-bytes").unwrap();

        // Move-aside (dest -> .old) runs for real; placing at dest AND the undo (.old -> dest) both
        // fail — a double fault that leaves dest missing.
        let policy = RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        };
        let target = dest.clone();
        let outcome = rename_into_place_with(&private, &dest, &policy, |_policy, from, to| {
            if to == target.as_path() {
                Err(std::io::Error::other("injected: cannot place at dest"))
            } else {
                std::fs::rename(from, to)
            }
        });

        assert!(
            matches!(outcome, InstallOutcome::Failed { .. }),
            "a double rename fault (place + undo both fail) must escalate to Failed, got {outcome:?}"
        );
        assert!(
            !dest.exists(),
            "the double fault genuinely leaves dest missing until the rollback runs"
        );

        // The caller's LKG rollback (fires on Failed) reinstates dest — so it is never left missing.
        // The pass restores the just-captured snapshot in-place (floor-exempt, RestoreKind::InPlace).
        lkg.restore(&snapshot, 0, crate::rollback::RestoreKind::InPlace)
            .expect("the last-known-good rollback restores dest on Failed");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"original-running-bytes",
            "dest is restored to its original bytes — never left missing on any branch"
        );
    }

    /// #558 (round 2): the SAME double-rename fault when the prior build is UN-AGEABLE
    /// (`installed_build == None` — a malformed-date nightly / unparseable core, `plan.rs::pack_build`
    /// returns None). The in-pass rollback MUST still restore dest — the floor gate is bypassed for a
    /// restore-in-place, so dest is never left missing regardless of ageability.
    #[test]
    fn a_double_rename_fault_with_an_unageable_build_still_rolls_back_dest_558() {
        use crate::rollback::{LkgCache, RestoreKind};

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("bin").join("dig-dns");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"original-running-bytes").unwrap();

        // The prior build's version is un-ageable → snapshot records build = None.
        let lkg = LkgCache::at(dir.path().join("lkg"));
        let snapshot = lkg
            .snapshot("dig-dns", &dest, None)
            .unwrap()
            .expect("the original target is snapshotted");

        let private = dest.with_extension(VERIFIED_RAW_EXT);
        std::fs::write(&private, b"new-verified-bytes").unwrap();

        let policy = RetryPolicy {
            attempts: 2,
            backoff: Duration::ZERO,
        };
        let target = dest.clone();
        let outcome = rename_into_place_with(&private, &dest, &policy, |_policy, from, to| {
            if to == target.as_path() {
                Err(std::io::Error::other("injected: cannot place at dest"))
            } else {
                std::fs::rename(from, to)
            }
        });

        assert!(
            matches!(outcome, InstallOutcome::Failed { .. }),
            "a double rename fault must escalate to Failed, got {outcome:?}"
        );
        assert!(!dest.exists(), "the double fault leaves dest missing");

        // Even with an un-ageable prior build, the in-pass restore-in-place reinstates dest under a
        // high floor — the round-1 gap where the None arm refused BEFORE writing dest is closed.
        lkg.restore(&snapshot, 10_000, RestoreKind::InPlace)
            .expect("an un-ageable in-pass snapshot is still restored (floor-exempt)");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"original-running-bytes",
            "dest is restored even when the prior build was un-ageable — never left missing"
        );
    }
}
