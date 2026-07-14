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
//! (`msiexec /qn`, `installer -pkg`, `dpkg -i`); a raw binary is replaced in place, retrying a
//! locked target with backoff and DEFERRING to the next pass rather than failing hard (e.g. Windows
//! holds the beacon's own image open).

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
        InstallMethod::RawBinary => rename_into_place(private, &pc.dest, policy),
        InstallMethod::WindowsMsi => run_native_installer(private, msiexec_argv(private)),
        InstallMethod::MacosPkg => run_native_installer(private, installer_argv(private)),
        InstallMethod::LinuxDeb => run_native_installer(private, dpkg_argv(private)),
    }
}

/// Atomically move the verified private copy over `dest`, retrying a locked rename with backoff and
/// DEFERRING if the target stays locked (SPEC §9.5). On give-up the private copy is cleaned up.
///
/// `pub(crate)`: [`crate::selfupdate`] reuses this verbatim for the beacon's OWN Unix self-update
/// — on Unix there is nothing self-replace-specific to do, replacing a running executable's
/// directory entry works exactly like any other raw-binary component (see that module's doc).
pub(crate) fn rename_into_place(
    private: &Path,
    dest: &Path,
    policy: &RetryPolicy,
) -> InstallOutcome {
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            let _ = std::fs::remove_file(private);
            return InstallOutcome::Failed {
                detail: format!("could not create {}: {e}", parent.display()),
            };
        }
    }
    match retry(policy, || std::fs::rename(private, dest)) {
        Ok(()) => InstallOutcome::Installed,
        Err(e) => {
            // The target stayed locked through the whole budget — leave it for the next pass.
            let _ = std::fs::remove_file(private);
            InstallOutcome::Deferred {
                reason: format!("target {} locked after retries: {e}", dest.display()),
            }
        }
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

/// Run `op`, retrying up to `policy.attempts` times with linear backoff. Returns the last error if
/// every attempt fails.
fn retry<T>(
    policy: &RetryPolicy,
    mut op: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..policy.attempts.max(1) {
        match op() {
            Ok(v) => return Ok(v),
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
    use crate::plan::InstallMethod;
    use sha2::{Digest, Sha256};
    use std::cell::Cell;
    use std::path::PathBuf;

    fn planned(dest: PathBuf, method: InstallMethod, digest: &str) -> PlannedComponent {
        PlannedComponent {
            name: "digstore".into(),
            method,
            dest,
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

    // -- the retry loop (deterministic, zero backoff) -------------------------------------------

    #[test]
    fn retry_succeeds_after_transient_failures() {
        let policy = RetryPolicy {
            attempts: 5,
            backoff: Duration::ZERO,
        };
        let calls = Cell::new(0u32);
        let result = retry(&policy, || {
            let n = calls.get() + 1;
            calls.set(n);
            if n < 3 {
                Err(std::io::Error::other("locked"))
            } else {
                Ok(n)
            }
        });
        assert_eq!(result.unwrap(), 3);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn retry_gives_up_after_the_budget() {
        let policy = RetryPolicy {
            attempts: 3,
            backoff: Duration::ZERO,
        };
        let calls = Cell::new(0u32);
        let result: std::io::Result<()> = retry(&policy, || {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other("always locked"))
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 3, "exactly `attempts` tries");
    }

    #[test]
    fn run_installer_reports_a_missing_program_as_failed() {
        let outcome = run_installer(&[
            "/definitely-not-a-real-installer-binary-xyz".to_string(),
            "-x".to_string(),
        ]);
        assert!(matches!(outcome, InstallOutcome::Failed { .. }));
    }
}
