//! The post-install health gate (SPEC §9.5).
//!
//! After an artifact is applied, the broker probes the component and only lets the pass advance
//! the trust state if the probe passes; otherwise it rolls the component back. The alpha probe is
//! a **version match**: the binary now on disk must report the version the manifest promised.
//! Reusing the shared decision matrix keeps this honest — a HEALTHY install is precisely one the
//! resolver would now judge [`UpdateAction::Skip`] (already current), so a mismatched or missing
//! binary (which the resolver would judge Install/Update) fails the gate.
//!
//! A richer per-component liveness probe (for a service component like dig-node: the service is
//! running and answering) layers on top of this in the service-management ticket (#504-F/-H); the
//! version match is the cross-platform floor every component shares.

use std::path::Path;

use dig_release_resolver::{decide, DetectedVersion, UpdateAction};

/// A version probe: given an installed binary's path, report what version it is. Production passes
/// [`dig_release_resolver::detect_installed_version`] (which spawns `<path> --version`); tests pass
/// a scripted probe so the gate's PASS and FAIL branches are both exercised deterministically.
pub type VersionProbe<'a> = dyn Fn(&Path) -> DetectedVersion + 'a;

/// Health-gate a just-installed component: the binary at `dest` must now report `expected_version`.
///
/// # Errors
///
/// A human-readable detail string if the binary is absent or reports a version other than
/// `expected_version` — the caller turns this into a rollback.
pub fn check_health(
    dest: &Path,
    expected_version: &str,
    probe: &VersionProbe,
) -> Result<(), String> {
    let detected = probe(dest);
    if matches!(detected, DetectedVersion::Absent) {
        return Err(format!("nothing installed at {}", dest.display()));
    }
    let decision = decide(&detected, expected_version);
    if decision.action == UpdateAction::Skip {
        Ok(())
    } else {
        Err(format!(
            "post-install version check failed: {}",
            decision.summary
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dest() -> PathBuf {
        PathBuf::from("/opt/dig/digstore")
    }

    #[test]
    fn matching_version_is_healthy() {
        let probe = |_: &Path| DetectedVersion::Present("digstore 0.15.0".to_string());
        assert!(check_health(&dest(), "0.15.0", &probe).is_ok());
    }

    #[test]
    fn wrong_version_is_unhealthy() {
        // The install "succeeded" but the binary still reports the OLD version — a silent failure
        // the health gate must catch (and the caller then rolls back).
        let probe = |_: &Path| DetectedVersion::Present("digstore 0.14.0".to_string());
        let err =
            check_health(&dest(), "0.15.0", &probe).expect_err("version mismatch is unhealthy");
        assert!(err.contains("version check"));
    }

    #[test]
    fn absent_binary_is_unhealthy() {
        let probe = |_: &Path| DetectedVersion::Absent;
        let err = check_health(&dest(), "0.15.0", &probe).expect_err("absent is unhealthy");
        assert!(err.contains("nothing installed"));
    }

    #[test]
    fn unreadable_version_is_unhealthy() {
        // The binary exists but `--version` produced nothing usable — treated as unhealthy
        // (the resolver would want to reinstall), so the gate fails and the component rolls back.
        let probe = |_: &Path| DetectedVersion::Present(String::new());
        assert!(check_health(&dest(), "0.15.0", &probe).is_err());
    }
}
