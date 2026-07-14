//! Whether THIS process currently holds the privilege to reconfigure how the beacon behaves.
//!
//! Two surfaces share the exact same bar: registering the daily [`crate::scheduler`] artifact
//! (a SYSTEM/root-run schedule) and mutating the persisted [`crate::config`] (the update channel,
//! pause/resume) — both are "change how this machine auto-updates itself", a privileged act on
//! every platform this beacon ships to. Centralizing the OS probe here means the two callers can
//! never drift onto two different definitions of "elevated".
//!
//! - **Windows:** `net session` only succeeds from an ELEVATED (UAC) console — being a member of
//!   the Administrators group is not enough on its own.
//! - **Unix:** the effective uid is `0` (root).

use crate::error::BrokerError;

/// Why [`require`]/[`require_elevated`] refuses an unprivileged caller.
const NOT_ELEVATED_DETAIL: &str = "this operation reconfigures the beacon's SYSTEM/root-run \
    schedule or update behavior and requires an elevated (Administrator) console or root";

/// Require the CURRENT process to be elevated, using the real OS probe ([`is_elevated`]).
///
/// # Errors
///
/// [`BrokerError::Io`] if the calling process is not Administrator/root.
pub fn require_elevated() -> Result<(), BrokerError> {
    require(is_elevated)
}

/// Require elevation, given an injectable `is_elevated` check. Production calls
/// [`require_elevated`] (the real OS probe); tests inject `|| true` / `|| false` so both branches
/// are exercised deterministically regardless of the ACTUAL privilege of the `cargo test`
/// process, which varies across CI images (see the module doc).
///
/// # Errors
///
/// [`BrokerError::Io`] if `is_elevated()` returns `false`.
pub fn require(is_elevated: impl FnOnce() -> bool) -> Result<(), BrokerError> {
    if is_elevated() {
        Ok(())
    } else {
        Err(BrokerError::Io(NOT_ELEVATED_DETAIL.to_string()))
    }
}

/// Is this process elevated (Administrator on Windows, root on Unix) right now?
#[cfg(windows)]
#[must_use]
pub fn is_elevated() -> bool {
    use crate::proc::HideConsole;
    use std::process::{Command, Stdio};

    // `net session` succeeds only from an elevated console — the same probe dig-relay's and
    // dig-dns's own service registration use, so every DIG service-registering CLI fails the same
    // way for the same reason. Resolved by absolute, trusted path (never a bare name through
    // `PATH`), matching every other native-tool invocation in this crate.
    let Some(system_root) = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("windir"))
    else {
        return false;
    };
    let net_exe = std::path::PathBuf::from(system_root)
        .join("System32")
        .join("net.exe");
    let Ok(net_exe) = crate::install::trusted_absolute(net_exe) else {
        return false;
    };
    Command::new(net_exe)
        .arg("session")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .hide_console()
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Is this process elevated (Administrator on Windows, root on Unix) right now?
#[cfg(unix)]
#[must_use]
pub fn is_elevated() -> bool {
    // SAFETY: `geteuid` has no preconditions and is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

/// Is this process elevated (Administrator on Windows, root on Unix) right now?
#[cfg(not(any(windows, unix)))]
#[must_use]
pub fn is_elevated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_ok_when_the_injected_check_reports_elevated() {
        require(|| true).expect("an elevated check must be accepted");
    }

    #[test]
    fn require_fails_cleanly_when_the_injected_check_reports_unprivileged() {
        let err = require(|| false).expect_err("an unprivileged check must be refused");
        assert!(matches!(err, BrokerError::Io(_)));
        assert!(err.to_string().contains("elevated"));
    }
}
