//! Whether THIS process currently holds the privilege to reconfigure how the beacon behaves.
//!
//! Two surfaces share the exact same bar: registering the daily [`crate::scheduler`] artifact
//! (a SYSTEM/root-run schedule) and mutating the persisted [`crate::config`] (the update channel,
//! pause/resume) — both are "change how this machine auto-updates itself", a privileged act on
//! every platform this beacon ships to. Centralizing the OS probe here means the two callers can
//! never drift onto two different definitions of "elevated".
//!
//! - **Windows:** the process token reports elevated (`GetTokenInformation`/`TokenElevation`) —
//!   i.e. the actual UAC elevation state, which is true only from an elevated (Administrator)
//!   context, NOT merely from membership in the Administrators group.
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
///
/// Windows: reads the process token's ACTUAL elevation state via `GetTokenInformation` with
/// `TokenElevation`. This replaces the previous `net session` probe (#546), which shelled out to
/// `net.exe` and returned a FALSE NEGATIVE whenever the Server (`LanmanServer`) service was stopped
/// — reporting "not elevated" even from a genuinely elevated console, which then wrongly blocked
/// the scheduler's own (privileged) registration. The token query has no such external dependency:
/// it asks the OS directly whether THIS token is elevated.
#[cfg(windows)]
#[must_use]
pub fn is_elevated() -> bool {
    use std::ffi::c_void;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: all four calls are FFI into documented, always-available Win32 token APIs.
    // - `GetCurrentProcess` returns a pseudo-handle that need not (and must not) be closed.
    // - `OpenProcessToken` fills `token` with an owned handle ONLY on success (`Ok`); we close it
    //   exactly once on every path out (success or query failure) and never use it after.
    // - `GetTokenInformation` writes into `elevation`, a fully-initialized stack `TOKEN_ELEVATION`
    //   whose size we pass, so there is no uninitialized read and no buffer-length mismatch.
    // On ANY failure we conservatively report "not elevated" (fail-closed), never leaking the token.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let query = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        query.is_ok() && elevation.TokenIsElevated != 0
    }
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

    /// The real token probe must run soundly (no panic, no handle leak, no crash) and return a
    /// definite boolean — we can't assert WHICH value on an arbitrary CI runner, only that the FFI
    /// path is exercised end-to-end. Its correctness vs the old `net session` probe is the #546 fix.
    #[cfg(windows)]
    #[test]
    fn is_elevated_token_probe_runs_soundly_and_is_stable() {
        // We can't assert WHICH value on an arbitrary runner, only that the token-query FFI path
        // runs end-to-end without panicking/leaking and is a pure, repeatable query (the same
        // process token yields the same answer). Its correctness vs the old `net session` probe —
        // no dependency on the Server service — is the #546 fix.
        assert_eq!(
            is_elevated(),
            is_elevated(),
            "the elevation probe is a stable, side-effect-free query"
        );
    }
}
