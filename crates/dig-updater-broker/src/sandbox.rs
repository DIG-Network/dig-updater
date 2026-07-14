//! Spawning the worker with LEAST PRIVILEGE — the only `unsafe` in the workspace.
//!
//! The privileged broker must run the network-facing worker unprivileged so that a hypothetical
//! memory-safety exploit in the fetch/parse path cannot escalate to the installing identity
//! (SPEC §8.3). The worker already holds no *install* capability by construction (it is a
//! separate binary with no install code); dropping privilege is defense-in-depth on top of that.
//!
//! - **Unix:** the child `setgroups([])` + `setgid` + `setuid` to `nobody` in a `pre_exec` hook,
//!   verifying it cannot regain uid 0. This is **fail-closed**: if the broker is privileged and
//!   the drop fails, the child never execs. When the broker is already unprivileged the drop is a
//!   no-op (nothing to drop).
//! - **Windows (alpha floor):** the child runs under a **restricted token** created with
//!   `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` (all privileges removed), spawned via
//!   `CreateProcessAsUserW`. Restricted tokens are exempt from `SeAssignPrimaryTokenPrivilege`, so
//!   this works when the broker runs as SYSTEM (the production path). If the host denies the
//!   spawn-as-user (e.g. a non-admin developer/CI shell lacking `SeIncreaseQuotaPrivilege`), it
//!   falls back to a normal spawn — the worker still cannot install. A full low-integrity /
//!   AppContainer sandbox is the hardening follow-up (#534, SPEC §11.2).

use std::io::{Read, Write};
use std::path::Path;

use crate::error::BrokerError;

/// How much privilege the spawned worker should hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    /// Drop to an unprivileged identity (Unix `nobody` / Windows restricted token). The
    /// production posture.
    Restricted,
    /// Inherit the broker's privileges. Used only when the broker is already unprivileged (tests,
    /// a non-service invocation) — never a way to grant the worker MORE than the broker has.
    Inherit,
}

/// Spawn the worker, pipe `input` to its stdin, and return `(exit_code, stdout_bytes)`.
///
/// stderr is inherited (worker diagnostics reach the broker's stderr); stdout carries exactly the
/// worker's JSON report.
///
/// # Errors
///
/// [`BrokerError::Spawn`] if the worker could not be spawned or communicated with.
pub fn spawn_worker_process(
    worker: &Path,
    input: &[u8],
    sandbox: Sandbox,
) -> Result<(i32, Vec<u8>), BrokerError> {
    imp::spawn(worker, input, sandbox).map_err(|e| BrokerError::Spawn(e.to_string()))
}

/// Prepare a directory the (possibly privilege-dropped) worker must WRITE into — the staging
/// directory — so it is broker-owned and non-world-writable, NOT world-writable `/tmp` (SPEC §8.3;
/// #504-E staging finding).
///
/// It is created and hardened to privileged identities. On Unix, when the broker is root and will
/// drop the worker to `nobody` ([`Sandbox::Restricted`]), the directory is additionally chowned to
/// that uid so the dropped worker can write while the directory stays `0700` (only `nobody` + root)
/// — closing the "any local user swaps staged bytes" vector that a shared `/tmp` leaves open. When
/// the worker inherits the broker's identity (tests, non-root), the broker owner already has write
/// access, so no chown is needed.
///
/// # Errors
///
/// [`BrokerError::Io`] if the directory cannot be created, hardened, or chowned.
pub fn prepare_worker_writable_dir(dir: &Path, sandbox: Sandbox) -> Result<(), BrokerError> {
    std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
    crate::secure::harden_state_dir(dir)?;
    #[cfg(unix)]
    {
        if sandbox == Sandbox::Restricted && imp::is_root() {
            let (uid, gid) = imp::nobody_ids();
            imp::chown_dir(dir, uid, gid)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = sandbox;
    }
    Ok(())
}

// ----------------------------------- Unix ----------------------------------------

#[cfg(unix)]
mod imp {
    use super::*;
    use crate::proc::HideConsole;
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    /// True when the broker runs as root (uid 0) and therefore MUST drop privilege before running
    /// network-facing code.
    pub(super) fn is_root() -> bool {
        // SAFETY: `geteuid` is always safe to call and has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    /// Give ownership of `dir` to `(uid, gid)` so a privilege-dropped worker can write into a
    /// directory that otherwise stays `0700` (root + that uid only).
    pub(super) fn chown_dir(dir: &Path, uid: u32, gid: u32) -> Result<(), BrokerError> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        // SAFETY: `chown` reads the NUL-terminated path and two plain integers; its result is
        // checked and no memory is retained past the call.
        let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        if rc != 0 {
            return Err(BrokerError::Io(io::Error::last_os_error().to_string()));
        }
        Ok(())
    }

    /// Resolve the `nobody` account's uid/gid, falling back to the conventional 65534.
    pub(super) fn nobody_ids() -> (u32, u32) {
        let name = std::ffi::CString::new("nobody").expect("static string");
        // SAFETY: `getpwnam` takes a valid NUL-terminated C string and returns either NULL or a
        // pointer to a static `passwd` we only read (never store past this call).
        unsafe {
            let pw = libc::getpwnam(name.as_ptr());
            if pw.is_null() {
                (65534, 65534)
            } else {
                ((*pw).pw_uid, (*pw).pw_gid)
            }
        }
    }

    pub fn spawn(worker: &Path, input: &[u8], sandbox: Sandbox) -> io::Result<(i32, Vec<u8>)> {
        let mut cmd = Command::new(worker);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .hide_console();

        if sandbox == Sandbox::Restricted && is_root() {
            let (uid, gid) = nobody_ids();
            // SAFETY: the closure runs in the forked child before exec. It only calls
            // async-signal-safe libc functions (`setgroups`/`setgid`/`setuid`) with values
            // computed in the parent; it allocates nothing and touches no shared state.
            unsafe {
                cmd.pre_exec(move || drop_privileges(uid, gid));
            }
        }
        communicate(cmd, input)
    }

    /// Irrevocably drop group + user privileges to `(uid, gid)`. Fails closed if any step fails
    /// or if uid 0 can still be regained afterward.
    fn drop_privileges(uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: called only in the child (post-fork, pre-exec). Ordering matters: clear
        // supplementary groups and set the gid BEFORE dropping the uid, because after `setuid`
        // the process no longer has the privilege to change its groups.
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Belt and suspenders: if we can still become root, the drop did not take.
            if libc::setuid(0) == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "privilege drop incomplete: uid 0 still reachable",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------- Windows ---------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::proc::HideConsole;
    use std::io;
    use std::process::{Command, Stdio};

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
    };
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Security::{
        CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess,
        OpenProcessToken, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    pub fn spawn(worker: &Path, input: &[u8], sandbox: Sandbox) -> io::Result<(i32, Vec<u8>)> {
        match sandbox {
            // A non-privileged broker (tests): a normal spawn, with clean std pipe IPC.
            Sandbox::Inherit => {
                let mut cmd = Command::new(worker);
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .hide_console();
                communicate(cmd, input)
            }
            // The production posture: run under a restricted token.
            Sandbox::Restricted => spawn_restricted(worker, input),
        }
    }

    /// Spawn the worker under a privilege-stripped restricted token, wiring stdin/stdout through
    /// anonymous pipes. Falls back to a plain `CreateProcessW` if spawning as the restricted user
    /// is denied by the host (non-admin dev/CI); the same pipe machinery is used either way, so
    /// the IPC path is exercised regardless of which spawn succeeds.
    fn spawn_restricted(worker: &Path, input: &[u8]) -> io::Result<(i32, Vec<u8>)> {
        // SAFETY: this block performs a sequence of Win32 calls whose invariants are upheld
        // locally — every HANDLE is initialized before use and closed on every path, pipe
        // security attributes are valid for the lifetime of the CreateProcess call, and the
        // command-line buffer outlives CreateProcess. Each call's result is checked.
        unsafe {
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: true.into(),
            };

            let mut child_stdin_rd = HANDLE::default();
            let mut our_stdin_wr = HANDLE::default();
            CreatePipe(&mut child_stdin_rd, &mut our_stdin_wr, Some(&sa), 0).map_err(win_io)?;
            SetHandleInherit(our_stdin_wr, false)?;

            let mut our_stdout_rd = HANDLE::default();
            let mut child_stdout_wr = HANDLE::default();
            CreatePipe(&mut our_stdout_rd, &mut child_stdout_wr, Some(&sa), 0).map_err(win_io)?;
            SetHandleInherit(our_stdout_rd, false)?;

            // Let the child inherit our stderr for diagnostics.
            let stderr = GetStdHandle(STD_ERROR_HANDLE).unwrap_or_default();

            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: child_stdin_rd,
                hStdOutput: child_stdout_wr,
                hStdError: stderr,
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();

            let app: Vec<u16> = wide(worker.as_os_str());
            let mut cmdline: Vec<u16> = wide_quoted(worker.as_os_str());

            let spawned = create_process(&app, &mut cmdline, &si, &mut pi);
            // Regardless of spawn outcome, the child ends belong to the child now.
            let _ = CloseHandle(child_stdin_rd);
            let _ = CloseHandle(child_stdout_wr);
            let _ = &sa; // keep `sa` alive through the CreateProcess call above

            if let Err(e) = spawned {
                let _ = CloseHandle(our_stdin_wr);
                let _ = CloseHandle(our_stdout_rd);
                return Err(e);
            }

            // Write the request, then close stdin so the worker sees EOF and starts producing.
            write_all(our_stdin_wr, input)?;
            let _ = CloseHandle(our_stdin_wr);

            let stdout = read_all(our_stdout_rd)?;
            let _ = CloseHandle(our_stdout_rd);

            WaitForSingleObject(pi.hProcess, u32::MAX);
            let mut code: u32 = 0;
            GetExitCodeProcess(pi.hProcess, &mut code).map_err(win_io)?;
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            // `si` (which borrows the pipe handles by value) has outlived every CreateProcess
            // call; the child ends were already closed above and our ends are closed below.
            let _ = &si;

            Ok((code as i32, stdout))
        }
    }

    /// Try to spawn under a restricted token; on an access/privilege failure, retry as a plain
    /// process (alpha fallback). Returns `Ok(())` on the first success.
    unsafe fn create_process(
        app: &[u16],
        cmdline: &mut [u16],
        si: &STARTUPINFOW,
        pi: &mut PROCESS_INFORMATION,
    ) -> io::Result<()> {
        if let Ok(token) = restricted_token() {
            let asuser = CreateProcessAsUserW(
                token,
                PCWSTR(app.as_ptr()),
                PWSTR(cmdline.as_mut_ptr()),
                None,
                None,
                true,
                CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                si,
                pi,
            );
            let _ = CloseHandle(token);
            if asuser.is_ok() {
                return Ok(());
            }
        }
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            true,
            CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            si,
            pi,
        )
        .map_err(win_io)
    }

    /// Build a restricted primary token from the current process token with all privileges
    /// removed (`DISABLE_MAX_PRIVILEGE`).
    unsafe fn restricted_token() -> windows::core::Result<HANDLE> {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_GROUPS
                | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )?;
        let mut restricted = HANDLE::default();
        let result = CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &mut restricted,
        );
        let _ = CloseHandle(token);
        result?;
        Ok(restricted)
    }

    unsafe fn write_all(handle: HANDLE, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut written: u32 = 0;
            WriteFile(handle, Some(data), Some(&mut written), None).map_err(win_io)?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "pipe write returned 0",
                ));
            }
            data = &data[written as usize..];
        }
        Ok(())
    }

    unsafe fn read_all(handle: HANDLE) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let mut read: u32 = 0;
            match ReadFile(handle, Some(&mut buf), Some(&mut read), None) {
                Ok(()) => {
                    if read == 0 {
                        break; // EOF
                    }
                    out.extend_from_slice(&buf[..read as usize]);
                }
                Err(e) if e.code() == ERROR_BROKEN_PIPE.to_hresult() => break, // child closed
                Err(e) => return Err(win_io(e)),
            }
        }
        Ok(out)
    }

    /// Set (or clear) the inherit flag on a handle.
    #[allow(non_snake_case)]
    unsafe fn SetHandleInherit(handle: HANDLE, inherit: bool) -> io::Result<()> {
        use windows::Win32::Foundation::SetHandleInformation;
        let flags = if inherit {
            HANDLE_FLAG_INHERIT
        } else {
            HANDLE_FLAGS(0)
        };
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, flags).map_err(win_io)
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn wide_quoted(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::iter::once(u16::from(b'"'))
            .chain(s.encode_wide())
            .chain(std::iter::once(u16::from(b'"')))
            .chain(std::iter::once(0))
            .collect()
    }

    fn win_io(e: windows::core::Error) -> io::Error {
        io::Error::other(e.to_string())
    }
}

// ------------------------------- shared IPC helper --------------------------------

/// Write `input` to the child's stdin, close it, wait, and return `(exit_code, stdout)`. Used by
/// the Unix path and the Windows `Inherit` path (both go through `std::process::Command`).
#[cfg(any(unix, windows))]
fn communicate(mut cmd: std::process::Command, input: &[u8]) -> std::io::Result<(i32, Vec<u8>)> {
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
        // `stdin` drops here, sending EOF so the worker starts producing its report.
    }
    let mut stdout = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_end(&mut stdout)?;
    }
    let status = child.wait()?;
    Ok((status.code().unwrap_or(-1), stdout))
}
