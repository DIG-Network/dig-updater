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
use std::time::Duration;

use crate::error::BrokerError;

/// The largest worker report the broker will buffer from the worker's stdout: 64 MiB.
///
/// A legitimate report is two feed JSON documents (delegation + manifest, each capped well under
/// 10 MiB) plus small per-artifact staged records, so this is generous headroom. Its sole purpose
/// is to stop a COMPROMISED worker from OOMing the privileged (root/SYSTEM) broker by writing to
/// stdout without bound (dig_ecosystem#1941) — mirroring `loadable::LDCONFIG_OUTPUT_CAP`.
pub const WORKER_STDOUT_CAP: u64 = 64 * 1024 * 1024;

/// Wall-clock the broker waits for the worker to finish ONE pass before killing it.
///
/// Deliberately generous: larger than any legitimate pass (the worker self-bounds each network
/// fetch and downloads at most a handful of artifacts), so it never interrupts honest work. It is
/// the BACKSTOP for a compromised worker that ignores its own timeouts and hangs forever — without
/// it, the worker could wedge the broker and hold the single-instance lock indefinitely, so the
/// update channel would never make progress again (dig_ecosystem#1941).
const WORKER_IPC_BUDGET: Duration = Duration::from_secs(30 * 60);

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
    imp::spawn(worker, input, sandbox)
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
/// Ownership and mode are not sufficient on their own: the dropped worker must also be able to
/// TRAVERSE every ancestor down to `dir`. That is why staging lives BESIDE the locked-down state
/// directory rather than inside it ([`crate::paths::sibling_staging_dir`]), and why this verifies
/// the reachability it just arranged — a pass that cannot be reached by its own worker must fail
/// HERE, naming the offending directory, instead of surfacing later as an opaque
/// `staging_io_error: Permission denied (os error 13)` (#1747).
///
/// # Errors
///
/// [`BrokerError::Io`] if the directory cannot be created, hardened, or chowned, or if an ancestor
/// denies the privilege-dropped worker the traverse right it needs to reach `dir`.
pub fn prepare_worker_writable_dir(dir: &Path, sandbox: Sandbox) -> Result<(), BrokerError> {
    std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
    crate::secure::harden_state_dir(dir)?;
    #[cfg(unix)]
    {
        if sandbox == Sandbox::Restricted && imp::is_root() {
            let (uid, gid) = imp::nobody_ids();
            imp::chown_dir(dir, uid, gid)?;
            if let Some(blocker) =
                crate::secure::first_untraversable_ancestor(dir, &crate::secure::filesystem_root())
            {
                return Err(BrokerError::Io(format!(
                    "the worker identity cannot reach its staging directory {}: {} denies traverse \
                     to any other identity",
                    dir.display(),
                    blocker.display()
                )));
            }
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

    pub fn spawn(
        worker: &Path,
        input: &[u8],
        sandbox: Sandbox,
    ) -> Result<(i32, Vec<u8>), BrokerError> {
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
        CloseHandle, ERROR_BROKEN_PIPE, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_TIMEOUT,
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
        OpenProcessToken, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    pub fn spawn(
        worker: &Path,
        input: &[u8],
        sandbox: Sandbox,
    ) -> Result<(i32, Vec<u8>), BrokerError> {
        match sandbox {
            // A non-privileged broker (tests): a normal spawn, with clean std pipe IPC. Goes
            // through the shared bounded `communicate`, so it inherits the deadline + stdout cap.
            Sandbox::Inherit => {
                let mut cmd = Command::new(worker);
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .hide_console();
                communicate(cmd, input)
            }
            // The production posture: run under a restricted token.
            Sandbox::Restricted => {
                spawn_restricted(worker, input).map_err(|e| BrokerError::Spawn(e.to_string()))
            }
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

            let stdout = read_all(our_stdout_rd, WORKER_STDOUT_CAP)?;
            let _ = CloseHandle(our_stdout_rd);

            // Bound the wait so a worker that closed stdout but never exits cannot wedge the broker.
            // A worker that never closes stdout is a residual Windows gap (the blocking `read_all`
            // above): the live permanent-wedge defect is the Unix/macOS `communicate` path, which is
            // fully bounded; a stall-deadline for this restricted-token read is a follow-up needing
            // overlapped/peeked pipe I/O (dig_ecosystem#1941).
            let budget_ms = u32::try_from(WORKER_IPC_BUDGET.as_millis()).unwrap_or(u32::MAX);
            if WaitForSingleObject(pi.hProcess, budget_ms) == WAIT_TIMEOUT {
                let _ = TerminateProcess(pi.hProcess, 1);
                WaitForSingleObject(pi.hProcess, u32::MAX);
            }
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

    /// Read the child's stdout to EOF, refusing to buffer more than `cap` bytes so a compromised
    /// worker cannot OOM the privileged broker (dig_ecosystem#1941). More than `cap` fails closed.
    unsafe fn read_all(handle: HANDLE, cap: u64) -> io::Result<Vec<u8>> {
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
                    if out.len() as u64 > cap {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("worker stdout exceeded the {cap}-byte cap"),
                        ));
                    }
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
fn communicate(cmd: std::process::Command, input: &[u8]) -> Result<(i32, Vec<u8>), BrokerError> {
    communicate_bounded(cmd, input, WORKER_IPC_BUDGET, WORKER_STDOUT_CAP)
}

/// The body of [`communicate`], with the wall-clock `budget` and stdout `cap` INJECTED so both the
/// hang path and the overflow path can be exercised against real child processes under tiny values
/// (the same injection idiom [`crate::probe::bounded_probe`] and [`crate::loadable`] use).
///
/// Two properties this guarantees against an untrusted/compromised worker:
/// - **it cannot hang the broker forever** — stdout is drained on a side thread so the deadline is
///   real even if the worker never closes it, and a worker still running at `budget` is killed and
///   reaped, failing closed with [`BrokerError::WorkerTimedOut`];
/// - **it cannot OOM the broker** — the side thread reads at most `cap + 1` bytes, and more than
///   `cap` fails closed with [`BrokerError::WorkerStdoutTooLarge`].
#[cfg(any(unix, windows))]
fn communicate_bounded(
    mut cmd: std::process::Command,
    input: &[u8],
    budget: Duration,
    cap: u64,
) -> Result<(i32, Vec<u8>), BrokerError> {
    let mut child = cmd.spawn().map_err(|e| BrokerError::Spawn(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A worker that dies before reading its whole request breaks this pipe; that is not fatal
        // on its own — the exit code / unparseable report surfaces it — so the write is best effort.
        let _ = stdin.write_all(input);
        // `stdin` drops here, sending EOF so the worker starts producing its report.
    }

    // Drain stdout on a side thread, bounded to `cap + 1` bytes, so a worker that writes forever
    // can never make the broker buffer without bound AND so this read can never block the deadline
    // below: a worker that never writes and never exits is caught by `wait_within`, not stuck here.
    let reader = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.by_ref().take(cap + 1).read_to_end(&mut buf);
            buf
        })
    });

    if crate::probe::wait_within(&mut child, budget).is_none() {
        crate::probe::kill_and_reap(&mut child);
        return Err(BrokerError::WorkerTimedOut(format!(
            "worker still running after {}s; killed and reaped",
            budget.as_secs()
        )));
    }

    // The child has exited (`wait_within` reaped it via `try_wait`); its status is cached, so this
    // returns the code without blocking.
    let code = child
        .wait()
        .map(|status| status.code().unwrap_or(-1))
        .unwrap_or(-1);

    let stdout = match reader {
        Some(handle) => handle
            .join()
            .map_err(|_| BrokerError::Spawn("the worker stdout reader thread panicked".into()))?,
        None => Vec::new(),
    };
    if stdout.len() as u64 > cap {
        return Err(BrokerError::WorkerStdoutTooLarge { limit: cap });
    }
    Ok((code, stdout))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Build a `sh -c <script>` command wired for the bounded IPC path (piped stdin+stdout).
    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        cmd
    }

    /// THE POINT (dig_ecosystem#1941): a worker that prints a partial report and then HANGS forever
    /// must not wedge the broker. The unbounded `read_to_end` this replaces would block here until
    /// the process died, holding the single-instance lock the whole time; the deadline makes it fail
    /// closed. The child outlives the test's budget (a 300s sleep) so a pass can only mean the broker
    /// killed it — no real 300s wait occurs because the assertion returns as soon as the budget fires.
    #[test]
    fn a_worker_that_hangs_after_partial_output_times_out() {
        let started = std::time::Instant::now();
        let result = communicate_bounded(
            sh("printf '{\"partial\":'; sleep 300"),
            b"request",
            Duration::from_millis(300),
            WORKER_STDOUT_CAP,
        );
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(BrokerError::WorkerTimedOut(_))),
            "a hanging worker must fail closed with WorkerTimedOut, got: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "communicate returned only after {elapsed:?}; it is not bounded by its budget"
        );
    }

    /// A COMPROMISED worker that floods stdout must not OOM the privileged broker: more than the cap
    /// fails closed with `WorkerStdoutTooLarge` rather than buffering without bound. The child writes
    /// well over the (tiny, injected) cap but far under a pipe buffer, then exits, so the overflow is
    /// detected deterministically rather than racing the deadline.
    #[test]
    fn a_worker_that_floods_stdout_is_rejected_not_buffered() {
        let cap = 1024;
        let result = communicate_bounded(
            sh("head -c 8192 /dev/zero"),
            b"request",
            Duration::from_secs(30),
            cap,
        );
        assert!(
            matches!(result, Err(BrokerError::WorkerStdoutTooLarge { limit }) if limit == cap),
            "an over-cap worker must fail closed with WorkerStdoutTooLarge, got: {result:?}"
        );
    }

    /// The common case is untouched: a well-behaved worker that echoes its request-derived report
    /// and exits is read verbatim with its exit code, so bounding costs honest workers nothing.
    #[test]
    fn a_well_behaved_worker_is_read_verbatim() {
        let result = communicate_bounded(
            sh("printf '{\"ok\":true}'; exit 0"),
            b"request",
            Duration::from_secs(30),
            WORKER_STDOUT_CAP,
        );
        let (code, stdout) = result.expect("a prompt small report must succeed");
        assert_eq!(code, 0);
        assert_eq!(stdout, b"{\"ok\":true}");
    }

    /// A report exactly at the cap is accepted — the bound rejects only STRICTLY-over-cap output, so
    /// a legitimate maximal report is not lost. Pins the boundary from the passing side (the flood
    /// test pins it from the failing side).
    #[test]
    fn a_report_exactly_at_the_cap_is_accepted() {
        let cap = 1024;
        let result = communicate_bounded(
            sh("head -c 1024 /dev/zero"),
            b"request",
            Duration::from_secs(30),
            cap,
        );
        let (_code, stdout) = result.expect("output exactly at the cap must be accepted");
        assert_eq!(stdout.len() as u64, cap);
    }
}
