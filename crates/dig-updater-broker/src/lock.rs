//! The single-instance lock (SPEC §8.2, #504-F).
//!
//! Before a pass touches the network or installs anything, it MUST hold this lock. If a prior
//! pass is still running (its schedule overran — a slow network, a stuck installer), the new
//! invocation exits immediately WITHOUT acting rather than racing it: two passes writing the same
//! trust state or replacing the same binary concurrently is exactly the kind of TOCTOU the rest of
//! this crate goes to such lengths to avoid.
//!
//! - **Windows:** a named mutex in the session-independent `Global\` namespace, so a
//!   Task-Scheduler-launched SYSTEM pass (Session 0) and a manually-run `dig-updater run` from an
//!   elevated console (an interactive session) still serialize against each other. Its DACL grants
//!   only Administrators + Local System, matching the "Admin/SYSTEM-only" bar the rest of the
//!   guarded state carries (SPEC §9.3) — an unprivileged local process can neither hold nor query
//!   it to deny-of-service the schedule.
//! - **Unix:** an advisory `flock` (`LOCK_EX | LOCK_NB`) on `<state_dir>/lock`. That file lives
//!   INSIDE the state directory the broker has already hardened to `0700` before this is ever
//!   called (see [`crate::Broker::run_once`]'s ordering), so an unprivileged process cannot even
//!   `open()` it to attempt a competing lock — the directory ACL does the enforcement work for us.
//!
//! Either way the lock is released automatically when its guard drops — including on a panic
//! unwind or process kill via the OS reclaiming the handle/fd — so a crashed pass never leaves a
//! stale lock that would wedge every future pass.

use std::path::Path;

use crate::error::BrokerError;

/// A held single-instance lock. Dropping it releases the lock; there is nothing to call. The
/// inner handle is held purely for its `Drop` side effect (releasing the mutex/flock), never read.
pub struct SingleInstanceLock(#[allow(dead_code)] imp::Handle);

impl SingleInstanceLock {
    /// Try to acquire the production lock for a pass rooted at `state_dir`.
    ///
    /// Returns `Ok(None)` — NOT an error — when a prior pass already holds it: SPEC §8.2 makes
    /// this an ordinary, expected outcome ("exit immediately without acting"), not a failure.
    ///
    /// On Windows this locks the well-known, DACL-restricted `Global\DigUpdater` mutex — openable
    /// only by Administrators/SYSTEM, so ONLY a privileged caller (the production contract every
    /// caller of [`crate::Broker::run_once`] already meets) can even ask whether it is held.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the lock primitive itself could not be created or opened (e.g. the
    /// state directory does not exist and cannot be created, or — on Windows — the caller is not
    /// privileged enough to open the Administrators/SYSTEM-only mutex).
    pub fn try_acquire(state_dir: &Path) -> Result<Option<Self>, BrokerError> {
        imp::try_acquire(imp::PRODUCTION_NAME, state_dir, imp::Dacl::AdminSystemOnly)
            .map(|opt| opt.map(SingleInstanceLock))
    }

    /// Try to acquire the lock under an explicit `name` (Windows mutex name; ignored on Unix,
    /// where the lock is already scoped by `state_dir`), WITHOUT the production DACL restriction.
    ///
    /// Exposed so tests exercise real lock contention — including from an unprivileged `cargo
    /// test` process, which could never OPEN the DACL-restricted production mutex — without
    /// colliding with either the fixed production name or each other when `cargo test` runs them
    /// concurrently. Never used by production code (see [`Self::try_acquire`]).
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the lock primitive could not be created or opened.
    pub fn try_acquire_named(name: &str, state_dir: &Path) -> Result<Option<Self>, BrokerError> {
        imp::try_acquire(name, state_dir, imp::Dacl::Default).map(|opt| opt.map(SingleInstanceLock))
    }
}

// --------------------------------------- Windows ---------------------------------------------

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
    use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex};

    use crate::error::BrokerError;

    /// The well-known, session-independent name every production pass locks on.
    pub(super) const PRODUCTION_NAME: &str = "DigUpdater";

    /// Administrators (`BA`) + Local System (`SY`) get full control (`GA`); no one else is
    /// granted anything, so an unprivileged process can neither acquire nor even open-to-query
    /// the mutex to deny-of-service the schedule.
    const ADMIN_SYSTEM_ONLY_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

    /// Which DACL a mutex is created with. [`Self::AdminSystemOnly`] is the production posture
    /// ([`super::SingleInstanceLock::try_acquire`]); [`Self::Default`] lets an unprivileged
    /// `cargo test` process exercise real contention on an injected test name
    /// ([`super::SingleInstanceLock::try_acquire_named`]) — under `AdminSystemOnly`, the SECOND
    /// (opening, not creating) `CreateMutexW` call on an object an unprivileged token cannot open
    /// fails with access-denied rather than the benign "already held" this module models as
    /// `Ok(None)`, which would make the contention path untestable without an elevated runner.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Dacl {
        AdminSystemOnly,
        Default,
    }

    pub struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid mutex handle this struct exclusively owns; releasing
            // and closing it here is the documented teardown pair, and no other code retains it.
            unsafe {
                let _ = ReleaseMutex(self.0);
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub(super) fn try_acquire(
        name: &str,
        _state_dir: &Path,
        dacl: Dacl,
    ) -> Result<Option<Handle>, BrokerError> {
        let wide_name = wide(&format!(r"Global\{name}"));
        // `Owned` must outlive the `CreateMutexW` call below (its `attributes` field borrows the
        // descriptor it owns), so it is bound here even when `dacl` is `Default` and nothing
        // inside it is used.
        let restricted = match dacl {
            Dacl::AdminSystemOnly => Some(admin_system_only_security_attributes()?),
            Dacl::Default => None,
        };
        let sa = restricted
            .as_ref()
            .map(|owned| std::ptr::from_ref(&owned.attributes));
        // SAFETY: `sa` (when present) and the security descriptor it references outlive this
        // call — `restricted` is a local value dropped only after `CreateMutexW` returns;
        // `wide_name` is a valid NUL-terminated UTF-16 buffer for the duration of the call.
        let handle = unsafe {
            CreateMutexW(sa, false, PCWSTR(wide_name.as_ptr()))
                .map_err(|e| BrokerError::Io(format!("CreateMutexW failed: {e}")))?
        };
        // A mutex that already existed (another pass holds or held it) is reported via
        // `GetLastError() == ERROR_ALREADY_EXISTS` even though `CreateMutexW` itself succeeded in
        // returning a handle — but ownership of that handle does NOT mean we own the mutex's
        // lock state, so treat this exactly like a failed acquire.
        // SAFETY: `GetLastError` has no preconditions and reads only thread-local state.
        let already_existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        if already_existed {
            // SAFETY: `handle` is the valid handle just returned above.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Ok(None);
        }
        Ok(Some(Handle(handle)))
    }

    /// A `SECURITY_ATTRIBUTES` restricting the mutex to Administrators + Local System, backed by
    /// a security descriptor built from the SDDL string above. The descriptor is OS-allocated
    /// (`ConvertStringSecurityDescriptorToSecurityDescriptorW` documents `LocalAlloc` semantics),
    /// so it is wrapped in [`Owned`], whose `Drop` calls `LocalFree` exactly once — no leak, and no
    /// second hand-rolled `unsafe` pattern beyond the one call site that needs it.
    fn admin_system_only_security_attributes() -> Result<Owned, BrokerError> {
        let sddl = wide(ADMIN_SYSTEM_ONLY_SDDL);
        let mut descriptor: *mut SECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is a valid NUL-terminated UTF-16 string for the duration of the call;
        // `descriptor` receives an OS-allocated buffer on success, checked below, and ownership of
        // that allocation passes to `Owned` immediately so it is freed on every exit path.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                std::ptr::addr_of_mut!(descriptor) as *mut _,
                None,
            )
            .map_err(|e| BrokerError::Io(format!("could not build the mutex DACL: {e}")))?;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor as *mut _,
            bInheritHandle: false.into(),
        };
        Ok(Owned {
            attributes,
            descriptor,
        })
    }

    /// Keeps the OS-allocated descriptor alive alongside the `SECURITY_ATTRIBUTES` that points
    /// into it (so the pointer stays valid across the `CreateMutexW` call above), and frees it via
    /// `LocalFree` on drop.
    struct Owned {
        attributes: SECURITY_ATTRIBUTES,
        descriptor: *mut SECURITY_DESCRIPTOR,
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            if self.descriptor.is_null() {
                return;
            }
            // SAFETY: `self.descriptor` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW` (LocalAlloc semantics) and is
            // freed exactly once, here, only after `CreateMutexW` has already returned (the
            // descriptor is no longer referenced by anything at this point).
            unsafe {
                let _ = LocalFree(HLOCAL(self.descriptor as *mut _));
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

// ----------------------------------------- Unix ------------------------------------------------

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::Path;

    use fs4::{FileExt, TryLockError};

    use crate::error::BrokerError;

    /// Unused on Unix — the lock is scoped by `state_dir`, not a name (see the module doc).
    pub(super) const PRODUCTION_NAME: &str = "";

    /// Unused on Unix (the DACL split is a Windows-only concern — the state dir's own `0700`
    /// permissions already do this job here); kept so [`super::SingleInstanceLock`]'s two entry
    /// points share one call shape across both platform `imp` modules.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Dacl {
        AdminSystemOnly,
        Default,
    }

    pub struct Handle(File);

    impl Drop for Handle {
        fn drop(&mut self) {
            // Closing the fd (which happens right after this anyway) already releases the flock;
            // the explicit unlock just makes that release immediate rather than incidental.
            // Fully-qualified so this always calls `fs4`'s method, never a same-named INHERENT
            // `std::fs::File` method a newer toolchain might stabilize (inherent methods win
            // trait-method resolution silently — see the note on `try_acquire` below).
            let _ = FileExt::unlock(&self.0);
        }
    }

    pub(super) fn try_acquire(
        _name: &str,
        state_dir: &Path,
        _dacl: Dacl,
    ) -> Result<Option<Handle>, BrokerError> {
        // This can be the very first thing a pass ever creates under `state_dir` (the lock is
        // acquired before `Broker::run_pass`'s own harden-then-ACL-check step), so it must not
        // rely on that LATER step to lock the directory down — it creates it owner-only (`0700`)
        // ITSELF, closing the brief insecure-permissions window a plain `create_dir_all` followed
        // by a separate `chmod` would otherwise leave open.
        create_dir_owner_only(state_dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            // Explicit: this file carries no content, only an flock — opening it across passes
            // must not truncate whatever (nothing) is there.
            .truncate(false)
            .mode(0o600)
            .open(state_dir.join("lock"))
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        // `fs4` wraps `flock` behind a safe API — the SAME crate `dig-node-core` already uses for
        // its own cross-process cache lock, so the beacon needs no second hand-rolled `unsafe`
        // primitive alongside `sandbox.rs`'s privilege drop.
        //
        // Called via the FULLY-QUALIFIED `FileExt::try_lock(&file)` rather than `file.try_lock()`:
        // Rust 1.89 stabilized an IDENTICALLY-NAMED inherent `std::fs::File::try_lock`, and
        // inherent methods silently win over trait methods in dot-call resolution — so on a
        // toolchain that new, `file.try_lock()` would quietly call std's method (returning
        // `std::fs::TryLockError`) instead of `fs4`'s, breaking the `match` below across
        // toolchain versions. The fully-qualified form pins this to `fs4::FileExt` regardless.
        match FileExt::try_lock(&file) {
            Ok(()) => Ok(Some(Handle(file))),
            Err(TryLockError::WouldBlock) => Ok(None), // held by another pass
            Err(TryLockError::Error(e)) => Err(BrokerError::Io(e.to_string())),
        }
    }

    /// `create_dir_all`, but the directory is born `0700` rather than the umask default — see the
    /// caller's comment on why this cannot wait for a later, separate harden step.
    fn create_dir_owner_only(dir: &Path) -> Result<(), BrokerError> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| BrokerError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn a_fresh_lock_is_acquired() {
        let home = dir();
        let lock = SingleInstanceLock::try_acquire_named("dig-updater-test-fresh", home.path())
            .expect("acquire must not error");
        assert!(lock.is_some(), "an unheld lock must be acquirable");
    }

    #[test]
    fn a_second_acquire_while_the_first_is_held_is_refused() {
        let home = dir();
        let name = "dig-updater-test-contended";
        let first = SingleInstanceLock::try_acquire_named(name, home.path())
            .expect("first acquire must not error")
            .expect("the lock starts unheld");
        let second = SingleInstanceLock::try_acquire_named(name, home.path())
            .expect("a contended acquire is a benign None, not an error");
        assert!(
            second.is_none(),
            "a lock already held by `first` must not be acquired again"
        );
        drop(first);
    }

    #[test]
    fn releasing_the_first_lets_a_later_acquire_succeed() {
        let home = dir();
        let name = "dig-updater-test-release-then-reacquire";
        let first = SingleInstanceLock::try_acquire_named(name, home.path())
            .expect("acquire")
            .expect("unheld");
        drop(first); // releases the lock
        let second = SingleInstanceLock::try_acquire_named(name, home.path())
            .expect("acquire")
            .expect("must be acquirable again once released");
        drop(second);
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_lives_inside_the_state_dir_not_beside_it() {
        let home = dir();
        let _lock = SingleInstanceLock::try_acquire_named("dig-updater-test-path", home.path())
            .expect("acquire")
            .expect("unheld");
        assert!(
            home.path().join("lock").exists(),
            "the lock file must live at <state_dir>/lock"
        );
    }
}
