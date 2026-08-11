//! Deciding whether a Windows DACL lets a NON-privileged principal write a guarded path.
//!
//! [`crate::secure::path_is_privileged_owned`] historically answered one question — *who owns this
//! directory* — and treated the answer as if it were *who can write this directory*. Those differ:
//! an `Administrators`-owned directory can still carry an ACE granting write to `Users`, and the
//! schedule install root is exactly the path where that matters, because a writable install root
//! means an attacker plants a binary the daily SYSTEM task later runs elevated
//! (dig_ecosystem#2571, defence-in-depth on #2334).
//!
//! # Why the ACL arrives as DATA
//!
//! Everything in this module above the [`read`] boundary is a pure function over an owned
//! [`Dacl`] value, so the whole decision matrix is exercised on Linux and macOS CI from fabricated
//! ACL fixtures. A rule that could only be exercised on an elevated Windows host with a
//! deliberately mis-ACL'd directory would be, in practice, unverified.
//!
//! # Which direction a wrong answer fails in
//!
//! Too strict here BRICKS the updater on legitimate machines — a refused `schedule install` means
//! no daily wake, which means no security updates at all, which is worse than the residual this
//! hardening closes (the residual needs an *elevated* misconfiguration to exist in the first
//! place). So the leniency is deliberate and asymmetric:
//!
//! - a DACL we could **not read** is `None` from [`read`], never a [`DaclVerdict`], and does NOT
//!   reject — the owner check stands alone, exactly as it did before this module existed;
//! - a DACL we **could** read and which is permissive DOES reject;
//! - a DENY ACE is subtracted from the same principal's allowed mask, so a directory an
//!   administrator hardened with an explicit deny over an inherited grant is not flagged;
//! - an `INHERIT_ONLY` ACE grants nothing on the object itself and is ignored.
//!
//! Distinguishing "read the DACL, found nothing bad" from "could not read the DACL" is the whole
//! point of [`Dacl`] being returned inside an [`Option`]: a restrictive directory can enumerate as
//! empty rather than failing, and collapsing those two into one "clean" answer would be a false
//! all-clear.

/// A rights mask bit granting write-equivalent access to a directory — enough to plant, replace or
/// remove the binary a privileged schedule runs, or to re-ACL the directory so that one can.
///
/// `WRITE_DAC`/`WRITE_OWNER` are included because either one lets its holder grant itself the
/// rest; `DELETE` is included because deleting the install root's binary and recreating it is
/// replacement by another name.
mod rights {
    /// `FILE_WRITE_DATA` / `FILE_ADD_FILE`.
    pub const WRITE_DATA: u32 = 0x0000_0002;
    /// `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY`.
    pub const ADD_SUBDIRECTORY: u32 = 0x0000_0004;
    /// `DELETE`.
    pub const DELETE: u32 = 0x0001_0000;
    /// `WRITE_DAC` — re-ACL the object, i.e. grant yourself everything else.
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// `WRITE_OWNER` — take ownership, i.e. grant yourself everything else.
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    /// `GENERIC_ALL`.
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    /// `GENERIC_WRITE`.
    pub const GENERIC_WRITE: u32 = 0x4000_0000;

    /// Every write-equivalent bit, as one mask.
    pub const WRITE_EQUIVALENT: u32 = WRITE_DATA
        | ADD_SUBDIRECTORY
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_ALL
        | GENERIC_WRITE;
}

/// `INHERIT_ONLY_ACE` — the ACE applies to children only, never to the object carrying it.
const INHERIT_ONLY_ACE: u8 = 0x08;

/// The well-known string SIDs whose write access to a privileged install root is EXPECTED, so a
/// grant to one of them is not a finding.
///
/// `CREATOR OWNER` and `OWNER RIGHTS` are here because the owner has already been proven privileged
/// by the caller ([`crate::secure::path_is_privileged_owned`] checks the owner SID first); an ACE
/// naming the owner therefore names a privileged identity by construction. Every other principal —
/// including `Users`, `Authenticated Users`, `Everyone`, `LOCAL SERVICE` and `NETWORK SERVICE` —
/// is unprivileged for this purpose: none of them should be able to replace a binary that runs as
/// SYSTEM.
const PRIVILEGED_SIDS: &[&str] = &[
    // Local System.
    "S-1-5-18",
    // BUILTIN\Administrators.
    "S-1-5-32-544",
    // CREATOR OWNER / OWNER RIGHTS — resolve to the (already-verified privileged) owner.
    "S-1-3-0",
    "S-1-3-4",
    // NT SERVICE\TrustedInstaller — owns most of `%ProgramFiles%` on a stock Windows install.
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Whether an ACE allows access, denies it, or is an audit/alarm entry that grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AceKind {
    /// `ACCESS_ALLOWED_ACE_TYPE`.
    Allow,
    /// `ACCESS_DENIED_ACE_TYPE`.
    Deny,
    /// An audit/alarm/callback ACE — affects logging, never access.
    Other,
}

/// One access-control entry, reduced to the four things the decision depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ace {
    /// Allow, deny, or neither.
    pub kind: AceKind,
    /// The trustee, as a string SID (`S-1-5-32-544`) — a string so the whole allowlist is pure and
    /// testable off-Windows.
    pub sid: String,
    /// The access mask.
    pub mask: u32,
    /// `INHERIT_ONLY_ACE` — grants nothing on the object itself.
    pub inherit_only: bool,
}

impl Ace {
    /// An `ACCESS_ALLOWED` ACE that applies to the object itself — the common case, and the shape
    /// most fixtures want.
    #[cfg(test)]
    pub fn allow(sid: &str, mask: u32) -> Self {
        Self {
            kind: AceKind::Allow,
            sid: sid.to_string(),
            mask,
            inherit_only: false,
        }
    }

    /// An `ACCESS_DENIED` ACE that applies to the object itself.
    #[cfg(test)]
    pub fn deny(sid: &str, mask: u32) -> Self {
        Self {
            kind: AceKind::Deny,
            ..Self::allow(sid, mask)
        }
    }
}

/// A discretionary access-control list as read from a security descriptor.
///
/// [`Dacl::Absent`] is NOT the same as [`Dacl::Present`] with no entries: a NULL DACL grants
/// EVERYONE full control, while an empty present DACL grants nobody anything. Conflating them
/// would turn the most permissive state Windows can express into the most restrictive one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dacl {
    /// No DACL on the descriptor — Windows grants every principal full control.
    Absent,
    /// A DACL is present, carrying these entries (possibly none).
    Present(Vec<Ace>),
}

/// What a DACL says about non-privileged write access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaclVerdict {
    /// Every write-equivalent grant belongs to a privileged principal.
    PrivilegedWriteOnly,
    /// A non-privileged principal holds write-equivalent access — the finding.
    UnprivilegedWrite {
        /// The offending trustee, for the refusal message.
        sid: String,
    },
}

/// Judge a DACL: does any non-privileged principal hold write-equivalent access to this object?
///
/// The effective mask for a trustee is its allowed bits minus its denied bits. Subtracting denies
/// is the lenient direction, and lenient is the direction this check must err in — see the module
/// docs on failure direction.
pub(crate) fn judge(dacl: &Dacl) -> DaclVerdict {
    let entries = match dacl {
        // A NULL DACL is world-writable. We DID read the descriptor, so this is a real finding and
        // not an unreadable one.
        Dacl::Absent => {
            return DaclVerdict::UnprivilegedWrite {
                sid: "<null DACL: every principal has full control>".to_string(),
            }
        }
        Dacl::Present(entries) => entries,
    };

    for ace in entries {
        if ace.kind != AceKind::Allow || ace.inherit_only || is_privileged_sid(&ace.sid) {
            continue;
        }
        let denied = denied_mask_for(entries, &ace.sid);
        if ace.mask & rights::WRITE_EQUIVALENT & !denied != 0 {
            return DaclVerdict::UnprivilegedWrite {
                sid: ace.sid.clone(),
            };
        }
    }
    DaclVerdict::PrivilegedWriteOnly
}

/// Every bit denied to `sid` by an applicable DENY ACE anywhere in the list.
fn denied_mask_for(entries: &[Ace], sid: &str) -> u32 {
    entries
        .iter()
        .filter(|ace| ace.kind == AceKind::Deny && !ace.inherit_only && ace.sid == sid)
        .fold(0, |acc, ace| acc | ace.mask)
}

/// Whether a string SID names a principal expected to hold write access to a privileged root.
fn is_privileged_sid(sid: &str) -> bool {
    PRIVILEGED_SIDS.contains(&sid)
}

#[cfg(windows)]
pub(crate) use imp::read;

/// Reading the real DACL off a path — the one impure, Windows-only part of this module.
#[cfg(windows)]
mod imp {
    use super::{Ace, AceKind, Dacl};
    use std::path::Path;
    use windows::Win32::Security::ACL;

    /// Read `path`'s DACL, or `None` if the security descriptor could not be read.
    ///
    /// `None` means the check has NO evidence — the caller must not read it as "clean" (module
    /// docs). Every other outcome, including a present-but-empty DACL, is evidence.
    pub fn read(path: &Path) -> Option<Dacl> {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `GetNamedSecurityInfoW` writes `dacl` (a pointer INTO the descriptor it
        // allocates) and `descriptor` (LocalAlloc'd, freed below). On failure it touches neither.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        // SAFETY: on success `dacl` is either NULL (no DACL) or a valid ACL inside `descriptor`,
        // which outlives the read because it is freed only after `entries` returns owned data.
        let parsed = if dacl.is_null() {
            Some(Dacl::Absent)
        } else {
            unsafe { entries(dacl) }.map(Dacl::Present)
        };
        // SAFETY: exactly the allocation `GetNamedSecurityInfoW` returned, freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        parsed
    }

    /// Walk every ACE in `acl` into owned [`Ace`] data. `None` if the ACL could not be walked —
    /// which stays distinct from an ACL that walked cleanly and held no entries.
    ///
    /// # Safety
    ///
    /// `acl` must be a valid, non-NULL `ACL` that outlives the call.
    unsafe fn entries(acl: *mut ACL) -> Option<Vec<Ace>> {
        use windows::Win32::Security::{GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER};
        use windows::Win32::System::SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
        };

        // SAFETY: the caller guarantees `acl` is a valid ACL.
        let count = u32::from(unsafe { (*acl).AceCount });
        let mut out = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut raw: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the ACL's own AceCount, so the ACE exists.
            if unsafe { GetAce(acl, index, &mut raw) }.is_err() || raw.is_null() {
                // One unreadable ACE makes the WHOLE list untrustworthy: the entry we could not
                // read is exactly the one that might carry the permissive grant.
                return None;
            }
            // SAFETY: `GetAce` yielded a pointer to a well-formed ACE, whose header is its first
            // field for every ACE type.
            let header = unsafe { *raw.cast::<ACE_HEADER>() };
            let kind = match u32::from(header.AceType) {
                ACCESS_ALLOWED_ACE_TYPE => AceKind::Allow,
                ACCESS_DENIED_ACE_TYPE => AceKind::Deny,
                _ => AceKind::Other,
            };
            // Only the two basic types are parsed past the header, and that restriction is load
            // bearing rather than an optimization: the OBJECT and CALLBACK_OBJECT variants carry
            // extra `Flags`/GUID fields BEFORE their trailing SID, so reading them at the basic
            // layout's offset would yield a SID from the wrong bytes — which could resolve to a
            // privileged principal and silently excuse a permissive grant. Every unparsed type is
            // an audit/alarm/object ACE, none of which can produce a finding.
            if kind == AceKind::Other {
                out.push(Ace {
                    kind,
                    sid: String::new(),
                    mask: 0,
                    inherit_only: header.AceFlags & super::INHERIT_ONLY_ACE != 0,
                });
                continue;
            }
            // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE lay out `{header, mask, sid_start}`
            // identically, so one layout reads either.
            // SAFETY: as above — the ACE is at least as large as this prefix, and the offsets are
            // taken from the struct itself rather than assumed.
            let mask = unsafe { (*raw.cast::<ACCESS_ALLOWED_ACE>()).Mask };
            let sid_offset = core::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            // SAFETY: `SidStart` is the first byte of the ACE's trailing SID, in bounds of the ACE.
            let sid = unsafe { sid_string(raw.byte_add(sid_offset)) }?;
            out.push(Ace {
                kind,
                sid,
                mask,
                inherit_only: header.AceFlags & super::INHERIT_ONLY_ACE != 0,
            });
        }
        Some(out)
    }

    /// Render a SID as its canonical `S-1-…` string, or `None` if it could not be converted.
    ///
    /// # Safety
    ///
    /// `sid` must point at a valid SID.
    unsafe fn sid_string(sid: *mut core::ffi::c_void) -> Option<String> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::PSID;

        let mut text = PWSTR::null();
        // SAFETY: the caller guarantees `sid` is valid; `text` is LocalAlloc'd and freed below.
        unsafe { ConvertSidToStringSidW(PSID(sid), &mut text) }.ok()?;
        if text.is_null() {
            return None;
        }
        // SAFETY: `ConvertSidToStringSidW` returned a NUL-terminated wide string.
        let owned = unsafe { text.to_string() }.ok();
        // SAFETY: exactly the allocation the conversion returned, freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.as_ptr().cast())));
        }
        owned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Users` — the principal a real permissive install root grants write to.
    const USERS: &str = "S-1-5-32-545";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const SYSTEM: &str = "S-1-5-18";
    /// `ALL APPLICATION PACKAGES` — present read-only on a stock `%ProgramFiles%`.
    const APP_PACKAGES: &str = "S-1-15-2-1";
    /// `FILE_GENERIC_READ | FILE_EXECUTE`, the read-only grant a stock install root carries.
    const READ_EXECUTE: u32 = 0x0012_01A9;
    /// `FILE_ALL_ACCESS`.
    const FULL: u32 = 0x001F_01FF;

    /// The stock `%ProgramFiles%` shape: privileged principals hold full control, everyone else is
    /// read-only. This is the CONTROL — if the check flags this, it bricks every real install.
    fn stock_program_files() -> Dacl {
        Dacl::Present(vec![
            Ace::allow(SYSTEM, FULL),
            Ace::allow(ADMINISTRATORS, FULL),
            Ace::allow(USERS, READ_EXECUTE),
            Ace::allow(APP_PACKAGES, READ_EXECUTE),
        ])
    }

    #[test]
    fn a_stock_install_root_is_accepted() {
        assert_eq!(
            judge(&stock_program_files()),
            DaclVerdict::PrivilegedWriteOnly
        );
    }

    #[test]
    fn an_admin_owned_root_with_a_write_ace_for_users_is_refused() {
        // The whole point of the ticket: the owner SID says `Administrators`, and the DACL still
        // lets an unprivileged group plant a binary the SYSTEM task will run.
        let mut aces = match stock_program_files() {
            Dacl::Present(aces) => aces,
            Dacl::Absent => unreachable!(),
        };
        aces.push(Ace::allow(USERS, rights::WRITE_DATA));
        assert_eq!(
            judge(&Dacl::Present(aces)),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            }
        );
    }

    #[test]
    fn every_write_equivalent_bit_alone_is_a_finding() {
        // Each bit is independently sufficient to replace the binary or to grant oneself the
        // rights to: pinning them one at a time keeps a future narrowing of the mask visible.
        for bit in [
            rights::WRITE_DATA,
            rights::ADD_SUBDIRECTORY,
            rights::DELETE,
            rights::WRITE_DAC,
            rights::WRITE_OWNER,
            rights::GENERIC_ALL,
            rights::GENERIC_WRITE,
        ] {
            assert_eq!(
                judge(&Dacl::Present(vec![Ace::allow(USERS, bit)])),
                DaclVerdict::UnprivilegedWrite {
                    sid: USERS.to_string()
                },
                "mask bit {bit:#x} must count as write-equivalent"
            );
        }
    }

    #[test]
    fn a_read_only_bit_for_an_unprivileged_group_is_not_a_finding() {
        // FILE_WRITE_ATTRIBUTES / FILE_WRITE_EA are deliberately NOT write-equivalent: neither
        // lets its holder change file CONTENT, and treating them as findings would flag ordinary
        // directories.
        for benign in [READ_EXECUTE, 0x0000_0100, 0x0000_0010] {
            assert_eq!(
                judge(&Dacl::Present(vec![Ace::allow(USERS, benign)])),
                DaclVerdict::PrivilegedWriteOnly,
                "mask {benign:#x} must not be a finding"
            );
        }
    }

    #[test]
    fn a_write_grant_to_a_privileged_principal_is_expected() {
        for sid in PRIVILEGED_SIDS {
            assert_eq!(
                judge(&Dacl::Present(vec![Ace::allow(sid, FULL)])),
                DaclVerdict::PrivilegedWriteOnly,
                "{sid} is expected to hold write access"
            );
        }
    }

    #[test]
    fn every_unprivileged_well_known_group_is_a_finding() {
        // The allowlist is an ALLOWlist, so this pins the groups an attacker could actually be a
        // member of. It fails the moment one of them is added to `PRIVILEGED_SIDS` — which is the
        // single edit that would silently reopen the hole this module exists to close.
        for sid in [
            // Everyone / World.
            "S-1-1-0",
            // Authenticated Users.
            "S-1-5-11",
            // BUILTIN\Users.
            USERS,
            // INTERACTIVE — every principal logged on at the console.
            "S-1-5-4",
            // A concrete unprivileged local account.
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
        ] {
            assert_eq!(
                judge(&Dacl::Present(vec![Ace::allow(sid, FULL)])),
                DaclVerdict::UnprivilegedWrite {
                    sid: sid.to_string()
                },
                "{sid} must not hold write access to a privileged install root"
            );
        }
    }

    #[test]
    fn file_all_access_for_an_unprivileged_group_is_a_finding() {
        // The composite mask a real misconfiguration carries, as opposed to the single bits above:
        // a check written against one named bit rather than `& WRITE_EQUIVALENT` could miss it.
        assert_eq!(
            judge(&Dacl::Present(vec![Ace::allow(USERS, FULL)])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            }
        );
    }

    #[test]
    fn a_deny_ace_neutralizes_the_matching_grant() {
        // An administrator who hardened an inherited `Users:(W)` with an explicit deny has a SAFE
        // directory; flagging it would refuse to install on a machine that is more locked down
        // than the baseline, which is the brick direction.
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::deny(USERS, rights::WRITE_EQUIVALENT),
                Ace::allow(USERS, FULL),
            ])),
            DaclVerdict::PrivilegedWriteOnly
        );
    }

    #[test]
    fn a_partial_deny_still_leaves_a_finding() {
        // Denying only DELETE does not stop the holder from overwriting the binary in place, so
        // the leniency of subtracting denies must not become a bypass.
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::deny(USERS, rights::DELETE),
                Ace::allow(USERS, rights::DELETE | rights::WRITE_DATA),
            ])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            }
        );
    }

    #[test]
    fn a_deny_is_subtracted_whichever_side_of_the_grant_it_sits() {
        // Windows evaluates ACEs in order, so a DENY placed AFTER an ALLOW does not actually take
        // away what the ALLOW already granted. This check subtracts it anyway, and does so on
        // purpose: the strict reading would flag a directory whose administrator plainly INTENDED
        // to deny, and a false refusal here stops the machine updating at all. Producing such a
        // DACL already requires the write access this check is looking for.
        let denied_first = judge(&Dacl::Present(vec![
            Ace::deny(USERS, rights::WRITE_EQUIVALENT),
            Ace::allow(USERS, FULL),
        ]));
        let allowed_first = judge(&Dacl::Present(vec![
            Ace::allow(USERS, FULL),
            Ace::deny(USERS, rights::WRITE_EQUIVALENT),
        ]));
        assert_eq!(denied_first, DaclVerdict::PrivilegedWriteOnly);
        assert_eq!(
            allowed_first, denied_first,
            "ACE order must not change the verdict"
        );
    }

    #[test]
    fn a_grant_after_a_clean_prefix_is_still_found() {
        // Enumeration must not stop at the first non-finding ACE, nor at the first DENY: the
        // permissive grant is at the END here, behind entries that each look fine alone.
        let mut aces = match stock_program_files() {
            Dacl::Present(aces) => aces,
            Dacl::Absent => unreachable!(),
        };
        aces.push(Ace::deny(APP_PACKAGES, rights::WRITE_EQUIVALENT));
        aces.push(Ace::allow("S-1-5-11", rights::WRITE_DAC));
        assert_eq!(
            judge(&Dacl::Present(aces)),
            DaclVerdict::UnprivilegedWrite {
                sid: "S-1-5-11".to_string()
            }
        );
    }

    #[test]
    fn a_deny_for_a_different_principal_does_not_excuse_the_grant() {
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::deny(APP_PACKAGES, rights::WRITE_EQUIVALENT),
                Ace::allow(USERS, rights::WRITE_DATA),
            ])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            }
        );
    }

    #[test]
    fn an_inherit_only_grant_does_not_apply_to_the_object() {
        // `CREATOR OWNER:(OI)(CI)(IO)(F)` is on every stock Program Files tree; an inherit-only
        // ACE confers nothing on the directory carrying it.
        let inherit_only = Ace {
            inherit_only: true,
            ..Ace::allow(USERS, FULL)
        };
        assert_eq!(
            judge(&Dacl::Present(vec![inherit_only])),
            DaclVerdict::PrivilegedWriteOnly
        );
    }

    #[test]
    fn an_inherit_only_deny_does_not_excuse_an_applicable_grant() {
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace {
                    inherit_only: true,
                    ..Ace::deny(USERS, rights::WRITE_EQUIVALENT)
                },
                Ace::allow(USERS, rights::WRITE_DATA),
            ])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            }
        );
    }

    #[test]
    fn an_audit_ace_grants_nothing() {
        let audit = Ace {
            kind: AceKind::Other,
            ..Ace::allow(USERS, FULL)
        };
        assert_eq!(
            judge(&Dacl::Present(vec![audit])),
            DaclVerdict::PrivilegedWriteOnly
        );
    }

    #[test]
    fn a_null_dacl_is_a_finding_and_an_empty_one_is_not() {
        // The two states that look alike and are opposites: NULL grants EVERYONE full control,
        // while a present-but-empty DACL grants nobody anything.
        assert!(matches!(
            judge(&Dacl::Absent),
            DaclVerdict::UnprivilegedWrite { .. }
        ));
        assert_eq!(
            judge(&Dacl::Present(vec![])),
            DaclVerdict::PrivilegedWriteOnly
        );
    }
}
