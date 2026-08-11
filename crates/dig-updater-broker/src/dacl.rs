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
//! - a security descriptor we could **not read** is `None` from [`read_snapshot`], never a
//!   [`DaclVerdict`], and proves nothing — so the path is not honored, which is exactly the answer
//!   the owner check alone gave before this module existed (`READ_CONTROL` governs both halves of
//!   the descriptor, so neither can be read without the other);
//! - a DACL we **could** read and which is permissive DOES reject;
//! - a DENY ACE that PRECEDES a grant is subtracted from the same principal's allowed mask, so a
//!   directory an administrator hardened with an explicit deny over an inherited grant is not
//!   flagged. A DENY that FOLLOWS the grant is not subtracted, because Windows stops at the first
//!   matching ACE and so never reaches it — honouring it would let one `SetFileSecurityW` call
//!   silence this check while leaving the directory world-writable. The deny's trustee need not be
//!   the granted principal: a DENY to `Everyone` is applied by Windows to every requester, so it is
//!   subtracted too — and no other group is, because only a SUPERSET of every principal can be
//!   subtracted without excusing access someone still holds (see [`EVERYONE`]);
//! - an `INHERIT_ONLY` ACE grants nothing on the object itself and is ignored;
//! - an ACE whose CONDITION cannot be evaluated, whose TRUSTEE cannot be read, or which cannot be
//!   READ AT ALL, is assumed to grant, and the walk continues past it rather than collapsing. This is the one place the leniency stops, and it stops there because the alternative
//!   was measured: a conditional grant (`XA` with a trivially-true `Member_of{SID(WD)}`) and an
//!   object grant (`OA`) each left a directory an unprivileged process could plant a binary in
//!   while this module reported it clean — reachable, like the trailing-DENY bypass above, with a
//!   single `SetFileSecurityW` call needing only `WRITE_DAC`.
//!
//! Distinguishing "read the DACL, found nothing bad" from "could not read the descriptor" is the
//! whole point of [`read_snapshot`] returning an [`Option`]: a restrictive directory can enumerate
//! as empty rather than failing, and collapsing those two into one "clean" answer would be a false
//! all-clear. The `Option` is reserved for the DESCRIPTOR, never for an entry inside it — a single
//! unreadable ACE is a finding, not an absence of evidence.

/// A rights mask bit granting write-equivalent access to a directory — enough to plant, replace or
/// remove the binary a privileged schedule runs, or to re-ACL the directory so that one can.
///
/// `WRITE_DAC`/`WRITE_OWNER` are included because either one lets its holder grant itself the
/// rest. Both delete rights are included, and they are NOT the same right: `DELETE` removes the
/// install root itself, while `FILE_DELETE_CHILD` removes the binary INSIDE it — bypassing that
/// binary's own DACL. Either one is enough to make the daily privileged task fail, which is the
/// stale-pin harm this hardening exists to prevent, and `FILE_DELETE_CHILD` combined with
/// `FILE_ADD_FILE` is outright binary replacement.
mod rights {
    /// `FILE_WRITE_DATA` / `FILE_ADD_FILE`.
    pub const WRITE_DATA: u32 = 0x0000_0002;
    /// `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY`.
    pub const ADD_SUBDIRECTORY: u32 = 0x0000_0004;
    /// `FILE_DELETE_CHILD` — delete a child of this directory REGARDLESS of the child's own DACL.
    pub const DELETE_CHILD: u32 = 0x0000_0040;
    /// `DELETE` — delete this object itself.
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
        | DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_ALL
        | GENERIC_WRITE;
}

/// `INHERIT_ONLY_ACE` — the ACE applies to children only, never to the object carrying it.
const INHERIT_ONLY_ACE: u8 = 0x08;

/// Stands in for the trustee of an ACE whose SID could not be read — never a real SID, so it can
/// never match [`PRIVILEGED_SIDS`] and can only ever produce a finding.
const UNREADABLE_TRUSTEE: &str = "<object ACE: trustee unreadable>";

/// `Everyone` / `World` — the ONE group whose DENY may be subtracted from another principal's
/// grant.
///
/// The asymmetry is deliberate and must not be "tidied" into a list of groups. Subtracting a DENY
/// from a trustee other than the granted one is only sound when the denied group is a SUPERSET of
/// every principal the grant could reach: Windows applies a DENY to any group in the requester's
/// token, so a superset deny is reached by *every* requester and cannot subtract more than Windows
/// itself would. `Everyone` is that superset by definition. `Authenticated Users` (`S-1-5-11`) is
/// NOT — it excludes `ANONYMOUS LOGON` and `Guest` — so subtracting it would excuse a grant those
/// principals still hold, which is a real false negative on the check this module exists to be.
const EVERYONE: &str = "S-1-1-0";

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
    /// An ACE that neither grants access nor takes any away — an audit/alarm entry, or a DENY the
    /// parser cannot rely on (see [`read`] on conditional and object ACEs).
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

    for (index, ace) in entries.iter().enumerate() {
        if ace.kind != AceKind::Allow || ace.inherit_only || is_privileged_sid(&ace.sid) {
            continue;
        }
        // Only the ACEs Windows would have evaluated BEFORE this grant can take anything away from
        // it — see `denied_mask_for`.
        let denied = denied_mask_for(&entries[..index], &ace.sid);
        if ace.mask & rights::WRITE_EQUIVALENT & !denied != 0 {
            return DaclVerdict::UnprivilegedWrite {
                sid: ace.sid.clone(),
            };
        }
    }
    DaclVerdict::PrivilegedWriteOnly
}

/// Every bit denied to `sid` by an applicable DENY ACE in `preceding` — the ACEs that sit BEFORE
/// the grant under judgement.
///
/// The slice is a prefix on purpose. Windows evaluates a DACL strictly in order and stops at the
/// first ACE matching the requested access, so a DENY placed AFTER an ALLOW is never reached and
/// takes nothing away. `SetFileSecurityW` stores a non-canonical order verbatim, so an
/// allow-then-deny DACL is a real, reachable shape — and one an attacker holding `WRITE_DAC` (a bit
/// contained in the very `FILE_ALL_ACCESS` misconfiguration this module detects) could write to keep
/// full write access while making the check report clean. Honouring a DENY only where Windows
/// honours it closes that bypass while keeping the intended leniency for the canonical hardened
/// shape, which Windows itself canonicalizes to DENY-first.
///
/// A DENY counts when its trustee is the granted principal itself OR [`EVERYONE`], because Windows
/// applies a DENY to any group in the requester's token — matching on the granted SID alone missed
/// the commonest hardening there is (deny `Everyone` over an inherited grant) and REFUSED a
/// directory that was genuinely unwritable. The widening stops at [`EVERYONE`]; see that constant
/// for why a superset is the only sound generalization and why `Authenticated Users` is not one.
fn denied_mask_for(preceding: &[Ace], sid: &str) -> u32 {
    preceding
        .iter()
        .filter(|ace| {
            ace.kind == AceKind::Deny
                && !ace.inherit_only
                && (ace.sid == sid || ace.sid == EVERYONE)
        })
        .fold(0, |acc, ace| acc | ace.mask)
}

/// Whether a string SID names a principal expected to hold write access to a privileged root.
fn is_privileged_sid(sid: &str) -> bool {
    PRIVILEGED_SIDS.contains(&sid) || is_administrator_account(sid)
}

/// Whether `sid` is one of the domain-relative accounts/groups that are administrator-equivalent by
/// definition — the built-in `Administrator`, or the `Domain`/`Schema`/`Enterprise Admins` groups.
///
/// These cannot go in [`PRIVILEGED_SIDS`] because their SID embeds the machine's or domain's own
/// identifier (`S-1-5-21-<domain>-500`), so only the trailing RID is well known. Recognising them
/// is not a courtesy: a stock elevated Windows host grants the built-in Administrator full control
/// of the directories it creates, so treating RID 500 as an unprivileged writer reports a finding on
/// an ordinary machine — and a false refusal here stops the host updating at all, which is the
/// expensive direction (module docs).
///
/// The match is deliberately narrow. It requires the `S-1-5-21-` domain prefix AND a well-known
/// administrative RID, so an ordinary local account (`…-1001`) — the account an attacker would
/// actually control — is NOT covered by it.
fn is_administrator_account(sid: &str) -> bool {
    /// RID 500 `Administrator`, 512 `Domain Admins`, 518 `Schema Admins`, 519 `Enterprise Admins`.
    const ADMINISTRATIVE_RIDS: &[&str] = &["500", "512", "518", "519"];

    let Some(domain_and_rid) = sid.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let Some((domain, rid)) = domain_and_rid.rsplit_once('-') else {
        return false;
    };
    // A bare `S-1-5-21-500` has no domain identifier and is not a real account SID.
    !domain.is_empty() && ADMINISTRATIVE_RIDS.contains(&rid)
}

#[cfg(windows)]
pub(crate) use imp::read_snapshot;

#[cfg(all(windows, test))]
pub(crate) use imp::read;

/// Reading the real owner and DACL off a path — the one impure, Windows-only part of this module.
#[cfg(windows)]
mod imp {
    use super::{Ace, AceKind, Dacl};
    use std::path::Path;
    use windows::Win32::Security::ACL;

    /// Everything one security-descriptor read says about who may write a path.
    ///
    /// Owner and DACL travel together because they are read together — see [`read_snapshot`].
    pub struct Snapshot {
        /// Whether the owner SID is `BUILTIN\Administrators` or `Local System`.
        pub owner_is_privileged: bool,
        /// The DACL. [`Dacl::Absent`] is a NULL DACL — world-writable — and NOT the same as a
        /// present DACL holding no entries; neither is the same as [`read_snapshot`] answering
        /// `None`, which means the descriptor itself could not be read.
        pub dacl: Dacl,
    }

    /// Read `path`'s owner and DACL in ONE `GetNamedSecurityInfoW` call, or `None` if the security
    /// descriptor could not be read at all (including the path not existing).
    ///
    /// # Why one call and not two
    ///
    /// A security descriptor is MUTABLE, so two reads answer about two different objects-in-time.
    /// Reading the owner and then the DACL let an attacker holding `WRITE_DAC` — the very right a
    /// flagged `FILE_ALL_ACCESS` grant contains — pass the owner leg and then deny `READ_CONTROL`
    /// before the DACL leg, turning the deliberate "unreadable DACL accepts on the owner check
    /// alone" leniency into a bypass of the whole check. That is the same single-`SetFileSecurityW`
    /// precondition this module already refuses to trust for a trailing DENY. One call yields one
    /// consistent snapshot, and costs one syscall instead of two.
    pub fn read_snapshot(path: &Path) -> Option<Snapshot> {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{
            IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `GetNamedSecurityInfoW` writes `owner` and `dacl` (pointers INTO the descriptor
        // it allocates) and `descriptor` (LocalAlloc'd, freed below). On failure it touches none.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        // SAFETY: on success `owner` is a valid SID pointer within the returned descriptor.
        let owner_is_privileged = unsafe {
            IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
                || IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
        };
        // SAFETY: on success `dacl` is either NULL (no DACL) or a valid ACL inside `descriptor`,
        // which outlives the read because it is freed only after `entries` returns owned data.
        let parsed = if dacl.is_null() {
            Dacl::Absent
        } else {
            Dacl::Present(unsafe { entries(dacl) })
        };
        // SAFETY: exactly the allocation `GetNamedSecurityInfoW` returned, freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        Some(Snapshot {
            owner_is_privileged,
            dacl: parsed,
        })
    }

    /// Just the DACL half of [`read_snapshot`] — the shape the `judge` fixtures read against.
    #[cfg(test)]
    pub fn read(path: &Path) -> Option<Dacl> {
        Some(read_snapshot(path)?.dacl)
    }

    /// Walk every ACE in `acl` into owned [`Ace`] data.
    ///
    /// The walk always completes. An entry it cannot decode becomes a maximally-pessimistic GRANT
    /// ([`unreadable_grant`]) rather than aborting the read, because the caller reads a failed read
    /// as "no descriptor" and accepts on the owner check alone — see the arms below.
    ///
    /// # Safety
    ///
    /// `acl` must be a valid, non-NULL `ACL` that outlives the call.
    unsafe fn entries(acl: *mut ACL) -> Vec<Ace> {
        use windows::Win32::Security::{GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER};
        use windows::Win32::System::SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
        };

        // SAFETY: the caller guarantees `acl` is a valid ACL.
        let count = u32::from(unsafe { (*acl).AceCount });
        let mut out = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut raw: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the ACL's own AceCount, so the ACE should exist; a
            // malformed ACL whose header over-counts is handled by the failure arm.
            if unsafe { GetAce(acl, index, &mut raw) }.is_err() || raw.is_null() {
                // The entry we could not read is exactly the one that might carry the permissive
                // grant, so it counts as GRANTING and the walk CONTINUES. Aborting to `None` would
                // report "no descriptor", which the caller accepts on the owner check alone — a
                // fail-OPEN reachable after the owner read has already succeeded, so nothing
                // upstream refuses on its behalf.
                out.push(unreadable_grant(false));
                continue;
            }
            // SAFETY: `GetAce` yielded a pointer to a well-formed ACE, whose header is its first
            // field for every ACE type.
            let header = unsafe { *raw.cast::<ACE_HEADER>() };
            let inherit_only = header.AceFlags & super::INHERIT_ONLY_ACE != 0;
            let kind = match u32::from(header.AceType) {
                // The CALLBACK variants lay out `{header, mask, SidStart}` exactly like their
                // basic equivalents — the conditional expression trails the SID — so the code
                // below reads them correctly. The condition itself is NOT evaluated, and the
                // asymmetry in how that is handled is deliberate: a grant whose condition cannot
                // be evaluated is assumed to APPLY (it is a finding), while a deny whose condition
                // cannot be evaluated is assumed NOT to apply (it excuses nothing). Both halves
                // refuse to take an unevaluable condition as evidence of safety, because Windows —
                // which CAN evaluate it — may well grant, and a trivially-true condition such as
                // `Member_of{SID(WD)}` always does.
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => AceKind::Allow,
                ACCESS_DENIED_ACE_TYPE => AceKind::Deny,
                ACCESS_DENIED_CALLBACK_ACE_TYPE => AceKind::Other,
                // The OBJECT variants carry `Flags` and up to two GUIDs BETWEEN the mask and the
                // trailing SID, so their trustee genuinely cannot be read at the basic layout's
                // offset — reading it there would yield a SID from the wrong bytes, possibly
                // resolving to a privileged principal and excusing the grant. An ALLOW whose
                // trustee is unknown must therefore be a FINDING: on a file object the kernel
                // ignores the object-type GUID and applies the mask in full, so this ACE really
                // does grant, to a principal we cannot name. This is the same policy the
                // unreadable-ACE arm above applies, for the same reason.
                ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    out.push(unreadable_grant(inherit_only));
                    continue;
                }
                // A DENY whose trustee is unreadable can be dropped rather than flagged: it grants
                // nothing, and `judge` only ever subtracts a DENY from a trustee it matches by
                // name, so an unnamed one could never have excused anything.
                ACCESS_DENIED_OBJECT_ACE_TYPE | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {
                    AceKind::Other
                }
                // What remains is audit/alarm, which lives in the SACL and cannot appear in a DACL
                // at all — plus any type a future Windows adds. Both grant nothing here.
                _ => AceKind::Other,
            };
            if kind == AceKind::Other {
                out.push(Ace {
                    kind,
                    sid: String::new(),
                    mask: 0,
                    inherit_only,
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
            let Some(sid) = (unsafe { sid_string(raw.byte_add(sid_offset)) }) else {
                // Same policy as the object-ACE arm below, for the same reason: an ALLOW whose
                // trustee cannot be named could name anyone, so it is a finding. A DENY whose
                // trustee cannot be named is DROPPED rather than flagged — it grants nothing, and
                // an unnamed deny could never have excused a grant anyway.
                if kind == AceKind::Allow {
                    out.push(unreadable_grant(inherit_only));
                }
                continue;
            };
            out.push(Ace {
                kind,
                sid,
                mask,
                inherit_only,
            });
        }
        out
    }

    /// An ACE the parser could not decode, rendered in the only shape that cannot become a false
    /// all-clear: a grant of EVERY right to a trustee that can never be privileged.
    ///
    /// [`super::UNREADABLE_TRUSTEE`] is not a real SID, so it never matches
    /// [`super::PRIVILEGED_SIDS`] and can only ever produce a finding.
    fn unreadable_grant(inherit_only: bool) -> Ace {
        Ace {
            kind: AceKind::Allow,
            sid: super::UNREADABLE_TRUSTEE.to_string(),
            mask: u32::MAX,
            inherit_only,
        }
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

    #[cfg(test)]
    mod unreadable_ace {
        use super::{entries, ACL};
        use crate::dacl::{judge, Dacl, DaclVerdict};

        /// An ACL header claiming an ACE the buffer does not contain, so `GetAce` FAILS on it.
        ///
        /// `ACL` must be DWORD-aligned, which the wrapper guarantees.
        #[repr(align(4))]
        struct AlignedAcl(ACL);

        #[test]
        fn an_ace_that_cannot_be_read_is_a_finding_not_an_accept() {
            // Aborting the walk on an unreadable ACE returned `None`, and `None` means "no
            // descriptor" — which `secure` deliberately ACCEPTS on the owner check alone. That
            // leniency is defensible only where it fires BEFORE anything is read (`READ_CONTROL`
            // governs the owner read too, so the owner leg refuses first); mid-walk, nothing
            // upstream refuses on its behalf. An ACE we cannot decode is exactly the ACE that might
            // carry the permissive grant, so it must count as GRANTING — the policy the object-ACE
            // and conditional-ACE arms already apply.
            let mut acl = AlignedAcl(ACL {
                AclRevision: 2,
                Sbz1: 0,
                AclSize: u16::try_from(size_of::<ACL>()).expect("the ACL header is 8 bytes"),
                AceCount: 1,
                Sbz2: 0,
            });
            // SAFETY: a well-formed, correctly-aligned ACL header that outlives the call. Its
            // AceCount deliberately exceeds the bytes present, which is precisely the read failure
            // under test.
            let walked = unsafe { entries(&mut acl.0) };
            assert_eq!(
                walked.len(),
                1,
                "the claimed ACE must still be accounted for"
            );
            assert!(
                matches!(
                    judge(&Dacl::Present(walked)),
                    DaclVerdict::UnprivilegedWrite { .. }
                ),
                "an ACE that cannot be read must count as granting, never as an accept"
            );
        }
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
    fn the_built_in_administrator_account_may_hold_write_access() {
        // Measured, not assumed: an elevated process on a stock Windows host creates directories
        // whose DACL grants RID 500 full control, so flagging it refuses an ordinary machine. The
        // SID below is the shape a real runner produced.
        for sid in [
            "S-1-5-21-1178926710-2200278958-3596451971-500",
            // Domain Admins / Schema Admins / Enterprise Admins.
            "S-1-5-21-1178926710-2200278958-3596451971-512",
            "S-1-5-21-1178926710-2200278958-3596451971-518",
            "S-1-5-21-1178926710-2200278958-3596451971-519",
        ] {
            assert_eq!(
                judge(&Dacl::Present(vec![Ace::allow(sid, FULL)])),
                DaclVerdict::PrivilegedWriteOnly,
                "{sid} is administrator-equivalent"
            );
        }
    }

    #[test]
    fn the_administrative_rid_match_does_not_spread_to_ordinary_accounts() {
        // The guard rail on the rule above. Each of these ends in or contains an administrative
        // RID's digits without BEING one, and every one of them must still be a finding —
        // otherwise the RID check has become a way to launder an attacker-controlled account SID.
        for sid in [
            // An ordinary local account — the SID an attacker actually controls.
            "S-1-5-21-1178926710-2200278958-3596451971-1001",
            // RID 500's digits as a prefix of a larger RID.
            "S-1-5-21-1178926710-2200278958-3596451971-5000",
            // An administrative RID in the DOMAIN position rather than the RID position.
            "S-1-5-21-500-2200278958-3596451971-1001",
            // The right RID under the wrong authority (not a `S-1-5-21-` account SID).
            "S-1-5-32-500",
            // No domain identifier at all.
            "S-1-5-21-500",
        ] {
            assert_eq!(
                judge(&Dacl::Present(vec![Ace::allow(sid, FULL)])),
                DaclVerdict::UnprivilegedWrite {
                    sid: sid.to_string()
                },
                "{sid} must not be mistaken for an administrative account"
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
    fn a_deny_counts_only_where_windows_would_reach_it() {
        // The two orders are NOT equivalent, and treating them as if they were was a real bypass:
        // Windows evaluates ACEs in sequence and stops at the first match, so a DENY placed AFTER
        // an ALLOW never runs. `SetFileSecurityW` stores that non-canonical order verbatim, and
        // writing it needs only `WRITE_DAC` — a bit inside the very FILE_ALL_ACCESS grant this
        // module exists to flag. Subtracting the trailing DENY therefore let an attacker who
        // already held full write make the directory report clean, with one call and no elevation.
        // Measured on Windows 11: a directory with `D:P(A;;FA;;;BU)(D;;FA;;;BU)` accepted a planted
        // binary from an unprivileged process, while `D:P(D;;FA;;;BU)(A;;FA;;;BU)` refused one.
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::deny(USERS, rights::WRITE_EQUIVALENT),
                Ace::allow(USERS, FULL),
            ])),
            DaclVerdict::PrivilegedWriteOnly,
            "a DENY before the grant is honoured by Windows, so it must be honoured here — the \
             canonical hardened shape must keep installing"
        );
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::allow(USERS, FULL),
                Ace::deny(USERS, rights::WRITE_EQUIVALENT),
            ])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            },
            "a DENY after the grant is unreachable on Windows and must not excuse it"
        );
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::allow(USERS, FULL),
                Ace::deny(EVERYONE, rights::WRITE_EQUIVALENT),
            ])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            },
            "position bounds the Everyone widening exactly as it bounds the same-SID case: a \
             trailing Everyone deny is just as unreachable"
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
    fn a_deny_for_an_unrelated_non_superset_principal_does_not_excuse_the_grant() {
        // Each denied trustee here is a principal a `BUILTIN\Users` member need NOT be — so Windows
        // may never reach the DENY at all when that member requests access, and subtracting it
        // would be a false all-clear. `Everyone` is deliberately absent from this list: it IS a
        // superset of `Users`, Windows DOES apply it, and the case it covers is
        // `an_everyone_deny_preceding_a_grant_is_honoured_because_everyone_contains_the_grantee`.
        for denied in [
            APP_PACKAGES,
            // Authenticated Users — the near-miss. It looks like a superset and is not: ANONYMOUS
            // LOGON and Guest are in `Users`-reachable tokens without being authenticated, so
            // subtracting it would create a real false negative.
            "S-1-5-11",
            // INTERACTIVE — absent from a service or network logon token.
            "S-1-5-4",
        ] {
            assert_eq!(
                judge(&Dacl::Present(vec![
                    Ace::deny(denied, rights::WRITE_EQUIVALENT),
                    Ace::allow(USERS, rights::WRITE_DATA),
                ])),
                DaclVerdict::UnprivilegedWrite {
                    sid: USERS.to_string()
                },
                "a DENY to {denied} does not necessarily reach a {USERS} member"
            );
        }
    }

    #[test]
    fn an_everyone_deny_preceding_a_grant_is_honoured_because_everyone_contains_the_grantee() {
        // The canonical hardening an administrator (or a vulnerability scanner's published
        // remediation) applies over an inherited grant: deny `Everyone`, leave the grant in place.
        // Windows evaluates the DENY against every token, so the directory really is unwritable —
        // and matching the deny's trustee to the grant's by STRING EQUALITY missed it entirely,
        // refusing `schedule install` on precisely the hosts that hardened themselves.
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::deny(EVERYONE, rights::WRITE_EQUIVALENT),
                Ace::allow(USERS, FULL),
                Ace::allow(SYSTEM, FULL),
            ])),
            DaclVerdict::PrivilegedWriteOnly,
            "a preceding Everyone DENY reaches every principal, so it neutralizes the grant"
        );
    }

    #[test]
    fn an_everyone_deny_is_still_bounded_by_mask() {
        // The widening to `Everyone` inherits the existing mask bound rather than escaping it; the
        // POSITION bound is pinned beside its same-SID twin in
        // `a_deny_counts_only_where_windows_would_reach_it`.
        assert_eq!(
            judge(&Dacl::Present(vec![
                Ace::deny(EVERYONE, rights::DELETE),
                Ace::allow(USERS, rights::DELETE | rights::WRITE_DATA),
            ])),
            DaclVerdict::UnprivilegedWrite {
                sid: USERS.to_string()
            },
            "a PARTIAL Everyone deny leaves the remaining write-equivalent bits granted"
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

    /// The fixture battery above never touches [`read`], so an ACL shape the OS can hold but the
    /// parser mis-reads would be invisible to every test in it — which is exactly how a
    /// non-canonical allow-then-deny DACL passed 18 green tests. These build REAL directories with
    /// REAL ACLs and run the whole `read` → `judge` path over them.
    ///
    /// They need no elevation: an ordinary user owns the directories it creates in `%TEMP%` and so
    /// already holds `WRITE_DAC` over them.
    #[cfg(windows)]
    mod real_acls {
        use super::super::{judge, read, Dacl, DaclVerdict};
        use std::path::Path;

        /// Replace `path`'s DACL with the one `sddl` describes, protected from inheritance.
        ///
        /// `SetFileSecurityW` writes the ACE sequence VERBATIM — it does not canonicalize — which is
        /// what makes a non-canonical allow-then-deny order reachable in the first place.
        fn set_dacl(path: &Path, sddl: &str) {
            use std::os::windows::ffi::OsStrExt;
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::{LocalFree, HLOCAL};
            use windows::Win32::Security::{SetFileSecurityW, DACL_SECURITY_INFORMATION};

            let wide_path: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let descriptor = sddl_to_descriptor(sddl).expect("SDDL must convert");
            // SAFETY: `descriptor` is the valid descriptor just converted.
            unsafe {
                SetFileSecurityW(
                    PCWSTR(wide_path.as_ptr()),
                    DACL_SECURITY_INFORMATION,
                    descriptor,
                )
            }
            .expect("the test process owns the directory, so it may re-DACL it");
            // SAFETY: exactly the allocation the conversion returned, freed once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
        }

        /// Convert an SDDL string into a security descriptor, surfacing the conversion FAILURE as
        /// an error rather than a panic — some shapes (an audit ACE inside a `D:` section) are
        /// deliberately unrepresentable, and a test asserts exactly that.
        fn sddl_to_descriptor(
            sddl: &str,
        ) -> windows::core::Result<windows::Win32::Security::PSECURITY_DESCRIPTOR> {
            use windows::core::PCWSTR;
            use windows::Win32::Security::Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            };
            use windows::Win32::Security::PSECURITY_DESCRIPTOR;

            let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            // SAFETY: the input is a NUL-terminated wide string; on success the descriptor is
            // LocalAlloc'd and freed by the caller.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide_sddl.as_ptr()),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    None,
                )
            }?;
            Ok(descriptor)
        }

        /// Whether an UNPRIVILEGED principal can actually create a file here — the ground truth the
        /// verdict is being compared against. The test process is a member of `BUILTIN\Users`, so
        /// its own success or failure IS the answer for a `BU`-granting DACL.
        ///
        /// **The probe answers for the CURRENT process, so a fixture must not grant any group this
        /// process belongs to other than the trustee under test.** In particular it must not grant
        /// `BA`: CI runs elevated (the GitHub Windows runner is a local Administrator that is also
        /// in `BUILTIN\Users`), so an `(A;;FA;;;BA)` ACE satisfies this probe no matter what the
        /// ACE under test does — turning every ground truth below into a measurement of the
        /// runner's own privilege. That is not hypothetical: it made
        /// `a_grant_whose_condition_is_false_is_still_a_finding` fail on CI while passing on an
        /// unelevated developer machine, and it silently hollowed out the positive cases, which
        /// were passing on the `BA` grant rather than on the grant they claim to exercise.
        fn a_file_can_be_planted(dir: &Path) -> bool {
            std::fs::write(dir.join("planted.exe"), b"MZ").is_ok()
        }

        #[test]
        fn a_trailing_deny_does_not_hide_a_world_writable_directory() {
            let root = tempfile::tempdir().expect("temp dir");
            let dir = root.path().join("allow-then-deny");
            std::fs::create_dir(&dir).expect("create");
            // Non-canonical on purpose: Windows stops at the leading ALLOW, so `BUILTIN\Users`
            // really does hold full control here.
            set_dacl(&dir, "D:P(A;;FA;;;BU)(D;;FA;;;BU)");

            assert!(
                a_file_can_be_planted(&dir),
                "ground truth: this directory IS writable by an unprivileged principal"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::UnprivilegedWrite {
                    sid: "S-1-5-32-545".to_string()
                },
                "a writable directory must be a finding whatever order the DENY sits in"
            );
        }

        #[test]
        fn the_canonical_hardened_shape_is_still_accepted() {
            let root = tempfile::tempdir().expect("temp dir");
            let dir = root.path().join("deny-then-allow");
            std::fs::create_dir(&dir).expect("create");
            // The order Windows itself canonicalizes to: the DENY is reached first and wins.
            set_dacl(&dir, "D:P(D;;FA;;;BU)(A;;FA;;;BU)(A;;FA;;;SY)");

            assert!(
                !a_file_can_be_planted(&dir),
                "ground truth: the leading DENY really does make this unwritable"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::PrivilegedWriteOnly,
                "refusing a genuinely hardened directory would stop the host updating at all"
            );
        }

        #[test]
        fn an_inherited_grant_is_read_off_the_child() {
            let root = tempfile::tempdir().expect("temp dir");
            let parent = root.path().join("parent");
            std::fs::create_dir(&parent).expect("create");
            // `OICI` — object- and container-inherit, NOT inherit-only, so the child carries an
            // applicable grant it never had written to it directly.
            set_dacl(&parent, "D:P(A;OICI;FA;;;BU)(A;OICI;FA;;;SY)");
            let child = parent.join("child");
            std::fs::create_dir(&child).expect("create");

            let Some(Dacl::Present(entries)) = read(&child) else {
                panic!("the child's DACL must be readable and present");
            };
            assert!(
                entries.iter().any(|ace| ace.sid == "S-1-5-32-545" && !ace.inherit_only),
                "the inherited Users grant must arrive as an ACE that applies to the child itself, \
                 got {entries:?}"
            );
            assert_eq!(
                judge(&Dacl::Present(entries)),
                DaclVerdict::UnprivilegedWrite {
                    sid: "S-1-5-32-545".to_string()
                }
            );
        }

        #[test]
        fn a_null_dacl_read_off_a_real_directory_is_a_finding() {
            let root = tempfile::tempdir().expect("temp dir");
            let dir = root.path().join("null-dacl");
            std::fs::create_dir(&dir).expect("create");
            // `D:NO_ACCESS_CONTROL` is how SDDL spells a NULL DACL — the world-writable state that
            // enumerates as no entries at all, and the one the parser must NOT report as clean.
            set_dacl(&dir, "D:NO_ACCESS_CONTROL");

            assert_eq!(
                read(&dir),
                Some(Dacl::Absent),
                "a NULL DACL must arrive as `Absent`, never as an empty `Present`"
            );
            assert!(matches!(
                judge(&read(&dir).expect("the descriptor is readable")),
                DaclVerdict::UnprivilegedWrite { .. }
            ));
        }

        /// `BUILTIN\Users`, the trustee every exploit below grants to.
        const USERS: &str = "S-1-5-32-545";
        /// `Authenticated Users`.
        const AUTHENTICATED_USERS: &str = "S-1-5-11";

        /// A directory carrying a deliberately hostile DACL, which reopens itself on the way out.
        ///
        /// Several fixtures leave the directory unwritable even by the process that made it, so
        /// [`tempfile::TempDir`]'s recursive delete would fail and silently litter the temp
        /// directory. The test process OWNS the directory and an owner implicitly holds
        /// `WRITE_DAC`, so it can always put a permissive DACL back — which is what makes cleanup
        /// reliable rather than best-effort.
        struct Fixture {
            root: tempfile::TempDir,
            dir: std::path::PathBuf,
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                // Everyone full control, so the recursive delete below can proceed.
                set_dacl(&self.dir, "D:P(A;;FA;;;WD)");
                let _ = &self.root;
            }
        }

        /// Build a directory with `sddl` as its protected DACL.
        ///
        /// `sddl` MUST NOT grant `BA` — see [`a_file_can_be_planted`] for why an Administrators
        /// grant destroys the ground truth these fixtures exist to provide.
        fn dir_with_dacl(name: &str, sddl: &str) -> (Fixture, std::path::PathBuf) {
            assert!(
                !sddl.contains(";BA)"),
                "a fixture must not grant BA: it would satisfy the ground-truth probe on an \
                 elevated runner regardless of the ACE under test"
            );
            let root = tempfile::tempdir().expect("temp dir");
            let dir = root.path().join(name);
            std::fs::create_dir(&dir).expect("create");
            set_dacl(&dir, sddl);
            (
                Fixture {
                    root,
                    dir: dir.clone(),
                },
                dir,
            )
        }

        #[test]
        fn a_conditional_grant_is_a_finding_because_its_condition_is_true() {
            // `Member_of{SID(WD)}` holds for EVERY token — everyone is in `Everyone` — so the
            // kernel really does hand `BUILTIN\Users` FILE_ALL_ACCESS here. Scoring a callback ACE
            // as granting nothing let one `SetFileSecurityW` call (needing only WRITE_DAC, a bit
            // inside the very FILE_ALL_ACCESS grant this module detects) silence the check while
            // leaving the directory world-writable.
            let (_root, dir) = dir_with_dacl(
                "callback-allow",
                "D:P(XA;;FA;;;BU;(Member_of{SID(WD)}))(A;;FA;;;SY)",
            );

            assert!(
                a_file_can_be_planted(&dir),
                "ground truth: Windows honours the conditional ACE and this directory IS writable"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::UnprivilegedWrite {
                    sid: USERS.to_string()
                },
            );
        }

        #[test]
        fn a_conditional_grant_to_authenticated_users_is_a_finding() {
            // The same bypass under a different trustee and a different (also always-true)
            // condition, so the fix cannot be a special case for one SID.
            let (_root, dir) = dir_with_dacl(
                "callback-allow-au",
                "D:P(XA;;FA;;;AU;(Member_of{SID(AU)}))(A;;FA;;;SY)",
            );

            assert!(
                a_file_can_be_planted(&dir),
                "ground truth: an authenticated token is in Authenticated Users, so this is writable"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::UnprivilegedWrite {
                    sid: AUTHENTICATED_USERS.to_string()
                },
            );
        }

        #[test]
        fn the_attacker_rewrite_of_a_flagged_directory_stays_flagged() {
            // The exploit in the shape an attacker actually reaches it: start from the classic
            // misconfiguration this module already flags, then spend the WRITE_DAC that grant
            // contains on ONE `SetFileSecurityW` rewriting it to a conditional form. The owner is
            // untouched, so the owner leg keeps passing, and the directory stays writable.
            let (_root, dir) = dir_with_dacl("attacker-rewrite", "D:P(A;;FA;;;BU)(A;;FA;;;SY)");
            assert!(matches!(
                judge(&read(&dir).expect("readable")),
                DaclVerdict::UnprivilegedWrite { .. }
            ));

            set_dacl(&dir, "D:P(XA;;FA;;;WD;(Member_of{SID(BU)}))(A;;FA;;;SY)");
            assert!(
                a_file_can_be_planted(&dir),
                "ground truth: the rewrite changed the verdict, not the writability"
            );
            assert!(
                matches!(
                    judge(&read(&dir).expect("readable")),
                    DaclVerdict::UnprivilegedWrite { .. }
                ),
                "an attacker must not be able to launder a flagged directory into a clean verdict"
            );
        }

        #[test]
        fn a_grant_whose_condition_is_false_is_still_a_finding() {
            // Deliberate, documented over-refusal. `@USER.ex` is an attribute no ordinary token
            // carries, so this condition is FALSE and the directory is genuinely unwritable — yet
            // it is reported as a finding, because the parser does not evaluate conditions and a
            // condition assumed false is exactly how the bypass above worked. Erring toward a
            // finding on an unevaluable grant is the safe direction; conditional ACEs do not occur
            // on real install roots, so the availability cost is nil (see the control tests).
            let (_root, dir) = dir_with_dacl(
                "condition-false",
                "D:P(XA;;FA;;;BU;(@USER.ex==1))(A;;FA;;;SY)",
            );

            assert!(
                !a_file_can_be_planted(&dir),
                "ground truth: an unsatisfiable condition really does withhold the grant"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::UnprivilegedWrite {
                    sid: USERS.to_string()
                },
                "an unevaluable condition must never be read as evidence of safety"
            );
        }

        #[test]
        fn an_object_grant_is_a_finding_even_though_its_trustee_is_unreadable() {
            // For a FILE object the kernel ignores the object-type GUID and applies the mask, so
            // this grants `BUILTIN\Users` full control. The parser cannot read the trustee — the
            // GUIDs sit between the mask and the SID — which is precisely why the ACE must be a
            // FINDING and not an excuse: an unreadable trustee could be anyone.
            let (_root, dir) = dir_with_dacl(
                "object-allow",
                "D:P(OA;;FA;;bf967aba-0de6-11d0-a285-00aa003049e2;BU)(A;;FA;;;SY)",
            );

            assert!(
                a_file_can_be_planted(&dir),
                "ground truth: the object-type GUID is ignored on a file, so this IS writable"
            );
            assert!(
                matches!(
                    judge(&read(&dir).expect("the DACL is readable")),
                    DaclVerdict::UnprivilegedWrite { .. }
                ),
                "an object ACE whose trustee cannot be read must never read as clean"
            );
        }

        #[test]
        fn file_delete_child_alone_is_a_finding_because_the_binary_can_be_removed() {
            // `FILE_DELETE_CHILD` (0x40) is the right to delete a child bypassing the child's OWN
            // DACL — distinct from `DELETE` (0x0001_0000), which deletes the directory itself.
            // Alone it is a denial-of-update primitive: the beacon binary vanishes, the SYSTEM
            // daily task fails, and the host silently stops receiving security updates.
            let (_root, dir) = dir_with_dacl("delete-child", "D:P(A;;FA;;;BU)");
            let binary = dir.join("dig-updater.exe");
            std::fs::write(&binary, b"MZ").expect("seed the binary before locking the directory");
            set_dacl(&dir, "D:P(A;;0x40;;;BU)(A;;0x1200a9;;;BU)(A;;FA;;;SY)");

            assert!(
                std::fs::remove_file(&binary).is_ok(),
                "ground truth: FILE_DELETE_CHILD really does let the binary be deleted"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::UnprivilegedWrite {
                    sid: USERS.to_string()
                },
            );
        }

        #[test]
        fn an_audit_ace_cannot_be_written_into_a_dacl() {
            // The claim that makes tightening the unparsed-ACE arm free of availability cost:
            // audit/alarm ACEs live in the SACL, so no DACL a caller could hand us contains one.
            // Verified rather than assumed — SDDL refuses to place one in the `D:` section.
            let root = tempfile::tempdir().expect("temp dir");
            let dir = root.path().join("audit-in-dacl");
            std::fs::create_dir(&dir).expect("create");
            assert!(
                sddl_to_descriptor("D:P(AU;;FA;;;BU)").is_err(),
                "an audit ACE must be unrepresentable in a DACL"
            );
        }

        #[test]
        fn an_everyone_deny_really_does_make_a_users_granting_directory_unwritable() {
            // The NEGATIVE ground truth, and the one the fixture battery cannot supply: only the
            // OS can say whether `Everyone:(DENY)` actually reaches a `BUILTIN\Users` member. It
            // does — so a verdict of `UnprivilegedWrite` here would refuse a directory that is
            // genuinely hardened, and a refused `schedule install` means the host stops receiving
            // security updates entirely.
            //
            // The DENY covers the write-equivalent mask in FULL on purpose. Denying only
            // `WD,AD,DC` while leaving `Users:(F)` in place would still leave that principal
            // `WRITE_DAC`, i.e. the right to lift the deny — that directory is NOT hardened and
            // this module is right to flag it.
            let (_root, dir) =
                dir_with_dacl("everyone-deny", "D:P(D;;FA;;;WD)(A;;FA;;;BU)(A;;FA;;;SY)");

            assert!(
                !a_file_can_be_planted(&dir),
                "ground truth: the Everyone DENY really does make this directory unwritable"
            );
            assert_eq!(
                judge(&read(&dir).expect("the DACL is readable")),
                DaclVerdict::PrivilegedWriteOnly,
                "refusing a genuinely hardened directory would stop the host updating at all"
            );
        }

        #[test]
        fn a_stock_system_directory_reads_as_privileged_write_only() {
            // The other direction of the same instrument: a real, untouched, hardened OS directory
            // must not be flagged, or `schedule install` refuses on every stock machine.
            let system32 = Path::new("C:\\Windows\\System32");
            assert_eq!(
                judge(&read(system32).expect("System32's DACL is readable")),
                DaclVerdict::PrivilegedWriteOnly
            );
        }
    }
}
