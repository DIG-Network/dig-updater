//! A total, panic-free reader for an ELF file's DYNAMIC LINKING requirements (dig_ecosystem#1870).
//!
//! The beacon needs one fact about an artifact it is about to install: which shared libraries the
//! dynamic linker will demand before the binary's `main` ever runs. The signed manifest offers ONE
//! `linux/x64` build per component, and for a desktop-linked component that build can name libraries
//! a headless server does not have (`libgtk-3.so.0`, `libgdk-3.so.0`, …). Installing it there
//! replaces a working binary with one that dies at `ld.so`.
//!
//! The obvious way to learn that is to ask the loader — run the binary, or `ldd` it. This module
//! exists because the beacon may do NEITHER. It runs as SYSTEM/root, and the component whose
//! artifact most needs this check ([`crate::plan::DIG_APP_COMPONENT_NAME`]) parses no arguments:
//! executing it seals a master seed and binds a signing socket. `ldd` is itself a loader invocation
//! on attacker-adjacent bytes, and a spawn's decision would live behind `#[cfg(unix)]`, unfalsifiable
//! on a Windows developer host. So the requirements are read out of the file's own bytes, statically.
//!
//! Only the fields that answer that one question are decoded: the identification bytes, the program
//! headers (`PT_INTERP`, `PT_DYNAMIC`, `PT_LOAD` for address translation) and the dynamic entries
//! `DT_NEEDED` / `DT_STRTAB` / `DT_STRSZ` / `DT_RPATH` / `DT_RUNPATH`.
//!
//! **Every read is bounds-checked, and that is a security property, not tidiness.** These bytes are
//! a downloaded artifact, parsed inside the privileged pass. A panic here would abort the pass — so a
//! malformed file would stop the host updating AT ALL, which is a denial of service on the update
//! channel itself. A truncated, hostile, or simply non-ELF file therefore yields an
//! [`ElfParseError`], and no length read out of the file is ever used to allocate.

use std::ops::Range;

/// Why an artifact's dynamic requirements could not be read. Every variant means "no answer",
/// never "no requirements" — the caller must treat them as INDETERMINATE and never as `Loadable`
/// (see [`crate::loadable`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfParseError {
    /// The file is not an ELF image at all (a `.deb`, an `.msi`, a Windows PE, a script, a stub).
    NotElf,
    /// A valid ELF this reader deliberately does not decode, with the reason (an encoding or an
    /// image kind whose dynamic requirements this reader cannot state honestly).
    Unsupported(&'static str),
    /// The file ended — or a structure pointed — outside the bytes provided.
    Truncated,
}

impl std::fmt::Display for ElfParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotElf => write!(f, "not an ELF image"),
            Self::Unsupported(why) => write!(f, "unsupported ELF image: {why}"),
            Self::Truncated => write!(f, "the ELF image is truncated or self-inconsistent"),
        }
    }
}

/// What the dynamic linker will require of an ELF image before it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElfNeeds {
    /// The machine the image is built for (`e_machine`, e.g. [`EM_X86_64`]). `0` (`EM_NONE`) means
    /// the image names no machine, which is never treated as a mismatch.
    ///
    /// An artifact for the wrong machine dies at `execve` with `Exec format error` no matter how
    /// resolvable its sonames are — and a `linux/arm64` build's sonames (`libc.so.6`,
    /// `libgcc_s.so.1`) all resolve perfectly on an x86-64 host, so the soname check alone would
    /// call it loadable.
    pub machine: u16,
    /// The program interpreter (`PT_INTERP`, e.g. `/lib64/ld-linux-x86-64.so.2`) — `None` for a
    /// static image, which needs no loader at all.
    pub interp: Option<String>,
    /// The `DT_NEEDED` sonames, in link order.
    pub needed: Vec<String>,
    /// The image's own search path (`DT_RUNPATH`, else the legacy `DT_RPATH`), split on `:` and
    /// UNEXPANDED — `$ORIGIN` is still literal here, because expanding it needs the artifact's
    /// final location, which is the caller's knowledge and not the file's.
    pub runpath: Vec<String>,
}

// --- the only ELF constants this reader needs ---

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

// --- the machine values this reader can name; every other value is compared numerically ---

/// `EM_386` — 32-bit x86.
pub const EM_386: u16 = 3;
/// `EM_ARM` — 32-bit ARM.
pub const EM_ARM: u16 = 40;
/// `EM_X86_64` — 64-bit x86.
pub const EM_X86_64: u16 = 62;
/// `EM_AARCH64` — 64-bit ARM.
pub const EM_AARCH64: u16 = 183;
/// `EM_RISCV` — RISC-V.
pub const EM_RISCV: u16 = 243;

/// A ceiling on how many `DT_NEEDED` entries are resolved from one image.
///
/// This is what makes [`crate::loadable`]'s byte ceiling mean something. Without it the work is
/// QUADRATIC in the file size: the dynamic array holds up to `size / 16` `DT_NEEDED` entries, and a
/// string table that is one unterminated blob makes each of them resolve to a string up to `size`
/// long — so a 200 KB artifact allocates tens of MB, inside the privileged pass. No real image links
/// against thousands of libraries; a file that claims to is malformed, and an honest error is the
/// right answer.
const MAX_NEEDED_ENTRIES: usize = 512;

/// A ceiling on the length of any single string resolved out of the dynamic string table. A soname or
/// a runpath is a filesystem name; nothing legitimate is longer than this, and the bound is the other
/// half of [`MAX_NEEDED_ENTRIES`]'s quadratic-allocation fix.
const MAX_STRING_BYTES: usize = 4096;

/// The ELF header size + program-header layout for the image's class (32- vs 64-bit). The two
/// classes differ only in field WIDTHS and OFFSETS, so isolating those here keeps one parser body
/// instead of two near-identical ones that could drift.
struct Layout {
    /// Whether addresses/offsets are 8 bytes wide (64-bit) rather than 4.
    wide: bool,
    /// Offset of `e_phoff` in the ELF header.
    e_phoff: usize,
    /// Offset of `e_phentsize` in the ELF header.
    e_phentsize: usize,
    /// Offset of `e_phnum` in the ELF header.
    e_phnum: usize,
    /// Offset of `p_offset` in a program header.
    p_offset: usize,
    /// Offset of `p_vaddr` in a program header.
    p_vaddr: usize,
    /// Offset of `p_filesz` in a program header.
    p_filesz: usize,
}

const LAYOUT_64: Layout = Layout {
    wide: true,
    e_phoff: 0x20,
    e_phentsize: 0x36,
    e_phnum: 0x38,
    p_offset: 0x08,
    p_vaddr: 0x10,
    p_filesz: 0x20,
};

const LAYOUT_32: Layout = Layout {
    wide: false,
    e_phoff: 0x1c,
    e_phentsize: 0x2a,
    e_phnum: 0x2c,
    p_offset: 0x04,
    p_vaddr: 0x08,
    p_filesz: 0x10,
};

/// Read `bytes`' dynamic-linking requirements ([`ElfNeeds`]).
///
/// Total by construction: any malformed, truncated, self-inconsistent or non-ELF input returns an
/// [`ElfParseError`] and NEVER panics — see the module doc for why that is load-bearing.
///
/// # Errors
///
/// [`ElfParseError::NotElf`] if the magic is absent; [`ElfParseError::Unsupported`] for a
/// big-endian image or a non-executable image kind; [`ElfParseError::Truncated`] if any header,
/// segment, dynamic entry or string table falls outside `bytes`.
pub fn parse_elf_needs(bytes: &[u8]) -> Result<ElfNeeds, ElfParseError> {
    let ident = bytes.get(..16).ok_or(ElfParseError::NotElf)?;
    if ident.get(..4) != Some(&ELF_MAGIC[..]) {
        return Err(ElfParseError::NotElf);
    }
    if ident[EI_DATA] != ELF_DATA_LSB {
        // A big-endian image on a little-endian host is not something this reader can state
        // requirements for honestly, and refusing beats guessing at a byte order.
        return Err(ElfParseError::Unsupported("big-endian encoding"));
    }
    let layout = match ident[EI_CLASS] {
        ELF_CLASS_64 => &LAYOUT_64,
        ELF_CLASS_32 => &LAYOUT_32,
        _ => return Err(ElfParseError::Unsupported("unknown ELF class")),
    };
    let machine = u16_at(bytes, 0x12)?;
    let e_type = u16_at(bytes, 0x10)?;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfParseError::Unsupported(
            "not an executable or shared object",
        ));
    }

    let segments = read_segments(bytes, layout)?;
    let interp = match segments.interp {
        Some(range) => Some(nul_terminated(
            bytes.get(range).ok_or(ElfParseError::Truncated)?,
        )?),
        None => None,
    };
    let Some(dynamic) = segments.dynamic else {
        // No `PT_DYNAMIC` — a static image. It requires nothing of the loader, which is a real,
        // affirmative answer rather than an absence of one.
        return Ok(ElfNeeds {
            machine,
            interp,
            ..ElfNeeds::default()
        });
    };
    let entries = read_dynamic(bytes.get(dynamic).ok_or(ElfParseError::Truncated)?, layout);
    let strings = string_table(bytes, &entries, &segments.loads)?;
    Ok(ElfNeeds {
        machine,
        interp,
        needed: resolve_all(strings, &entries.needed)?,
        runpath: read_runpath(strings, &entries)?,
    })
}

/// The program-header facts the dynamic requirements are read through: where the dynamic array and
/// the interpreter string live (as FILE ranges), and the `PT_LOAD` segments that translate a virtual
/// address into a file offset.
#[derive(Default)]
struct Segments {
    /// The `PT_DYNAMIC` file range, if the image has one.
    dynamic: Option<Range<usize>>,
    /// The `PT_INTERP` file range, if the image has one.
    interp: Option<Range<usize>>,
    /// Each `PT_LOAD` as `(virtual address, file offset, size)`.
    loads: Vec<LoadSegment>,
}

/// One `PT_LOAD` mapping, the unit of virtual-address → file-offset translation.
struct LoadSegment {
    /// The segment's virtual address.
    vaddr: u64,
    /// Its file offset.
    offset: usize,
    /// Its size in the file.
    size: usize,
}

/// Walk the program headers, collecting only the three segment kinds that answer the question.
fn read_segments(bytes: &[u8], layout: &Layout) -> Result<Segments, ElfParseError> {
    let phoff = usize_at(bytes, layout.e_phoff, layout.wide)?;
    let phentsize = usize::from(u16_at(bytes, layout.e_phentsize)?);
    let phnum = usize::from(u16_at(bytes, layout.e_phnum)?);
    if phentsize < layout.p_filesz + if layout.wide { 8 } else { 4 } {
        return Err(ElfParseError::Truncated);
    }
    let mut segments = Segments::default();
    for index in 0..phnum {
        let base = phoff
            .checked_add(
                index
                    .checked_mul(phentsize)
                    .ok_or(ElfParseError::Truncated)?,
            )
            .ok_or(ElfParseError::Truncated)?;
        let header = bytes
            .get(
                base..base
                    .checked_add(phentsize)
                    .ok_or(ElfParseError::Truncated)?,
            )
            .ok_or(ElfParseError::Truncated)?;
        let p_type = u32_at(header, 0)?;
        let offset = usize_at(header, layout.p_offset, layout.wide)?;
        let size = usize_at(header, layout.p_filesz, layout.wide)?;
        let range = offset..offset.checked_add(size).ok_or(ElfParseError::Truncated)?;
        match p_type {
            PT_DYNAMIC => segments.dynamic = Some(range),
            PT_INTERP => segments.interp = Some(range),
            PT_LOAD => segments.loads.push(LoadSegment {
                vaddr: u64_at(header, layout.p_vaddr, layout.wide)?,
                offset,
                size,
            }),
            _ => {}
        }
    }
    Ok(segments)
}

/// The dynamic entries this reader cares about, gathered from one `PT_DYNAMIC` array.
#[derive(Default)]
struct DynamicEntries {
    /// String-table offsets of the `DT_NEEDED` sonames, in link order.
    needed: Vec<u64>,
    /// `DT_STRTAB` — the string table's VIRTUAL address (not a file offset).
    strtab_vaddr: Option<u64>,
    /// `DT_STRSZ` — the string table's size.
    strsz: Option<u64>,
    /// `DT_RUNPATH`'s string-table offset (preferred), else `DT_RPATH`'s.
    runpath: Option<u64>,
    /// `DT_RPATH`'s string-table offset, used only when no `DT_RUNPATH` is present.
    rpath: Option<u64>,
}

/// Read the `PT_DYNAMIC` array. Stops at `DT_NULL` (the array's own terminator) and silently ignores
/// every tag it does not need, so an unfamiliar tag can never make a well-formed image unreadable.
fn read_dynamic(dynamic: &[u8], layout: &Layout) -> DynamicEntries {
    let stride = if layout.wide { 16 } else { 8 };
    let half = stride / 2;
    let mut entries = DynamicEntries::default();
    for chunk in dynamic.chunks_exact(stride) {
        // `chunks_exact` guarantees the width, so these reads cannot fail.
        let Ok(tag) = u64_at(chunk, 0, layout.wide) else {
            return entries;
        };
        let Ok(value) = u64_at(chunk, half, layout.wide) else {
            return entries;
        };
        match tag {
            DT_NULL => return entries,
            DT_NEEDED => entries.needed.push(value),
            DT_STRTAB => entries.strtab_vaddr = Some(value),
            DT_STRSZ => entries.strsz = Some(value),
            DT_RUNPATH => entries.runpath = Some(value),
            DT_RPATH => entries.rpath = Some(value),
            _ => {}
        }
    }
    entries
}

/// The dynamic string table's bytes, located by translating `DT_STRTAB`'s virtual address through the
/// `PT_LOAD` segments and bounded by `DT_STRSZ`.
///
/// A dynamic array that names neither is not a table this reader can find, and a table that extends
/// past the file is [`ElfParseError::Truncated`] — the two ways a corrupt or hostile image would try
/// to steer a read outside the artifact's bytes.
fn string_table<'a>(
    bytes: &'a [u8],
    entries: &DynamicEntries,
    loads: &[LoadSegment],
) -> Result<&'a [u8], ElfParseError> {
    let vaddr = entries.strtab_vaddr.ok_or(ElfParseError::Truncated)?;
    let size = entries.strsz.ok_or(ElfParseError::Truncated)?;
    let offset = file_offset_of(vaddr, loads).ok_or(ElfParseError::Truncated)?;
    let size = usize::try_from(size).map_err(|_| ElfParseError::Truncated)?;
    let end = offset.checked_add(size).ok_or(ElfParseError::Truncated)?;
    bytes.get(offset..end).ok_or(ElfParseError::Truncated)
}

/// Translate a virtual address to a file offset via the `PT_LOAD` segment that contains it. `None`
/// when no segment maps it — an inconsistency this reader refuses rather than guessing through.
fn file_offset_of(vaddr: u64, loads: &[LoadSegment]) -> Option<usize> {
    loads.iter().find_map(|load| {
        let delta = vaddr.checked_sub(load.vaddr)?;
        let delta = usize::try_from(delta).ok()?;
        (delta < load.size).then(|| load.offset.checked_add(delta))?
    })
}

/// The image's own library search path: `DT_RUNPATH` when present, else the legacy `DT_RPATH` — the
/// precedence the dynamic linker itself applies. Split on `:`, empty components dropped.
fn read_runpath(strings: &[u8], entries: &DynamicEntries) -> Result<Vec<String>, ElfParseError> {
    let Some(offset) = entries.runpath.or(entries.rpath) else {
        return Ok(Vec::new());
    };
    Ok(string_at(strings, offset)?
        .split(':')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect())
}

/// Resolve every string-table offset to its string, failing closed if any lies outside the table.
///
/// Refuses an image claiming more than [`MAX_NEEDED_ENTRIES`] requirements — see that constant for
/// why the count, not just the file size, has to be bounded.
fn resolve_all(strings: &[u8], offsets: &[u64]) -> Result<Vec<String>, ElfParseError> {
    if offsets.len() > MAX_NEEDED_ENTRIES {
        return Err(ElfParseError::Unsupported(
            "more DT_NEEDED entries than any real image has",
        ));
    }
    offsets.iter().map(|off| string_at(strings, *off)).collect()
}

/// The NUL-terminated string at `offset` within the dynamic string table.
fn string_at(strings: &[u8], offset: u64) -> Result<String, ElfParseError> {
    let offset = usize::try_from(offset).map_err(|_| ElfParseError::Truncated)?;
    nul_terminated(strings.get(offset..).ok_or(ElfParseError::Truncated)?)
}

/// The NUL-terminated string at the start of `bytes`, as UTF-8 (lossy — a soname with non-UTF-8
/// bytes still needs to be NAMED in a refusal, and lossy decoding cannot fail).
///
/// Two bounds, both load-bearing rather than tidy:
///
/// - the NUL is only looked for within [`MAX_STRING_BYTES`], so the allocation is bounded by a
///   CONSTANT and not by how far away the next zero byte happens to be;
/// - control characters are replaced, because these bytes are attacker-supplied and this string is
///   about to be written to a root process's journal and an operator's terminal, where a bare `\r`
///   or an ANSI CSI sequence can overwrite the line that reports the refusal.
fn nul_terminated(bytes: &[u8]) -> Result<String, ElfParseError> {
    let searchable = bytes.get(..MAX_STRING_BYTES).unwrap_or(bytes);
    let end = searchable
        .iter()
        .position(|b| *b == 0)
        .ok_or(ElfParseError::Truncated)?;
    Ok(crate::display::without_control_chars(
        &String::from_utf8_lossy(&bytes[..end]),
    ))
}

// --- checked primitive reads; every one of these is why this parser cannot panic ---

/// A little-endian `u16` at `offset`, or [`ElfParseError::Truncated`].
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ElfParseError> {
    let raw: [u8; 2] = fixed(bytes, offset)?;
    Ok(u16::from_le_bytes(raw))
}

/// A little-endian `u32` at `offset`, or [`ElfParseError::Truncated`].
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ElfParseError> {
    let raw: [u8; 4] = fixed(bytes, offset)?;
    Ok(u32::from_le_bytes(raw))
}

/// A class-width address/offset at `offset`, widened to `u64`.
fn u64_at(bytes: &[u8], offset: usize, wide: bool) -> Result<u64, ElfParseError> {
    if wide {
        let raw: [u8; 8] = fixed(bytes, offset)?;
        Ok(u64::from_le_bytes(raw))
    } else {
        Ok(u64::from(u32_at(bytes, offset)?))
    }
}

/// A class-width address/offset at `offset`, as a `usize` this host can index with.
fn usize_at(bytes: &[u8], offset: usize, wide: bool) -> Result<usize, ElfParseError> {
    usize::try_from(u64_at(bytes, offset, wide)?).map_err(|_| ElfParseError::Truncated)
}

/// `N` bytes at `offset`, bounds-checked.
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ElfParseError> {
    let end = offset.checked_add(N).ok_or(ElfParseError::Truncated)?;
    let slice = bytes.get(offset..end).ok_or(ElfParseError::Truncated)?;
    let mut raw = [0u8; N];
    raw.copy_from_slice(slice);
    Ok(raw)
}

/// Real ELF images, fabricated byte by byte, for tests in this crate.
///
/// `pub(crate)` deliberately: [`crate::loadable`]'s end-to-end tests must drive the PRODUCTION byte
/// path — read the file, parse it, decide — over a genuine ELF image on disk. Injecting a
/// pre-built [`ElfNeeds`] there would test the decision while leaving the read-and-parse half
/// unexercised in any decisive direction, which is exactly how a neutered guard stays green.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    /// A synthetic, minimal ELF64 LE shared object for the host's own machine — see
    /// [`synth_elf_for`].
    pub(crate) fn synth_elf(
        needed: &[&str],
        runpath: Option<&str>,
        interp: Option<&str>,
    ) -> Vec<u8> {
        synth_elf_for(EM_X86_64, needed, runpath, interp)
    }

    /// A synthetic, minimal ELF64 LE shared object for `machine`, carrying `needed` as `DT_NEEDED`
    /// entries, an optional `DT_RUNPATH`, and an optional `PT_INTERP` — built so a single `PT_LOAD`
    /// maps the whole file at `vaddr == offset`, which is what lets the fixture exercise the real
    /// virtual-address translation instead of bypassing it.
    pub(crate) fn synth_elf_for(
        machine: u16,
        needed: &[&str],
        runpath: Option<&str>,
        interp: Option<&str>,
    ) -> Vec<u8> {
        let phnum = 2 + usize::from(interp.is_some());
        let phoff = 64usize;
        let dyn_off = phoff + phnum * 56;

        // The string table: a leading NUL (offset 0 is conventionally the empty string), then each
        // soname, then the runpath.
        let mut strtab = vec![0u8];
        let mut needed_offsets = Vec::new();
        for soname in needed {
            needed_offsets.push(strtab.len() as u64);
            strtab.extend_from_slice(soname.as_bytes());
            strtab.push(0);
        }
        let runpath_offset = runpath.map(|r| {
            let at = strtab.len() as u64;
            strtab.extend_from_slice(r.as_bytes());
            strtab.push(0);
            at
        });

        let mut dynamic: Vec<(u64, u64)> =
            needed_offsets.iter().map(|off| (DT_NEEDED, *off)).collect();
        if let Some(off) = runpath_offset {
            dynamic.push((DT_RUNPATH, off));
        }
        // DT_STRTAB is patched once the table's file offset is known (below).
        dynamic.push((DT_STRTAB, 0));
        dynamic.push((DT_STRSZ, strtab.len() as u64));
        dynamic.push((DT_NULL, 0));
        let dyn_size = dynamic.len() * 16;
        let interp_off = dyn_off + dyn_size;
        let interp_bytes: Vec<u8> = interp
            .map(|i| {
                let mut b = i.as_bytes().to_vec();
                b.push(0);
                b
            })
            .unwrap_or_default();
        let strtab_off = interp_off + interp_bytes.len();
        let total = strtab_off + strtab.len();
        for entry in &mut dynamic {
            if entry.0 == DT_STRTAB {
                entry.1 = strtab_off as u64;
            }
        }

        let mut out = vec![0u8; 64];
        out[..4].copy_from_slice(&ELF_MAGIC);
        out[EI_CLASS] = ELF_CLASS_64;
        out[EI_DATA] = ELF_DATA_LSB;
        out[6] = 1; // EI_VERSION
        out[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
        out[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        out[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        out[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        out[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());

        let mut phdr = |p_type: u32, offset: usize, size: usize| {
            let mut h = vec![0u8; 56];
            h[0..4].copy_from_slice(&p_type.to_le_bytes());
            h[0x08..0x10].copy_from_slice(&(offset as u64).to_le_bytes());
            h[0x10..0x18].copy_from_slice(&(offset as u64).to_le_bytes()); // vaddr == offset
            h[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
            out.extend_from_slice(&h);
        };
        phdr(PT_LOAD, 0, total);
        phdr(PT_DYNAMIC, dyn_off, dyn_size);
        if interp.is_some() {
            phdr(PT_INTERP, interp_off, interp_bytes.len());
        }

        for (tag, value) in &dynamic {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&interp_bytes);
        out.extend_from_slice(&strtab);
        assert_eq!(out.len(), total, "the fixture's own layout must be exact");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{synth_elf, synth_elf_for};
    use super::*;

    #[test]
    fn parse_elf_needs_reads_dt_needed_from_a_fabricated_elf64() {
        // The #1870 shape: the dig-app linux/x64 artifact's own DT_NEEDED set, in link order.
        let bytes = synth_elf(&["libgtk-3.so.0", "libgdk-3.so.0", "libc.so.6"], None, None);
        let needs = parse_elf_needs(&bytes).expect("a well-formed ELF64 must parse");
        assert_eq!(
            needs.needed,
            vec!["libgtk-3.so.0", "libgdk-3.so.0", "libc.so.6"]
        );
        assert!(needs.interp.is_none() && needs.runpath.is_empty());
    }

    #[test]
    fn parse_elf_needs_reads_dt_runpath_and_pt_interp() {
        let bytes = synth_elf(
            &["libc.so.6"],
            Some("$ORIGIN/../lib:/opt/dig/lib"),
            Some("/lib64/ld-linux-x86-64.so.2"),
        );
        let needs = parse_elf_needs(&bytes).expect("parse");
        assert_eq!(needs.interp.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
        assert_eq!(
            needs.runpath,
            vec!["$ORIGIN/../lib".to_string(), "/opt/dig/lib".to_string()],
            "the runpath is split but left UNEXPANDED — $ORIGIN is the caller's to resolve"
        );
    }

    #[test]
    fn a_non_elf_file_is_not_elf_never_a_panic() {
        // The three shapes the beacon actually meets on the apply path: a Debian package, a Windows
        // PE/MSI, and a file too short to hold an identification block at all.
        for input in [
            &b"!<arch>\ndebian-binary   1085872000  0     0     100644  4         `\n2.0\n"[..],
            &b"MZ\x90\x00\x03\x00\x00\x00"[..],
            &[0u8, 0, 0][..],
            &[][..],
        ] {
            assert_eq!(parse_elf_needs(input), Err(ElfParseError::NotElf));
        }
    }

    #[test]
    fn every_truncation_of_a_valid_elf_returns_an_error_and_never_panics() {
        // A privileged pass must survive a partial artifact: EVERY prefix of a well-formed image is
        // fed in, and the only acceptable outcomes are an error or an honest partial answer — never
        // a panic, which would stop the host updating at all.
        let bytes = synth_elf(
            &["libgtk-3.so.0", "libc.so.6"],
            Some("/opt/dig/lib"),
            Some("/ld"),
        );
        for n in 0..bytes.len() {
            match parse_elf_needs(&bytes[..n]) {
                Err(_) => {}
                Ok(needs) => assert!(
                    needs.needed.len() <= 2,
                    "a truncated image must never invent requirements: {needs:?}"
                ),
            }
        }
    }

    #[test]
    fn a_dynamic_entry_pointing_outside_the_file_is_truncated_not_a_panic() {
        let good = synth_elf(&["libc.so.6"], None, None);

        // DT_STRTAB steered to a huge virtual address that no PT_LOAD maps.
        let mut steered = good.clone();
        patch_dynamic(&mut steered, DT_STRTAB, u64::MAX - 8);
        assert_eq!(parse_elf_needs(&steered), Err(ElfParseError::Truncated));

        // DT_STRSZ claiming the table runs to the end of the address space — the read must be
        // refused, and must not be used to size an allocation.
        let mut oversized = good.clone();
        patch_dynamic(&mut oversized, DT_STRSZ, u64::MAX);
        assert_eq!(parse_elf_needs(&oversized), Err(ElfParseError::Truncated));

        // A DT_NEEDED offset past the end of the string table.
        let mut off_table = good;
        patch_dynamic(&mut off_table, DT_NEEDED, 1 << 40);
        assert_eq!(parse_elf_needs(&off_table), Err(ElfParseError::Truncated));
    }

    /// Overwrite the value of the first dynamic entry tagged `tag` — the corruption a hostile or
    /// damaged image would use to steer a read outside the artifact's own bytes.
    fn patch_dynamic(bytes: &mut [u8], tag: u64, value: u64) {
        let mut at = 0;
        while at + 16 <= bytes.len() {
            if bytes[at..at + 8] == tag.to_le_bytes() {
                bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
                return;
            }
            at += 8;
        }
        panic!("the fixture must contain a dynamic entry tagged {tag}");
    }

    #[test]
    fn a_static_image_needs_nothing_of_the_loader() {
        // No PT_DYNAMIC at all: a real, affirmative "requires nothing", distinct from an unreadable
        // answer. Built by hand because `synth_elf` always emits a dynamic segment.
        let mut out = vec![0u8; 64];
        out[..4].copy_from_slice(&ELF_MAGIC);
        out[EI_CLASS] = ELF_CLASS_64;
        out[EI_DATA] = ELF_DATA_LSB;
        out[0x10..0x12].copy_from_slice(&ET_EXEC.to_le_bytes());
        out[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        out[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        out[0x38..0x3a].copy_from_slice(&0u16.to_le_bytes());
        let needs = parse_elf_needs(&out).expect("a static image parses");
        assert!(needs.needed.is_empty() && needs.interp.is_none());
    }

    #[test]
    fn the_images_own_machine_is_read_and_not_assumed() {
        // An arm64 build landing in the `linux/x64` slot names sonames that all resolve on an x86-64
        // host, so `e_machine` is the ONLY thing in the file that distinguishes it. Both directions
        // are asserted, so a reader that returned a constant fails one of them.
        for machine in [EM_X86_64, EM_AARCH64] {
            let bytes = synth_elf_for(machine, &["libc.so.6"], None, None);
            assert_eq!(parse_elf_needs(&bytes).expect("parse").machine, machine);
        }
    }

    #[test]
    fn a_soname_carrying_control_characters_cannot_forge_a_log_line() {
        // These bytes are attacker-supplied and are about to be named in a root process's journal.
        let bytes = synth_elf(&["lib\r\x1b[2Kpass applied.so.0", "libc.so.6"], None, None);
        let needs = parse_elf_needs(&bytes).expect("parse");
        assert!(
            !needs.needed[0].contains('\r') && !needs.needed[0].contains('\u{1b}'),
            "a control character reached the refusal detail: {:?}",
            needs.needed[0]
        );
        assert_eq!(
            needs.needed[1], "libc.so.6",
            "an ordinary soname is untouched — the control is that real names still arrive intact"
        );
    }

    #[test]
    fn a_string_longer_than_the_ceiling_is_refused_rather_than_allocated() {
        // Pinned from BOTH sides of MAX_STRING_BYTES: without a constant bound, resolving N entries
        // out of an unterminated table allocates N * table-size — quadratic in the file, inside the
        // privileged pass, however tight the byte ceiling above it is.
        let at_bound = "a".repeat(MAX_STRING_BYTES - 1);
        let bytes = synth_elf(&[&at_bound], None, None);
        assert_eq!(
            parse_elf_needs(&bytes)
                .expect("at the bound it parses")
                .needed,
            vec![at_bound],
            "a name that fits the ceiling must still be read"
        );

        let over = "a".repeat(MAX_STRING_BYTES + 1);
        let bytes = synth_elf(&[&over], None, None);
        assert_eq!(
            parse_elf_needs(&bytes),
            Err(ElfParseError::Truncated),
            "one byte past the ceiling must not be read"
        );
    }

    #[test]
    fn more_dt_needed_entries_than_any_real_image_has_is_refused() {
        let names: Vec<String> = (0..=MAX_NEEDED_ENTRIES)
            .map(|i| format!("lib{i}.so.0"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();

        let at_bound = synth_elf(&refs[..MAX_NEEDED_ENTRIES], None, None);
        assert_eq!(
            parse_elf_needs(&at_bound)
                .expect("at the bound it parses")
                .needed
                .len(),
            MAX_NEEDED_ENTRIES
        );

        let over = synth_elf(&refs, None, None);
        assert_eq!(
            parse_elf_needs(&over),
            Err(ElfParseError::Unsupported(
                "more DT_NEEDED entries than any real image has"
            ))
        );
    }

    #[test]
    fn a_big_endian_image_is_unsupported_rather_than_misread() {
        let mut bytes = synth_elf(&["libc.so.6"], None, None);
        bytes[EI_DATA] = 2; // ELFDATA2MSB
        assert_eq!(
            parse_elf_needs(&bytes),
            Err(ElfParseError::Unsupported("big-endian encoding"))
        );
    }
}
