//! Turning a release's human semver into the manifest's monotonic `build` number.
//!
//! The beacon's anti-downgrade check (SPEC §7.5) compares an integer `build`, not a semver string.
//! We encode `major.minor.patch` into a single monotonically-increasing `u64`:
//!
//! ```text
//! build = major * 1_000_000  +  minor * 1_000  +  patch
//! ```
//!
//! This preserves ordering (a higher version always yields a higher build) as long as `minor` and
//! `patch` stay below 1000 — true for every DIG component and enforced here so a future
//! four-digit component version fails loudly rather than silently colliding.
//!
//! NIGHTLY builds use a DIFFERENT, non-overlapping build scale: the UTC build date `YYYYMMDD`
//! ([`parse_nightly_build`]), strictly increasing day-over-day — exactly the "never install an
//! older nightly" semantic (#591 D5). The two scales are NEVER compared across channels: each
//! channel keeps its own monotonic trust state, so a stable `build` (thousands) and a nightly
//! `build` (tens of millions) never meet.

use crate::error::FeedsignError;

/// The radix headroom for each semver field. `minor` and `patch` MUST stay below this so the
/// packed `build` number keeps semver ordering (a carry from `patch` into `minor` would break
/// monotonicity).
const FIELD_RADIX: u64 = 1_000;

/// A parsed `major.minor.patch` release version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// The major version.
    pub major: u64,
    /// The minor version.
    pub minor: u64,
    /// The patch version.
    pub patch: u64,
}

impl Version {
    /// The packed monotonic build number for the anti-downgrade comparison (SPEC §5.2 `build`).
    #[must_use]
    pub fn build_number(self) -> u64 {
        self.major * FIELD_RADIX * FIELD_RADIX + self.minor * FIELD_RADIX + self.patch
    }
}

/// Parse a release version, tolerating a leading `v` (`v0.29.0`) and ignoring any pre-release /
/// build metadata suffix (`0.29.0-rc.1` → `0.29.0`).
///
/// # Errors
///
/// [`FeedsignError::Version`] if the string is not `major.minor.patch` of decimal integers, or if
/// `minor`/`patch` reach the radix ceiling (which would break build-number monotonicity).
pub fn parse_version(raw: &str) -> Result<Version, FeedsignError> {
    let trimmed = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    // Drop any `-prerelease` / `+build` metadata; the core `x.y.z` is what we encode.
    let core = trimmed.split(['-', '+']).next().unwrap_or(trimmed);

    let mut parts = core.split('.');
    let mut next = |field: &str| -> Result<u64, FeedsignError> {
        parts
            .next()
            .ok_or_else(|| FeedsignError::Version(format!("{raw}: missing {field}")))?
            .parse::<u64>()
            .map_err(|e| FeedsignError::Version(format!("{raw}: {field}: {e}")))
    };
    let major = next("major")?;
    let minor = next("minor")?;
    let patch = next("patch")?;
    if parts.next().is_some() {
        return Err(FeedsignError::Version(format!(
            "{raw}: too many version components (expected major.minor.patch)"
        )));
    }
    if minor >= FIELD_RADIX || patch >= FIELD_RADIX {
        return Err(FeedsignError::Version(format!(
            "{raw}: minor/patch must be < {FIELD_RADIX} to keep build-number ordering"
        )));
    }
    Ok(Version {
        major,
        minor,
        patch,
    })
}

/// The nightly build number: the UTC build DATE `YYYYMMDD`, parsed from a nightly prerelease
/// version string `X.Y.Z-nightly.YYYYMMDD.<sha>` (#590/#591 D5).
///
/// The nightly release builder synthesizes exactly this shape (`nightly-release.yml`), so the date
/// segment is the second dot-field of the `-nightly.` prerelease. It is a monotonic build stamp on
/// its OWN scale — never compared against the stable packed-semver scale ([`Version::build_number`]).
///
/// # Errors
///
/// [`FeedsignError::Version`] if `version` has no `-nightly.` segment, or the date segment is not
/// exactly eight decimal digits (a malformed nightly stamp fails the run closed rather than
/// producing a feed with a meaningless build number).
pub fn parse_nightly_build(version: &str) -> Result<u64, FeedsignError> {
    let after = version.split("-nightly.").nth(1).ok_or_else(|| {
        FeedsignError::Version(format!(
            "{version}: not a nightly version (expected `X.Y.Z-nightly.YYYYMMDD.<sha>`)"
        ))
    })?;
    let date = after.split('.').next().unwrap_or_default();
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FeedsignError::Version(format!(
            "{version}: nightly date segment must be 8 digits (YYYYMMDD), got {date:?}"
        )));
    }
    date.parse::<u64>()
        .map_err(|e| FeedsignError::Version(format!("{version}: nightly date: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_v_prefixed() {
        assert_eq!(
            parse_version("0.29.0").unwrap(),
            Version {
                major: 0,
                minor: 29,
                patch: 0
            }
        );
        assert_eq!(
            parse_version("v0.29.0").unwrap(),
            parse_version("0.29.0").unwrap()
        );
    }

    #[test]
    fn ignores_prerelease_and_build_metadata() {
        assert_eq!(
            parse_version("1.2.3-rc.1").unwrap(),
            parse_version("1.2.3").unwrap()
        );
        assert_eq!(
            parse_version("1.2.3+build.5").unwrap(),
            parse_version("1.2.3").unwrap()
        );
    }

    #[test]
    fn build_number_encodes_and_orders() {
        assert_eq!(parse_version("0.29.0").unwrap().build_number(), 29_000);
        assert_eq!(parse_version("0.13.1").unwrap().build_number(), 13_001);
        assert_eq!(parse_version("0.2.0").unwrap().build_number(), 2_000);
        assert_eq!(parse_version("1.0.0").unwrap().build_number(), 1_000_000);
    }

    #[test]
    fn build_number_is_monotonic_in_version() {
        let older = parse_version("0.13.1").unwrap().build_number();
        let newer = parse_version("0.13.2").unwrap().build_number();
        let bump_minor = parse_version("0.14.0").unwrap().build_number();
        let bump_major = parse_version("1.0.0").unwrap().build_number();
        assert!(older < newer);
        assert!(newer < bump_minor);
        assert!(bump_minor < bump_major);
    }

    #[test]
    fn rejects_malformed_versions() {
        assert!(parse_version("1.2").is_err());
        assert!(parse_version("1.2.3.4").is_err());
        assert!(parse_version("a.b.c").is_err());
        assert!(parse_version("").is_err());
    }

    #[test]
    fn rejects_four_digit_minor_or_patch() {
        // Would collide with a carry into the next field, breaking monotonicity — fail loudly.
        assert!(parse_version("1.1000.0").is_err());
        assert!(parse_version("1.0.1000").is_err());
    }

    #[test]
    fn nightly_build_is_the_utc_date() {
        assert_eq!(
            parse_nightly_build("0.9.0-nightly.20260714.abc1234").unwrap(),
            20_260_714
        );
        // A shortsha of any length + a bare version with no leading `v` both parse the same date.
        assert_eq!(
            parse_nightly_build("1.2.3-nightly.20251231.deadbeef").unwrap(),
            20_251_231
        );
    }

    #[test]
    fn nightly_build_is_monotonic_day_over_day() {
        let older = parse_nightly_build("0.9.0-nightly.20260713.aaa").unwrap();
        let newer = parse_nightly_build("0.9.0-nightly.20260714.bbb").unwrap();
        assert!(older < newer, "a later date must sort higher");
    }

    #[test]
    fn nightly_build_rejects_a_non_nightly_version() {
        // A plain stable version has no `-nightly.` segment — it must never be mis-parsed as a
        // nightly build (the two scales are distinct, #591 D5).
        assert!(parse_nightly_build("0.9.0").is_err());
        assert!(parse_nightly_build("0.9.0-rc.1").is_err());
    }

    #[test]
    fn nightly_build_rejects_a_malformed_date() {
        assert!(parse_nightly_build("0.9.0-nightly.2026071.abc").is_err()); // 7 digits
        assert!(parse_nightly_build("0.9.0-nightly.202607144.abc").is_err()); // 9 digits
        assert!(parse_nightly_build("0.9.0-nightly.20x6q714.abc").is_err()); // non-digits
        assert!(parse_nightly_build("0.9.0-nightly.").is_err()); // empty date
    }
}
