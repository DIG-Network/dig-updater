//! Making attacker-supplied text safe to SHOW (dig_ecosystem#1870 hardening).
//!
//! A refusal has to NAME the sonames it refused on, and those names are raw bytes out of a downloaded
//! artifact. They travel from the ELF string table into a `eprintln!` in a root process — so into
//! journald — and into `dig-updater status`, so onto an operator's terminal. A carriage return or an
//! ANSI CSI sequence survives both verbatim, which is enough to overwrite the very line that reports
//! the refusal and forge a reassuring one in its place. The operator then reads a pass as applied
//! while nothing was installed.
//!
//! `status.json` is already safe — `serde_json` escapes control characters — so this covers the two
//! places that are NOT: the log lines and the human renderer.

/// `text` with every control character replaced by `U+FFFD`, so it cannot move a terminal cursor,
/// start an escape sequence, or break a log line into two.
///
/// Replaces rather than strips: a name that had a control character in it is not a name to trust, and
/// the replacement character makes that visible instead of silently producing a plausible-looking
/// one. Ordinary text — every soname, path and version string the beacon really meets — is returned
/// unchanged.
#[must_use]
pub fn without_control_chars(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_returned_unchanged() {
        // The control on the assertion below: a sanitizer that mangled real sonames would be worse
        // than none, because every refusal detail an operator acts on goes through here.
        let plain = "libgtk-3.so.0, /usr/lib/x86_64-linux-gnu/libc.so.6 (build 3004000)";
        assert_eq!(without_control_chars(plain), plain);
    }

    #[test]
    fn a_forged_log_line_cannot_survive_the_renderer() {
        // The real payload shape: CR to return the cursor to column 0, then a plausible success line,
        // so the terminal shows a reassuring message over the refusal that was actually reported.
        let forged = "lib\r\x1b[2Kdig-updater: pass applied (2 component(s)).so.0";
        let safe = without_control_chars(forged);
        assert!(
            !safe.contains('\r') && !safe.contains('\u{1b}'),
            "no carriage return and no escape byte may reach the terminal: {safe:?}"
        );
        assert_eq!(
            safe.chars().count(),
            forged.chars().count(),
            "each control character is REPLACED, so the forgery is visible rather than erased"
        );
    }

    #[test]
    fn a_newline_cannot_split_one_log_line_into_two() {
        assert!(!without_control_chars("a\nb\tc\0d").contains(['\n', '\t', '\0']));
    }
}
