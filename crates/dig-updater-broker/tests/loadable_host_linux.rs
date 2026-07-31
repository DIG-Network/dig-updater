//! The ONE host-gated part of the #1870 loadability check: does the REAL host resolver actually see
//! this machine's libraries?
//!
//! Everything else about the check is asserted host-independently — the parse ([`dig_updater_broker::elf`]),
//! the pure decision, and the applier's refusal — precisely so a mutation cannot hide behind a
//! `#[cfg]`. What CANNOT be proven that way is whether `ldconfig -p` (or the directory fallback) is
//! read correctly on a real Linux host, so that alone lives here, and it is asserted from BOTH sides:
//! a library every glibc Linux has must be found, and a fabricated one must NOT be — a resolver that
//! answered `true` for everything, or `false` for everything, fails one of the two.

#![cfg(target_os = "linux")]

#[test]
fn the_host_resolver_finds_libc_and_not_a_fabricated_soname() {
    let sonames = dig_updater_broker::loadable::host_sonames()
        .expect("a Linux host must be able to enumerate its own shared libraries");
    assert!(
        sonames.contains("libc.so.6") || sonames.iter().any(|s| s.starts_with("libc.")),
        "the C library must be visible to the resolver, or every ELF artifact would be refused"
    );
    assert!(
        !sonames.contains("libdefinitely-not-here-1870.so.9"),
        "a resolver that answers yes to everything would never refuse an unloadable artifact"
    );
}
