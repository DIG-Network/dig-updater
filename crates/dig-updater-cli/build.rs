//! Build script: on Windows, embed the branded DIG application icon.
//!
//! Compiles `assets/dig.rc`, which carries the branded DIG application icon
//! (RT_GROUP_ICON/RT_ICON), into the `dig-updater` binary. The workspace's
//! `.cargo/config.toml` already embeds an `asInvoker` RT_MANIFEST for every
//! Windows binary via linker rustflags (`/MANIFEST:EMBED` +
//! `/MANIFESTUAC:level='asInvoker'`); `embed_resource::compile` only adds
//! `cargo:rustc-link-arg-bins` for the compiled `.res`, so the two resource
//! kinds accumulate rather than collide — which is also why `assets/dig.rc`
//! deliberately declares no manifest of its own.
//!
//! No-op on non-Windows.

fn main() {
    #[cfg(windows)]
    embed_icon();
}

/// Compile the branded DIG icon into the `dig-updater` binary.
///
/// The result is checked rather than discarded: an environment that cannot
/// compile a resource would otherwise silently produce an unbranded binary,
/// which is precisely the failure this build step exists to prevent.
#[cfg(windows)]
fn embed_icon() {
    embed_resource::compile("../../assets/dig.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to compile assets/dig.rc — no usable Windows resource compiler?");

    println!("cargo:rerun-if-changed=../../assets/dig.rc");
    println!("cargo:rerun-if-changed=../../assets/dig.ico");
}
