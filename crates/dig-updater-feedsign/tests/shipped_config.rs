//! The SHIPPED `feed-config.json` is what the 6-hourly Feed workflow actually signs, so its
//! contents are a production contract, not a sample. These tests read that real file and check each
//! declared component against the asset names its repository really publishes.
//!
//! A component whose `asset_prefix`/`asset_kind` do not match its releases resolves ZERO artifacts,
//! and `select_artifacts` then fails the whole feed closed — so a typo here takes the live update
//! feed down for every component at once. That is worth a test that runs offline, on every PR,
//! against pinned real-release asset names.

use dig_updater_feedsign::{select_artifacts, AssetKind, FeedConfig, GithubRelease};

/// The config the Feed workflow signs with (`--config feed-config.json`, from the repo root).
fn shipped_config() -> FeedConfig {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../feed-config.json");
    let json = std::fs::read_to_string(path).expect("the shipped feed-config.json is readable");
    FeedConfig::from_json(&json).expect("the shipped feed-config.json parses")
}

/// The asset names dig-app's real `v3.0.0` release publishes, verified against the GitHub API. It
/// ships FOUR `dig-app-…` binaries and — from the very same release — four `dign-…` binaries, its
/// separate user CLI.
const DIG_APP_V3_ASSETS: &[&str] = &[
    "dig-app-3.0.0-linux-x64",
    "dig-app-3.0.0-macos-arm64",
    "dig-app-3.0.0-macos-x64",
    "dig-app-3.0.0-windows-x64.exe",
    "dign-3.0.0-linux-x64",
    "dign-3.0.0-macos-arm64",
    "dign-3.0.0-macos-x64",
    "dign-3.0.0-windows-x64.exe",
];

/// dig-app's real `v3.0.0` release, parsed from the GitHub REST shape the signer really consumes —
/// so the fixture exercises the same deserialization path as production, not a hand-built struct.
fn dig_app_v3_release() -> GithubRelease {
    let assets: Vec<String> = DIG_APP_V3_ASSETS
        .iter()
        .map(|name| {
            format!(
                r#"{{"name":"{name}","browser_download_url":"https://github.com/DIG-Network/dig-app/releases/download/v3.0.0/{name}"}}"#
            )
        })
        .collect();
    let json = format!(r#"{{"tag_name":"v3.0.0","assets":[{}]}}"#, assets.join(","));
    GithubRelease::from_json(
        "https://api.github.com/repos/DIG-Network/dig-app/releases/latest",
        &json,
    )
    .expect("the real release shape parses")
}

#[test]
fn the_shipped_config_declares_dig_app() {
    let cfg = shipped_config();
    let dig_app = cfg
        .components
        .iter()
        .find(|c| c.name == "dig-app")
        .expect("dig-app is a tracked component (dig_ecosystem#1746)");

    assert_eq!(dig_app.repo, "DIG-Network/dig-app");
    assert_eq!(dig_app.asset_prefix, "dig-app");
    // dig-app publishes raw per-platform executables; it ships no `.msi`/`.pkg`/`.deb`, so the
    // native-package shapes would resolve nothing at all.
    assert_eq!(dig_app.asset_kind, AssetKind::RawBinary);
}

#[test]
fn the_shipped_dig_app_entry_resolves_all_four_real_v3_platforms() {
    let cfg = shipped_config();
    let dig_app = cfg
        .components
        .iter()
        .find(|c| c.name == "dig-app")
        .expect("dig-app is a tracked component");

    let arts = select_artifacts(&dig_app_v3_release(), dig_app, "3.0.0")
        .expect("dig-app's real release resolves under its shipped config");

    let mut platforms: Vec<_> = arts
        .iter()
        .map(|a| (a.os.as_str(), a.arch.as_str()))
        .collect();
    platforms.sort_unstable();
    assert_eq!(
        platforms,
        vec![
            ("linux", "x64"),
            ("macos", "arm64"),
            ("macos", "x64"),
            ("windows", "x64")
        ],
        "all four platforms the beacon ships to must resolve"
    );
}

/// `dign` is NOT dig-app's artifact in this feed, and the exact-name match is what keeps it out.
///
/// This matters beyond tidiness: the beacon already installs `dign` as a byte-identical ALIAS of
/// dig-node (`plan.rs`, #548), and dig-node still publishes its own `dign-<ver>-*` assets. Two
/// components resolving artifacts for one installed filename would have them overwrite each other
/// on every pass, so dig-app's entry must select only the `dig-app-…` binaries — even though the
/// `dign-…` ones sit in the very same release.
#[test]
fn the_shipped_dig_app_entry_never_selects_the_sibling_dign_binaries() {
    let cfg = shipped_config();
    let dig_app = cfg
        .components
        .iter()
        .find(|c| c.name == "dig-app")
        .expect("dig-app is a tracked component");

    let arts = select_artifacts(&dig_app_v3_release(), dig_app, "3.0.0").expect("resolves");

    for art in &arts {
        let file = art.url.rsplit('/').next().unwrap_or_default();
        assert!(
            file.starts_with("dig-app-"),
            "dig-app must select only its own binaries; got {file}"
        );
    }
}

/// dig_ecosystem#1912: the shipped dig-app entry declares the headless Linux variant, and when the
/// release carries the `-headless` asset the feed resolves BOTH linux/x64 builds — the default and
/// the headless — so a headless host has a loadable artifact to select.
#[test]
fn the_shipped_dig_app_entry_resolves_both_linux_variants_when_headless_is_published() {
    let cfg = shipped_config();
    let dig_app = cfg
        .components
        .iter()
        .find(|c| c.name == "dig-app")
        .expect("dig-app is a tracked component");
    assert_eq!(
        dig_app.variants.len(),
        1,
        "the shipped entry declares exactly the headless variant"
    );
    assert_eq!(dig_app.variants[0].variant, "headless");

    // A future release that also ships the headless build.
    let names = [
        "dig-app-3.5.0-linux-x64",
        "dig-app-3.5.0-linux-x64-headless",
        "dig-app-3.5.0-macos-arm64",
        "dig-app-3.5.0-macos-x64",
        "dig-app-3.5.0-windows-x64.exe",
    ];
    let assets: Vec<String> = names
        .iter()
        .map(|name| {
            format!(
                r#"{{"name":"{name}","browser_download_url":"https://github.com/DIG-Network/dig-app/releases/download/v3.5.0/{name}"}}"#
            )
        })
        .collect();
    let json = format!(r#"{{"tag_name":"v3.5.0","assets":[{}]}}"#, assets.join(","));
    let release = GithubRelease::from_json("https://api/x", &json).expect("parses");

    let arts = select_artifacts(&release, dig_app, "3.5.0").expect("resolves");
    let linux: Vec<_> = arts.iter().filter(|a| a.os == "linux").collect();
    assert_eq!(linux.len(), 2, "both linux/x64 builds resolve");
    assert_eq!(linux[0].variant, None);
    assert_eq!(linux[1].variant.as_deref(), Some("headless"));
}

/// Every component in the shipped config must name a DIG-Network repository and a non-empty asset
/// prefix — the two fields a resolution failure always traces back to.
#[test]
fn every_shipped_component_is_fully_specified() {
    for c in &shipped_config().components {
        assert!(
            c.repo.starts_with("DIG-Network/"),
            "{} names an unexpected repo: {}",
            c.name,
            c.repo
        );
        assert!(!c.asset_prefix.is_empty(), "{} has no asset prefix", c.name);
    }
}

/// The reusable cross-OS build every channel of THIS repo calls (`build-binaries.yml`).
fn build_workflow() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/build-binaries.yml"
    );
    std::fs::read_to_string(path).expect("the shared build workflow is readable")
}

#[test]
fn this_repos_build_produces_exactly_the_asset_names_its_declared_kind_expects() {
    // dig_ecosystem#618: dig-node's nightly published raw binaries while the feed, per its
    // `native_package` kind, looked for `.msi`/`.pkg`/`.deb` — so the feed job failed every night for
    // three weeks. dig-updater is the REFERENCE nightlies implementation that repo copied, so the
    // reference itself must hold the invariant the copy broke: the asset names this repo's build
    // STAGES are exactly the names the feed LOOKS FOR for this repo's own component.
    //
    // The staged name is `{bin}-{version}-{matrix.out_name}`, so each `out_name` is the whole tail
    // after the version — which is what makes the comparison below meaningful rather than incidental.
    let wf = build_workflow();
    assert!(
        wf.contains(r#"cp "$SRC" "dist/${bin}-${VER}-${{ matrix.out_name }}""#),
        "the build stages assets as `{{bin}}-{{version}}-{{out_name}}`; this guard's derivation \
         assumes that shape, so a change to it must update the guard too"
    );

    let cfg = shipped_config();
    let me = cfg
        .components
        .iter()
        .find(|c| c.repo == "DIG-Network/dig-updater")
        .expect("the feed tracks this repo's own component");

    let version = "9.9.9";
    let mut built: Vec<String> = wf
        .lines()
        .filter_map(|line| line.trim().strip_prefix("out_name: "))
        .map(|out_name| format!("{}-{version}-{out_name}", me.asset_prefix))
        .collect();
    built.sort();
    assert!(
        !built.is_empty(),
        "the build workflow declares no platforms"
    );

    let mut wanted =
        dig_updater_feedsign::expected_asset_names(&me.asset_prefix, version, me.asset_kind);
    wanted.sort();

    assert_eq!(
        built, wanted,
        "this repo's build output and its declared `asset_kind` ({:?}) have drifted: the feed would \
         resolve zero artifacts for {}",
        me.asset_kind, me.name
    );
}
