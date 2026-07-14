//! Regression guard for the PER-CHANNEL feed workflow (#603) + its publish control-flow (#545).
//!
//! `feed.yml` signs, verifies, and publishes TWO fully independent signed feeds — one per update
//! CHANNEL (stable + nightly, SPEC §10.1) — via a `channel` job matrix. Each channel is published
//! to two untrusted bases the beacon ships pointing at: the PRIMARY S3 origin
//! (`updates.dig.net/v1/<channel>/`) and a FALLBACK rolling GitHub release (`feed-<channel>`). A
//! not-yet-migrated beacon still fetches the LEGACY `/v1/alpha` base + rolling `feed` release, so
//! the stable leg mirrors its byte-identical feed there for back-compat until #604 ships.
//!
//! These tests pin the load-bearing shape so a careless edit cannot silently:
//!
//!   1. drop a channel (both `stable` and `nightly` must be signed + verified + published),
//!   2. couple the channels' fate (`fail-fast: false` — the nightly leg failing during the #592
//!      fan-out window must never skip the stable leg),
//!   3. de-parameterize the publish (the S3 dest + live smoke URL must key off `matrix.channel`, so
//!      each channel lands at its OWN path),
//!   4. break the LEGACY `/v1/alpha` feed existing beacons still depend on, or
//!   5. regress the #545/U4 trust posture: every publish (per-channel + legacy) stays STRICTLY
//!      downstream of the PER-CHANNEL keystone verify, and the fallback is decoupled from the
//!      primary smoke so a primary-edge hiccup can't skip the fallback it exists to hedge.

use std::path::PathBuf;

/// The `feed.yml` step names this guard reasons about, spelled EXACTLY as they appear in the file.
/// The matrix runs one copy of each step per channel, so a name is a single definition here.
const KEYSTONE_STEP: &str = "Verify the signed feed end-to-end (pinned key)";
const KEYSTONE_ID: &str = "keystone";
const SIGN_STEP: &str = "Sign the feed";
const S3_PUBLISH_STEP: &str = "Publish to updates.dig.net (S3 primary)";
const SMOKE_STEP: &str = "Smoke-test the live primary (byte-exact)";
const FALLBACK_STEP: &str = "Publish to the rolling feed-<channel> release";
const LEGACY_ALPHA_STEP: &str = "Publish the stable feed to legacy /v1/alpha (back-compat)";

/// `feed.yml`, resolved relative to this crate so the test is location-independent.
fn feed_workflow() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join("feed.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// A single `steps:` entry: its declared `- name:`, the value of its `if:` conditional (empty when
/// absent), and its ordinal position in the step list (0-based, for "runs before/after" reasoning).
struct Step {
    name: String,
    if_expr: String,
    order: usize,
}

/// Split a workflow into its step-list entries. A step begins at the 6-space `- ` indentation the
/// workflow uses for `steps:` items; deeper script/comment lines never match, so they stay grouped
/// under their owning step. A step's `if:` is read from the first `if:` line inside the step body.
fn steps_of(workflow: &str) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    for line in workflow.lines() {
        if line.starts_with("      - ") {
            let name = line
                .trim_start()
                .strip_prefix("- name:")
                .map(|n| n.trim().trim_matches('"').to_string())
                .unwrap_or_default();
            let order = steps.len();
            steps.push(Step {
                name,
                if_expr: String::new(),
                order,
            });
        }
        if let Some(step) = steps.last_mut() {
            if let Some(rest) = line.trim_start().strip_prefix("if:") {
                if step.if_expr.is_empty() {
                    step.if_expr = rest.trim().to_string();
                }
            }
        }
    }
    steps
}

/// Locate a step by its exact `name`, failing loudly if the workflow shape drifted out from under
/// this guard (a renamed step must consciously update the constants above).
fn step<'a>(steps: &'a [Step], name: &str) -> &'a Step {
    steps
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("feed.yml must have a step named {name:?}"))
}

/// A conditional "escapes" the implicit `success()` gate when it uses any status function that lets
/// a step run after an upstream failure/cancellation (`always()`, `!cancelled()`, `failure()`, …).
/// Such a step no longer inherits "all prior steps passed", so it MUST re-assert the trust keystone.
fn escapes_implicit_success(if_expr: &str) -> bool {
    ["always()", "cancelled()", "failure()"]
        .iter()
        .any(|marker| if_expr.contains(marker))
}

/// A publish must fire only when the keystone verify SUCCEEDED — either by relying on the implicit
/// `success()` gate (positioned after the keystone) or, when it escapes that gate to decouple from
/// the primary edge, by explicitly re-asserting `steps.keystone.outcome == 'success'`.
fn gated_on_keystone_success(if_expr: &str) -> bool {
    if escapes_implicit_success(if_expr) {
        if_expr.contains(&format!("steps.{KEYSTONE_ID}.outcome == 'success'"))
            || if_expr.contains(&format!("steps.{KEYSTONE_ID}.conclusion == 'success'"))
    } else {
        true
    }
}

/// #603: the workflow must sign + publish BOTH channels via a `channel` matrix, and the two legs
/// must not share fate (`fail-fast: false`), so the nightly leg failing during the #592 fan-out
/// window can never skip the stable leg.
#[test]
fn both_channels_run_via_an_independent_matrix() {
    let wf = feed_workflow();
    assert!(
        wf.contains("matrix:") && wf.contains("channel: [stable, nightly]"),
        "feed.yml must run a `channel` matrix over BOTH stable and nightly (SPEC §10.1)"
    );
    assert!(
        wf.contains("fail-fast: false"),
        "the channel matrix must be `fail-fast: false` so a nightly-leg failure (expected during \
         the #592 fan-out) cannot cancel/skip the stable leg"
    );
}

/// The sign step selects the channel it is signing (`--channel`), and the primary publish + live
/// smoke are keyed off `matrix.channel`, so each channel lands at its OWN `/v1/<channel>/` path
/// rather than every leg overwriting one shared path.
#[test]
fn publish_is_parameterized_per_channel() {
    let wf = feed_workflow();
    assert!(
        wf.contains("--channel \"${{ matrix.channel }}\""),
        "the sign step must pass `--channel \"${{{{ matrix.channel }}}}\"` so each leg signs its own channel"
    );
    assert!(
        wf.contains("/v1/${{ matrix.channel }}"),
        "the S3 primary publish dest must be keyed off `matrix.channel` (`/v1/${{{{ matrix.channel }}}}`)"
    );
    assert!(
        wf.contains("v1/${{ matrix.channel }}/manifest.json"),
        "the live smoke URL must be keyed off `matrix.channel` so each channel's primary is proven"
    );
}

/// Back-compat: the LEGACY `/v1/alpha` base + rolling `feed` release existing beacons still fetch
/// must keep being published (from the stable leg) until #604 ships the channel-aware ladder.
#[test]
fn legacy_alpha_feed_is_preserved() {
    let wf = feed_workflow();
    let steps = steps_of(&wf);
    // The legacy alpha S3 mirror exists and is stable-leg-only (never a duplicate write per leg).
    let alpha = step(&steps, LEGACY_ALPHA_STEP);
    assert!(
        alpha.if_expr.contains("matrix.channel == 'stable'"),
        "the legacy /v1/alpha publish must run ONLY on the stable leg (if: {:?})",
        alpha.if_expr
    );
    assert!(
        wf.contains("/v1/alpha"),
        "feed.yml must still publish the legacy `/v1/alpha` base (back-compat until #604)"
    );
    assert!(
        wf.contains("gh release view feed --repo"),
        "feed.yml must still publish the legacy rolling `feed` release (back-compat until #604)"
    );
    // And the legacy alpha mirror stays downstream of the (stable) keystone — never an unverified feed.
    let keystone = step(&steps, KEYSTONE_STEP);
    assert!(
        keystone.order < alpha.order,
        "the legacy /v1/alpha publish must run AFTER the {KEYSTONE_STEP:?} keystone, never before it"
    );
}

/// #545: the fallback publish must NOT be blocked by the primary smoke. It satisfies this either by
/// gating on `always()` (fires regardless of the smoke's outcome) or by running BEFORE the smoke.
#[test]
fn fallback_publish_is_decoupled_from_primary_smoke() {
    let steps = steps_of(&feed_workflow());
    let fallback = step(&steps, FALLBACK_STEP);
    let smoke = step(&steps, SMOKE_STEP);

    let decoupled = fallback.if_expr.contains("always()") || fallback.order < smoke.order;
    assert!(
        decoupled,
        "the fallback GitHub-release publish is still gated on the primary smoke's success \
         (if: {:?}, ordered after the {SMOKE_STEP:?} step): a primary-edge hiccup that fails the \
         smoke would skip the very fallback it exists to hedge (#545). Gate it with `always()` or \
         move it before the smoke.",
        fallback.if_expr
    );
}

/// The trust keystone stays the single hard gate: the fallback publish must be positioned after the
/// end-to-end verify AND must never be able to run when that verify did not succeed. Decoupling from
/// the primary edge (#545) must not open a path to publishing an unverified feed.
#[test]
fn fallback_publish_stays_downstream_of_keystone_verify() {
    let steps = steps_of(&feed_workflow());
    let keystone = step(&steps, KEYSTONE_STEP);
    let fallback = step(&steps, FALLBACK_STEP);

    assert!(
        keystone.order < fallback.order,
        "the fallback publish must run AFTER the {KEYSTONE_STEP:?} keystone, never before it"
    );
    assert!(
        gated_on_keystone_success(&fallback.if_expr),
        "the fallback publish escapes the implicit success() gate (if: {:?}) without re-asserting \
         `steps.{KEYSTONE_ID}.outcome == 'success'`, so it could publish a feed the pinned-key \
         keystone did not verify (#545 must not regress the U4 trust posture)",
        fallback.if_expr
    );
}

/// Neither publish may precede the verify: the HARD S3 primary publish (and the sign step feeding
/// it) must sit around the keystone correctly — sign BEFORE verify, publish AFTER. This complements
/// the fallback guard so no publish path can serve an unverified feed.
#[test]
fn primary_publish_stays_downstream_of_keystone_verify() {
    let steps = steps_of(&feed_workflow());
    let sign = step(&steps, SIGN_STEP);
    let keystone = step(&steps, KEYSTONE_STEP);
    let s3_publish = step(&steps, S3_PUBLISH_STEP);

    assert!(
        sign.order < keystone.order,
        "the sign step must run BEFORE the {KEYSTONE_STEP:?} keystone (you verify what you signed)"
    );
    assert!(
        keystone.order < s3_publish.order,
        "the S3 primary publish must run AFTER the {KEYSTONE_STEP:?} keystone, never before it"
    );
}
