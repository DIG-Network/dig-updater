# Runbook — releasing dig-updater (nightly from main + stable from release/X.Y)

How this repo's binaries (`dig-updater` + `dig-updater-worker`) are built and released. This is the
ecosystem's **reference release-branch system** (epic #1049); the normative contract is `SPEC.md`
§14. It is distinct from the signed **feed** (`feed.yml`, `SPEC.md` §10), which is how the beacon
reads updates for OTHER components — see `SPEC.md` §10 for the feed.

## The two version streams (read this first)

There are TWO independent version streams, and they never collide:

| Stream | Branch | Purpose | Version |
|---|---|---|---|
| **Leading dev / nightly** | `main` | The trunk. Nightlies cut here every night from HEAD. | `X.(Y+1).0` and up — always AHEAD of the newest release line; per-PR bumps accumulate toward the NEXT stable line. |
| **Deliberate stable** | `release/X.Y` | A curated stable line, branched off main at a chosen good commit. Stable `vX.Y.Z` tags are cut FROM here; stabilized + hotfixed here. | `X.Y.0`, then `X.Y.1`, `X.Y.2` … (hotfixes walk the patch). |

The stable version is **deliberate at branch-cut** (release-prep), not the accidental sum of per-PR
bumps on main.

## TL;DR

- Releases are **NOT cut on merge to `main`**.
- **Nightly** (UNCHANGED): built every night from `main` HEAD at **midnight UTC** (+ manual
  dispatch) as a **pre-release** under a dated tag `nightly-YYYYMMDD` + a rolling `nightly` tag.
  `prerelease: true`, never `latest`. Keeps the newest 14 dated nightlies.
- **Stable** (`vX.Y.Z`): cut from a `release/X.Y` BRANCH by a manual dispatch selected against that
  branch — never from main, never by the cron. `prerelease: false`, `make_latest: true`.

## Prerequisites / credentials

- **`RELEASE_TOKEN`** — an org-level classic PAT (the ecosystem release token). Both channels no-op
  with a warning if it is absent. Used to push the changelog commit past branch protection and to
  push tags that trigger downstream workflows (`GITHUB_TOKEN` cannot do either). Set org-wide, or per
  repo under Settings → Secrets → Actions.
- No other secret is needed for releasing (the feed's `BEACON_SIGNING_KEY` is unrelated).

## If nightlies silently stop — check for the 60-day cron auto-disable

GitHub disables a `schedule:` trigger after **60 days of no repo activity** on a public repo, with
**no automatic re-enable** — and since this cron is the *only* automatic release trigger (there is
no more push-to-main tagger), a quiet repo can go dark with no error anywhere. If nightlies (or a
long-overdue stable release) stop appearing:

```bash
gh api repos/DIG-Network/dig-updater/actions/workflows/nightly-release.yml --jq .state
# "disabled_inactivity" means GitHub turned it off — re-enable it:
gh workflow enable nightly-release.yml --repo DIG-Network/dig-updater
```

Any repo activity (a merged PR, a manual dispatch) resets the 60-day counter, so this normally only
bites a repo that goes fully quiet for two months. (Fleet-wide re-enable checking across every
releasing submodule is a standing loop-housekeeping concern, not something this repo checks for
its siblings.)

## Cut a STABLE release (the normal path)

Stable is a two-step deliberate act: **(1) open the release line**, then **(2) cut `vX.Y.Z` from it**.

### Step 1 — open the release line (`cut-release-branch.yml`)

Actions → **Cut release branch** → **Run workflow** (against `main`) → inputs:

- `version` = the deliberate first stable version for this line, e.g. `0.15.0` (must be `X.Y.0`).
- `next_dev_version` = where main's leading dev version moves next, e.g. `0.16.0` (`X.(Y+1).0`).

This branches `release/0.15` off main HEAD, sets `0.15.0` on it in a `chore(release): prep v0.15.0`
commit, pushes the branch, and opens a **"next dev cycle" PR** bumping main to `0.16.0`. Review +
merge that PR so main moves ahead. The workflow REFUSES if `release/0.15` or `v0.15.0` already
exists.

### Step 2 — cut `vX.Y.Z` from the release line

Actions → **Nightly + stable release** → **Run workflow** → **set the branch/ref to `release/0.15`**
→ `channel: stable` → Run. The stable job (bound to `refs/heads/release/*`) sees `v0.15.0` has no
tag yet, regenerates `CHANGELOG.md` with git-cliff, commits `chore(release): v0.15.0` **to
`release/0.15`**, tags it, and pushes with `RELEASE_TOKEN`. The pushed `v*` tag fires `release.yml`,
which builds every OS/arch and publishes the stable GitHub Release with `make_latest: true`.

> The tag's ORIGIN branch is invisible to consumers: the beacon feed resolves stable via
> `releases/latest` (SPEC §10.3), and `release.yml` always publishes with `make_latest: true`, so a
> `vX.Y.Z` cut from `release/X.Y` is served identically to one cut from anywhere. **Invariant: never
> drop `make_latest: true` from the stable release** or the feed would resolve the wrong release.

### Stabilize a release line (bugfixes before the first cut)

Open PRs **against `release/X.Y`** (not main) with fixes; bump the patch (`X.Y.1`, …) in the PR. The
same PR gates run (`ci.yml`, `commitlint.yml`, `ensure-version-increment.yml` all trigger on
`release/**`; the version-increment gate compares against the release branch base). Then cut the
patch via Step 2.

### Hotfix a shipped release + forward-port

1. PR the fix to `release/X.Y`, bumping the patch to `X.Y.(Z+1)`.
2. Cut `vX.Y.(Z+1)` via Step 2 (dispatch stable against `release/X.Y`).
3. **Forward-port** the fix to `main` (cherry-pick or a fresh PR) so the next release line carries
   it — otherwise the fix regresses in the next `X.(Y+1)` line.

### Re-cut / re-release the current version (e.g. after a failed build)

Actions → **Nightly + stable release** → **Run workflow** → ref `release/X.Y`, `channel: stable`,
**`force: true`** → Run. `force` bypasses the skip-if-tagged guard and moves the existing `vX.Y.Z`
tag onto a fresh changelog commit (the release branch is never force-pushed), re-firing
`release.yml`.

`force` is guarded, not a blanket override: it REFUSES (non-zero exit, clear error) when the tag
already has a PUBLISHED release AND currently points at a different commit than this run would
build — that combination would silently overwrite a shipped release's binaries with different
code under the same version. It only proceeds for a same-commit retry (the failed-build case
above) or a tag with no published release yet. If you actually need to ship new code, bump
`Cargo.toml` and let a normal (non-force) run cut the next version instead.

## Cut a NIGHTLY on demand

Actions → **Nightly + stable release** → **Run workflow** → `channel: nightly` (or `both`) → Run. It
builds `main` HEAD, publishes/refreshes today's `nightly-YYYYMMDD` pre-release, moves the rolling
`nightly` tag to it, and prunes old nightlies.

## How nightlies work (details)

- **Version string:** `X.Y.Z-nightly.YYYYMMDD.<shortsha>` synthesized at build time (nothing is
  committed). As a semver prerelease it sorts below the plain `X.Y.Z`.
- **Tags:** an immutable dated `nightly-YYYYMMDD` (history) + a force-moved rolling `nightly` (always
  the newest — the stable "latest nightly" download URL:
  `https://github.com/DIG-Network/dig-updater/releases/download/nightly/...`).
- **Retention:** the newest **14** dated nightlies + the rolling `nightly` are kept; older dated
  pre-releases and their tags are pruned together (`gh release delete --cleanup-tag`). Tune via the
  `KEEP_NIGHTLIES` env in `nightly-release.yml`. `v*` stable releases are never pruned.
- **Idempotent:** a same-day re-run refreshes today's release instead of erroring.

## Verify a release went live

- **Stable:** `gh release view vX.Y.Z --repo DIG-Network/dig-updater` — 4 OS/arch pairs × 2 binaries
  (8 assets), `prerelease: false`, marked latest. Watch the build: `gh run watch <id>`.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-updater` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`, 8 assets stamped with the nightly version.

## Workflows

| File | Trigger | Role |
|---|---|---|
| `cut-release-branch.yml` | `workflow_dispatch` (on main) | Opens a stable line: branch `release/X.Y` off main + prep commit + "next dev cycle" PR. |
| `nightly-release.yml` | midnight-UTC cron + `workflow_dispatch` | Orchestrator: stable (from `release/*`, changelog + tag) + nightly (from main HEAD, build + pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag (`make_latest: true`). |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build (both channels call it). |
| `ci.yml` / `commitlint.yml` / `ensure-version-increment.yml` | PR + push to `main` **and** `release/**` | The full pre-merge gate set — runs on release-branch PRs too (hotfix/stabilize). |

## Local build (dev)

```bash
cargo build --workspace --release --locked
cargo test  --workspace --locked        # includes the workflow-shape guard tests
```
