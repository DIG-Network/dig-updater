# Runbook — releasing dig-updater (nightly cron + manual dispatch)

How this repo's binaries (`dig-updater` + `dig-updater-worker`) are built and released. This is the
ecosystem's **reference nightlies system** (#590); the normative contract is `SPEC.md` §14. It is
distinct from the signed **feed** (`feed.yml`, `SPEC.md` §10), which is how the beacon reads updates
for OTHER components — see `runbooks/` and `SPEC.md` §10 for the feed.

## TL;DR

- Releases are **NOT cut on merge to `main`**. They are batched to a **nightly cron at midnight UTC**
  plus **manual dispatch**.
- **Stable** (`vX.Y.Z`): cut automatically when the `Cargo.toml` version was bumped (detected as
  "the `vX.Y.Z` tag doesn't exist yet"), or on demand. `prerelease: false`, marked `latest`.
- **Nightly**: built every night from `main` HEAD as a **pre-release** under a dated tag
  `nightly-YYYYMMDD` + a rolling `nightly` tag. `prerelease: true`, never `latest`. Keeps the newest
  14 dated nightlies.

## Prerequisites / credentials

- **`RELEASE_TOKEN`** — an org-level classic PAT (the ecosystem release token). Both channels no-op
  with a warning if it is absent. Used to push the changelog commit past branch protection and to
  push tags that trigger downstream workflows (`GITHUB_TOKEN` cannot do either). Set org-wide, or per
  repo under Settings → Secrets → Actions.
- No other secret is needed for releasing (the feed's `BEACON_SIGNING_KEY` is unrelated).

## Cut a STABLE release (the normal path)

1. In your feature PR, bump `[workspace.package].version` in the root `Cargo.toml` per SemVer and run
   `cargo update --workspace` so `Cargo.lock` matches (the version-increment CI gate requires the
   bump; `--locked` builds require the lock in sync). Merge the PR (squash) as usual.
2. Nothing releases on merge. At the next **midnight UTC** the `nightly-release.yml` cron runs its
   **stable** job: it sees the new version has no `vX.Y.Z` tag, regenerates `CHANGELOG.md` with
   git-cliff, commits `chore(release): vX.Y.Z` to `main`, tags it, and pushes with `RELEASE_TOKEN`.
3. The pushed `v*` tag fires `release.yml`, which builds every OS/arch and publishes the stable
   GitHub Release (with the changelog as notes).

### Cut a stable release NOW (don't wait for midnight)

Actions → **Nightly + stable release** → **Run workflow** → `channel: stable` (or `both`) → Run.
Same logic as the cron, on demand.

### Re-cut / re-release the current version (e.g. after a failed build)

Actions → **Nightly + stable release** → **Run workflow** → `channel: stable`, **`force: true`** →
Run. `force` bypasses the skip-if-tagged guard and moves the existing `vX.Y.Z` tag onto a fresh
changelog commit (`main` is never force-pushed), re-firing `release.yml`.

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
| `nightly-release.yml` | midnight-UTC cron + `workflow_dispatch` | Orchestrator: stable (changelog + tag) + nightly (build + pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build (both channels call it). |
| `ci.yml` | PR + push to main | The full fmt/clippy/test/coverage/build gate (pre-merge). |

## Local build (dev)

```bash
cargo build --workspace --release --locked
cargo test  --workspace --locked        # includes the workflow-shape guard tests
```
