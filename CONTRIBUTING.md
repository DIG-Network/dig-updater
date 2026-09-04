# Contributing to dig-updater

dig-updater is the DIG auto-update beacon — a transient, scheduled process that wakes daily,
performs one verified update pass over every installed DIG binary, and exits. Its central design
invariant: **the signature is the gate, not the transport** — every artifact it installs must
chain, cryptographically, to a root public key compiled into the beacon binary, so a hostile CDN,
broken TLS, a stolen release token, or a compromised build runner cannot make it install malicious
or downgraded code. Read `SPEC.md` before changing anything that touches the trust core, the
manifest/delegation format, or the install/rollback pipeline.

## Reporting an issue

File at [github.com/DIG-Network/dig-updater/issues](https://github.com/DIG-Network/dig-updater/issues)
with observed behavior, expected behavior, and repro steps.

This repo has no `SECURITY.md` yet. Given the trust-chain surface described above, a genuine
security finding (a signature-verification bypass, a rollback/downgrade path, a privilege-escalation
route from the unprivileged worker into the privileged broker) is still worth disclosing carefully —
open an issue but avoid posting full exploit detail publicly; the maintainer will follow up.

## Prerequisites

- Rust — this repo has no `rust-toolchain.toml`; CI installs the `stable` toolchain via
  `dtolnay/rust-toolchain@stable`, so build with whatever `stable` `rustup` resolves to.
- **Windows only:** any binary or test harness whose filename contains "updater" trips Windows
  UAC installer-detection (`os error 740`) unless it embeds an `asInvoker` application manifest.
  `.cargo/config.toml` already does this at link time for every build (including `cargo test`), so
  a normal `cargo build`/`cargo test` on Windows runs unelevated — no extra setup needed.
- A handful of tests mutate real, privileged OS state (a Scheduled Task, a systemd unit, a
  LaunchDaemon, the production single-instance mutex) and are `#[ignore]`d by default; running
  them requires the same privilege the beacon runs at (Administrator on Windows, root on Unix) —
  see [Build & test](#build--test) below. You don't need to run these locally to contribute; CI's
  `scheduler-elevated` job covers them on all three OSes.

## Build & test

```sh
# build the whole workspace
cargo build --workspace

# run the ordinary test suite (the elevated tests below are skipped by default)
cargo test --workspace
```

The elevated, OS-mutating tests, run explicitly from an elevated console/`sudo` if you need them:

```sh
cargo test -p dig-updater-broker --lib -- --ignored             # production lock contention
cargo test -p dig-updater-broker --test scheduler -- --ignored  # install/status/uninstall + ACL
```

## The gate

CI (`.github/workflows/ci.yml`) runs these on every PR against `main` or a `release/**` branch;
run them locally first:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo llvm-cov --workspace --locked --fail-under-lines 80 --summary-only   # coverage gate, >=80% lines
cargo build --workspace --release --locked
```

Clippy and the full test suite additionally run on `ubuntu-latest`, `windows-latest`, and
`macos-latest` — the sandbox's privilege-drop path is `#[cfg]`-split per OS, so a Linux-only check
would leave the Windows restricted-token path unverified. The `scheduler-elevated` job runs the
`--ignored` tests above, elevated, on all three OSes. A separate `release-scripts` job lints
(`shellcheck`) and tests the `scripts/*.sh` release helpers, since those mutate a git tree from a
release workflow.

## PR conventions

- **Conventional Commits**, commitlint-enforced (`.github/workflows/commitlint.yml`) against both
  the commit messages and the PR title.
- **Bump the version** in the root `Cargo.toml`'s `[workspace.package].version` as part of the PR —
  `ensure-version-increment.yml` fails the PR if it doesn't strictly increase versus the PR's base
  branch (patch/minor/major per the usual SemVer judgement).
- `main` is protected: GitHub Flow only (branch → PR → squash-merge), every required check green,
  every review thread resolved, no direct pushes.

## Releasing (release-branch model — reads differently from most `modules/apps` repos)

dig-updater has adopted the release-branch model (epic #1049), not the plain nightly-off-`main`
default: `main` is the leading dev trunk, and stable lines live on dedicated `release/X.Y`
branches opened by `cut-release-branch.yml`.

- **Nightly channel** — the midnight-UTC cron in `nightly-release.yml` builds `main` HEAD and
  publishes a dated `nightly-YYYYMMDD` pre-release plus a rolling `nightly` tag, unconditionally,
  every night (`nightly-meta`'s `if:` gates on `github.ref == 'refs/heads/main'` and
  `github.event_name == 'schedule' || inputs.channel == 'nightly' || inputs.channel == 'both'`).
  Nothing is committed; the version is synthesized at build time as
  `X.Y.Z-nightly.YYYYMMDD.<shortsha>`.
- **Stable channel** — cut ONLY by a manual `workflow_dispatch(channel: stable|both)` **selected
  against a `release/X.Y` branch**, never against `main`. The `stable` job's `if:` requires
  `startsWith(github.ref, 'refs/heads/release/')` — a dispatch selected against `main` skips the
  job silently (it still reports `completed`), so always pick the release branch as the ref when
  dispatching a stable cut. It reads the version from that branch's `Cargo.toml`, and is a no-op
  if `vX.Y.Z` already exists there (unless `force: true` re-cuts the same commit).
- Cutting the tag runs `git-cliff` to regenerate `CHANGELOG.md`, commits it to the release branch,
  tags it, and pushes both with the org `RELEASE_TOKEN` — the pushed `v*` tag then fires
  `release.yml`, which builds and publishes the binaries with `make_latest:true`.

See `SPEC.md` §14 and `runbooks/release.md` for the full mechanics.
