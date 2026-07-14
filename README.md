# dig-updater

**The DIG auto-update beacon** — a daily, signed, verified, rollback-safe updater that keeps
every installed DIG binary (`dig-node`, `dig-installer`, `dig-relay`, …) current on the
nightly alpha channel.

## Trust invariant — the signature is the gate, not the transport

Every byte the beacon installs chains, cryptographically, to a **root public key compiled into
the beacon binary**:

1. A **root→targets delegation** (signed by the pinned root key) names the key allowed to sign
   manifests.
2. A **manifest** (signed by that targets key) lists, per component and per OS/arch, the
   download URL and the **SHA-256** of the artifact bytes.
3. Each downloaded artifact is verified byte-for-byte against that in-manifest digest **before**
   it reaches the privileged installer.

So a hostile CDN, broken TLS, a stolen release token, or a compromised build runner cannot make
the beacon install malicious or downgraded code — none of them holds a key that chains to the
pinned root. Freshness (monotonic `sequence`/`generated` + short expiries + a ≤12h heartbeat
re-sign + a `rollback_floor_build`) additionally defeats freeze, replay, and downgrade attacks.

The full, normative contract is **[`SPEC.md`](./SPEC.md)** — read it before changing anything.

## Architecture (at a glance)

- **Transient scheduled process.** The beacon is not a resident daemon: a per-OS scheduler
  artifact (a Windows Scheduled Task / a systemd timer / a launchd LaunchDaemon) wakes it daily,
  jittered, with boot-recovery for a missed run; it runs one verified pass, and it exits — which
  dissolves the self-replace deadlock and leaves no socket to attack.
- **Privileged broker + unprivileged sandboxed worker.** Only the worker touches the network
  (fetch + verify); it holds no install privilege. The broker applies verified installs behind
  a health gate and rolls back (re-verified, floor-bounded, no data loss) on failure. A
  single-instance lock (Admin/SYSTEM-only) keeps two passes from ever overlapping.
- **The beacon updates itself too.** Its own tracked component goes through the SAME
  stage → snapshot → install → health → rollback pipeline as every other component, applied
  LAST in a pass so a self-swap can never leave another component's install mid-flight.

## Workspace

| Crate | Role |
|-------|------|
| `crates/dig-updater-trust` | **Security core:** signed manifest + delegation types, monotonic trust state, Ed25519 + SHA-256 verification, the pinned root key. |
| `crates/dig-updater-broker` | Privileged orchestration: spawn the sandboxed worker, the single-instance lock, ACL self-check, install/health-gate/rollback, the per-OS scheduler artifact (`scheduler` module), and the beacon's own self-update (`selfupdate` module). |
| `crates/dig-updater-worker` | Unprivileged fetch/verify worker — the only part that touches the network. |
| `crates/dig-updater-cli` | The `dig-updater` binary — the operator interface: `check [--now\|--dry-run]`, `run` (a full pass — what the schedule invokes), `channel get\|set`, `pause [--until <ts>] / resume`, `schedule install\|uninstall\|status`, `status` (unprivileged). |
| `crates/dig-updater-feedsign` | CI-only feed signer (never shipped in the beacon binary). |

## Build

```bash
cargo build --workspace          # build everything
cargo test  --workspace          # the full test suite (OS-mutating scheduler/lock tests are
                                  # #[ignore]d — see below)
cargo clippy --workspace --all-targets -- -D warnings
cargo llvm-cov --workspace --fail-under-lines 80 --summary-only   # coverage gate
```

> **Windows local-dev note.** A test/binary whose filename contains "updater" trips Windows UAC
> installer-detection (error 740) when run unelevated; `.cargo/config.toml` embeds an
> `asInvoker` manifest at link time (covering the shipped binaries AND the `cargo test`
> harness), so this runs unelevated on every OS the beacon ships to.

### Elevated tests

A handful of tests mutate real, privileged OS state — a Scheduled Task, systemd units, a
LaunchDaemon, the production single-instance mutex — and therefore require the SAME privilege
the beacon runs at (Administrator on Windows, root on Unix). They are `#[ignore]`d by default;
run them explicitly from an elevated console/`sudo`:

```bash
cargo test -p dig-updater-broker --lib -- --ignored             # the production lock contention test
cargo test -p dig-updater-broker --test scheduler -- --ignored  # install/status/uninstall + ACL checks
```

The dedicated `scheduler-elevated` CI job runs both on all three OSes on every PR.

## The pinned key

- `keys/beacon-root.pub` — the root public key (PEM). The matching base64 is compiled into
  `dig-updater-trust` as `BEACON_ROOT_PUBKEY_B64`; a unit test asserts the two agree.
- The **private** half is the `BEACON_SIGNING_KEY` GitHub Actions secret on this repo, used by
  CI to sign the feed. It is never committed and never printed.

## Status

Alpha: the trust core, the install path, the scheduling/self-update surface, and the operator CLI
(channel/pause/status) are implemented and tested (epic **#504**, work-units -A/-C/-D/-E/-F/-G).
Remaining follow-ups — the `updates.dig.net` feed origin, native packages + installer
registration, the `dig-node` updater RPC proxy (built on the `status.json` contract in `SPEC.md`
§13), an Updates UI, and docs — are tracked under #504. Nothing is released to users yet.
License: **GPL-2.0-only**.
