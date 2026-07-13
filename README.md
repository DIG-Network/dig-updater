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

- **Transient scheduled process.** The beacon is not a resident daemon: the OS scheduler wakes
  it daily (plus boot-recovery), it runs one verified pass, and it exits — which dissolves the
  self-replace deadlock and leaves no socket to attack.
- **Privileged broker + unprivileged sandboxed worker.** Only the worker touches the network
  (fetch + verify); it holds no install privilege. The broker applies verified installs behind
  a health gate and rolls back (re-verified, floor-bounded, no data loss) on failure.

## Workspace

| Crate | Role |
|-------|------|
| `crates/dig-updater-trust` | **Security core** (implemented + tested): signed manifest + delegation types, monotonic trust state, Ed25519 + SHA-256 verification, the pinned root key. |
| `crates/dig-updater-broker` | Privileged orchestration (stub — #504-E/-F). |
| `crates/dig-updater-worker` | Unprivileged fetch/verify worker (stub — #504-D). |
| `crates/dig-updater-cli` | The `dig-updater` binary: `check` / `status` (wired stubs). |

## Build

```bash
cargo build --workspace          # build everything
cargo test  --workspace          # run the trust-core test suite
cargo clippy --workspace --all-targets -- -D warnings
cargo llvm-cov --workspace --fail-under-lines 80 --summary-only   # coverage gate
```

> **Windows local-dev note.** A test/binary whose filename contains "updater" trips Windows UAC
> installer-detection (error 740) when run unelevated. CI runs tests on Linux, so this is a
> local nuisance only; to run the suite on Windows without elevation, set
> `__COMPAT_LAYER=RunAsInvoker`. The shipped Windows binary will carry an `asInvoker` manifest
> (an OS-integration follow-up).

## The pinned key

- `keys/beacon-root.pub` — the root public key (PEM). The matching base64 is compiled into
  `dig-updater-trust` as `BEACON_ROOT_PUBKEY_B64`; a unit test asserts the two agree.
- The **private** half is the `BEACON_SIGNING_KEY` GitHub Actions secret on this repo, used by
  CI to sign the feed. It is never committed and never printed.

## Status

Alpha scaffold: the trust core + full CI/release gate set are in place; the fetch/install/
scheduler pipeline lands in follow-up tickets under epic **#504**. Nothing is released to users
yet. License: **GPL-2.0-only**.
