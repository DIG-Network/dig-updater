# dig-updater — Specification

**Status:** normative. This document is the authoritative contract for the DIG auto-update
beacon (`dig-updater`). An independent reimplementation MUST be buildable against this
document alone. The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used per RFC 2119.

The beacon keeps every installed DIG binary (`dig-node`, `dig-installer`, `dig-relay`,
future components) current on the **nightly alpha channel**: once a day it fetches a signed
description of the latest builds, verifies it, downloads the artifacts, verifies each one,
and installs them behind a health gate — rolling back on failure.

---

## 1. Trust invariant — the signature is the gate, not the transport

**Every byte the beacon installs MUST chain, cryptographically, to a single root public key
compiled into the beacon binary.** The chain has exactly three links:

1. A **root→targets delegation**, signed by the pinned **root** key, names the key currently
   authorized to sign update manifests (the **targets** key).
2. An **update manifest**, signed by that targets key, states — per component and per OS/arch
   — the download URL and the **SHA-256 digest** of the artifact bytes.
3. Each **downloaded artifact** is verified byte-for-byte against the digest in the signed
   manifest **before** it is handed to the privileged installer.

Because the digest lives *inside* the signed manifest, and the manifest chains to the pinned
root key, the authenticity of an installed artifact depends ONLY on the private keys — never
on the transport, the CDN, the DNS, the TLS session, the CI token, or the build runner. The
network is treated as fully hostile. **A valid signature over a fresh manifest is necessary
and sufficient to trust; the absence of one is sufficient to reject.**

An implementation MUST NOT install any artifact whose bytes it has not verified against a
digest carried in a manifest that verified under the current delegation under the pinned root
key. There is no "trusted download" fast path and no TLS-only fallback.

---

## 2. Threat model

The beacon runs on end-user machines and updates privileged software; a compromise can seize
an entire fleet. The design defends against each of the following adversaries **in
isolation** — none of them, alone, suffices to install malicious or downgraded code or to
brick/seize the fleet:

| Adversary | Capability | Why it fails |
|-----------|-----------|--------------|
| Hostile CDN / mirror | Serves arbitrary bytes at any artifact URL | Bytes are rejected unless they match the signed SHA-256 (§1 link 3). |
| Broken / MITM'd TLS | Forges/strips TLS, injects responses | Transport is untrusted; only the signature chain is trusted (§1). |
| Stolen `RELEASE_TOKEN` | Pushes tags, GitHub releases, feed objects | The token cannot sign; a manifest it publishes fails verification under the targets key. |
| Compromised build runner | Produces malicious binaries + digests | A manifest is only trusted if signed by the targets key; the runner does not hold it (alpha: see §11.2 residual). |
| Compromised **targets** key | Signs arbitrary manifests | Blast radius is bounded: the pinned root key can rotate the delegation to a new targets key (raising `root_version`), and freshness limits (§7) bound replay. The targets key can NEVER re-delegate or act as root. |
| Feed freeze / replay | Pins clients to a stale (vulnerable) version | Short manifest expiry + monotonic `generated`/`sequence` high-water-marks reject stale/replayed manifests (§7). |
| Downgrade attack | Serves an old, validly-signed, vulnerable build | `rollback_floor_build` + monotonic build checks reject builds below the floor (§7). |
| Self-update deadlock | A resident updater cannot replace its own running image | The beacon is a **transient** process (§8): it exits after one pass, so nothing holds its image open at replace time. |

The one adversary NOT fully defended in the alpha channel is a **compromised root key**; the
alpha uses a single root key whose private half lives in CI. Bounding this is the hardening
path in §11.2 (2-of-N threshold + offline root + KMS). This residual is accepted for alpha per
the #504 clearance and MUST be closed before public launch.

---

## 3. Cryptographic primitives

- **Signatures:** Ed25519 (RFC 8032). Public keys are 32 bytes; signatures are 64 bytes.
  Verification MUST be *strict* (reject small-order/non-canonical public keys and malleable
  signatures — the `verify_strict` semantics of `ed25519-dalek`). Verification MUST NOT accept
  a signature under a key of any other algorithm.
- **Digests:** SHA-256 (FIPS 180-4). Artifact digests are the 32-byte SHA-256 of the exact
  artifact bytes, represented on the wire as 64 lowercase hexadecimal characters.
- **Encodings on the wire:** signatures and public keys embedded in JSON are base64 with the
  **standard** alphabet (RFC 4648 §4), no line breaks. Digests are lowercase hex.

---

## 4. Signing hierarchy

### 4.1 Roles

- **Root key.** The trust anchor. Its PUBLIC half is *pinned* — compiled into every beacon
  binary (§4.2). Its PRIVATE half signs ONE thing: the delegation (§5.1). It never signs
  manifests directly (except that in the alpha floor root and targets are the same key — see
  §4.3).
- **Targets key.** The online key that signs manifests (§5.2). It is named by, and only valid
  while named by, the current delegation.

### 4.2 The pinned root key

The pinned root public key is committed to this repository in two byte-identical forms, and a
conformant build MUST verify they agree:

- `keys/beacon-root.pub` — PEM (`SubjectPublicKeyInfo`, RFC 8410): the 12-byte Ed25519 SPKI
  header `30 2a 30 05 06 03 2b 65 70 03 21 00` followed by the 32 raw key bytes.
- `crates/dig-updater-trust` `BEACON_ROOT_PUBKEY_B64` — the standard-base64 of the same 32 raw
  key bytes, the form compiled into the binary.

The current alpha root key is:

```
BEACON_ROOT_PUBKEY_B64 = "ZcjI14QiJ1Qety2clrKoDEkJyehiSBRoiYylEfiW3JI="
raw (hex)              = 65c8c8d7842227541eb72d9c96b2a80c4909c9e862481468898ca511f896dc92
```

The **private** half is the `BEACON_SIGNING_KEY` GitHub Actions secret on
`DIG-Network/dig-updater`. It MUST NEVER be committed to the repository and MUST NEVER be
printed in logs. CI uses it to sign the feed (§10).

### 4.3 Alpha floor vs production

- **Alpha (current).** A single self-generated Ed25519 key acts as BOTH root and targets; its
  private half lives in the CI secret. The delegation still exists on the wire (root signs a
  delegation naming the same key as targets), so the verification code path is the production
  path from day one — only the key custody is reduced.
- **Production (hardening path, §11.2).** The root key becomes a 2-of-N threshold with at
  least one key held **offline**, backed by a KMS/HSM; the targets key is a distinct online
  key; the pinned root key is rotated at that point. These are tracked follow-ups and are NOT
  part of the alpha channel.

---

## 5. Wire formats

All feed objects are UTF-8 JSON. Each signed object is a two-field envelope: the payload plus a
detached signature over the payload's **canonical signing bytes** (§5.4).

### 5.1 Delegation

```jsonc
// SignedDelegation
{
  "delegation": {
    "root_version":   1,                 // u32, monotonic delegation version
    "targets_pubkey": "<base64-32-byte>",// the key authorized to sign manifests
    "expires":        1731000000         // u64 unix seconds; not trusted after
  },
  "signature": "<base64-64-byte>"        // Ed25519 over signing_bytes(delegation), by ROOT
}
```

- `root_version` MUST NOT be less than the highest `root_version` the client has accepted
  (§7). A newer delegation rotates the targets key by raising `root_version`.
- `targets_pubkey` is the base64 of the 32-byte Ed25519 key whose signature authenticates
  manifests under this delegation.
- The signature MUST verify under the **pinned root key** (§4.2).

### 5.2 Manifest

```jsonc
// SignedManifest
{
  "manifest": {
    "schema":               1,           // u32 manifest schema version
    "root_version":         1,           // u32; MUST equal the in-force delegation's root_version
    "sequence":             42,          // u64, monotonic per-manifest counter (anti-rollback)
    "generated":            1730990000,  // u64 unix seconds when signed (anti-freeze high-water)
    "expires":              1731033200,  // u64 unix seconds; short (see §7 heartbeat)
    "rollback_floor_build": 20,          // u64; no component build below this may install
    "components": [
      {
        "name":    "dig-node",           // component id, matches the installed component
        "version": "0.26.0",             // human-facing semver of the latest release
        "build":   26,                   // u64 monotonic build number (anti-downgrade)
        "artifacts": [
          {
            "os":     "linux",           // os token: windows | linux | macos
            "arch":   "x64",             // arch token: x64 | arm64
            "url":    "https://updates.dig.net/dig-node/0.26.0/linux-x64",
            "sha256": "<64-hex>",        // SHA-256 of the artifact bytes
            "size":   18874368           // u64 advisory byte size (digest is authority)
          }
        ]
      }
    ]
  },
  "signature": "<base64-64-byte>"        // Ed25519 over signing_bytes(manifest), by TARGETS
}
```

- `root_version` MUST equal the `root_version` of the delegation whose targets key verified the
  manifest; a mismatch is rejected (a mixed delegation+manifest pair).
- `schema` identifies the manifest layout. A reader MUST accept every schema version it
  understands and MUST NOT reject an otherwise-valid manifest solely because `schema` is higher
  than the newest it emits, provided it can still parse it. Schema evolution is additive.
- `url` is UNTRUSTED. Only `sha256` authenticates the bytes.

### 5.3 Component / Artifact

A `component` groups one release (`version`, `build`) and its per-OS/arch `artifacts`. An
`artifact` is the smallest installable unit. The tuple (`os`, `arch`) MUST be unique within a
component. `build` is the monotonic identity used for anti-downgrade comparisons; `version` is
for display and MUST correspond to `build`.

### 5.4 Signed bytes — the signer canonicalizes, the verifier checks the RECEIVED slice

A signature covers the UTF-8 JSON bytes of the **payload** object (`delegation` or `manifest`) —
NOT the envelope, and NOT the `signature` field.

- **Signer.** A signer produces the payload deterministically: fields in the declaration order of
  §5.1 / §5.2, no insignificant whitespace, no maps/unordered collections. (The reference signer
  serializes the payload struct with `serde_json`, whose field order is fixed and which contains
  no maps.) It signs exactly those bytes and embeds them verbatim in the envelope.
- **Verifier.** A verifier MUST verify the signature over the **exact payload bytes as received on
  the wire** — the raw substring of the envelope's `delegation`/`manifest` value — and MUST NOT
  re-serialize the parsed payload and verify over that. The reference verifier captures the raw
  slice with a `serde_json` `RawValue` envelope (`SignedManifest::from_json` /
  `SignedDelegation::from_json`).

This distinction is what makes schema evolution (§5.2) **forward-compatible**: a future feed may
add an additive field an older verifier does not know. Those bytes are still inside the signed
message, so verifying over the received slice still succeeds; the verifier parses the fields it
understands and ignores the rest. Re-serializing the parsed struct would drop the unknown field
and compute different bytes, wrongly rejecting a valid newer feed — so verifiers MUST NOT do that.
An implementation MUST include a test that a manifest carrying an unknown field still verifies.

---

## 6. Monotonic trust state

The beacon persists the freshest values it has ever accepted. This state is what turns a
validly-signed but *stale* manifest (a freeze or rollback replay) into a rejected one.

```
TrustState {
  root_version:         u32,  // highest delegation root_version ever accepted
  sequence:             u64,  // highest manifest sequence ever accepted
  generated:            u64,  // highest manifest generated timestamp ever accepted
  rollback_floor_build: u64,  // highest rollback_floor_build ever accepted (never lowers)
}
```

- A fresh install starts with all fields zero; the first validly-signed, unexpired manifest is
  accepted and establishes the baseline.
- After a manifest is accepted, each field is advanced to `max(current, manifest value)`. The
  marks are strictly monotonic — they never move backward, even if `advance` is fed an older
  manifest.
- The state MUST be persisted in an Admin/SYSTEM-only location (§9.3) so an unprivileged
  process cannot roll it back to re-enable a downgrade.

---

## 7. Freshness — anti-rollback, anti-freeze, anti-downgrade

A valid signature is necessary but NOT sufficient. Before acting on a manifest the beacon MUST
enforce, in addition to the signature checks (§9):

1. **Not expired.** `now <= manifest.expires`. The delegation MUST also satisfy
   `now <= delegation.expires`.
2. **Anti-rollback (sequence).** `manifest.sequence >= state.sequence`.
3. **Anti-freeze (generated).** `manifest.generated >= state.generated`.
4. **Delegation monotonicity.** `manifest.root_version >= state.root_version`.
5. **Anti-downgrade (build floor).** For every component, `component.build >=
   manifest.rollback_floor_build`. A build strictly below the floor MUST NOT be installed even
   if the manifest is otherwise valid.

**Heartbeat re-sign.** The feed MUST be re-signed on a short cadence — at most every **12
hours** — with a fresh `generated` and a short `expires` (recommended `expires = generated +
12h`). A client that cannot obtain a manifest with `now <= expires` MUST treat the feed as
stale (frozen) and MUST NOT act on the expired manifest; it retries on the next pass. This
bounds how long a network adversary can freeze a client to the expiry window rather than
indefinitely.

**Boot recovery.** On system boot (or when a scheduled pass was missed), the beacon SHOULD run
a catch-up pass so a machine that was offline past an expiry re-establishes freshness promptly
rather than waiting for the next daily tick.

---

## 8. Process model

### 8.1 Transient, scheduled, single-pass

The beacon is NOT a resident daemon. It is a **transient scheduled process**: the OS scheduler
wakes it (daily, plus boot-recovery), it performs exactly ONE update pass, and it **exits**.
There is no long-lived socket and no resident service to attack or to keep patched.

This design dissolves the **self-replace deadlock**: a resident updater cannot overwrite its
own running executable on Windows (the image is locked) or safely on Unix. Because the beacon
has exited by the time an install runs — and because self-update of the beacon itself is staged
for the *next* wake rather than performed in-process — nothing holds the image open at replace
time.

### 8.2 Single-instance lock

Each pass MUST acquire a single-instance lock before doing any work and release it on exit. If
the lock is already held (a prior pass overran), the new invocation MUST exit immediately
without acting. The lock MUST live in an Admin/SYSTEM-only location.

### 8.3 Privilege split — privileged broker + unprivileged worker

A pass runs as two processes:

- **Broker (privileged).** Holds the rights to replace on-disk binaries and reconfigure OS
  services. It does NOT touch the network. It spawns the worker, receives only *verified*
  results, applies installs behind the health gate (§9.5), and rolls back on failure.
- **Worker (unprivileged, sandboxed).** The ONLY part that touches the network. It downloads
  the delegation, manifest, and artifacts, and verifies every one against the trust core
  (§9). It holds NO install privilege, so a compromise of this network-facing code cannot
  escalate to code execution as the installing identity.
  - On Windows (alpha floor) the worker runs under a restricted token / low-integrity level; a
    full AppContainer sandbox is a hardening follow-up (§11.2).
  - On Unix the worker drops to an unprivileged uid.

The broker MUST re-verify (or receive proof of verification for) any artifact before installing
it; it MUST NOT trust the worker to have verified correctly on a security-relevant path where
re-verification is cheap (digests are).

---

## 9. Verification algorithm (normative)

Given the pinned root key `R`, the persisted `TrustState S`, a `SignedDelegation D`, a
`SignedManifest M`, and the current time `now`, a pass MUST proceed in this order and MUST
abort (install nothing) on the first failure:

1. **Verify the delegation.** Decode `D.signature` (base64→64 bytes). Verify it strictly over
   `D`'s **received payload bytes** (§5.4) under `R`. On failure → reject. Then require
   `now <= D.delegation.expires`. Decode `D.delegation.targets_pubkey` (base64→32 bytes) into
   the targets key `T`.
2. **Verify the manifest signature.** Decode `M.signature`. Verify it strictly over `M`'s
   **received payload bytes** (§5.4) under `T`. On failure → reject.
3. **Bind manifest to delegation.** Require `M.manifest.root_version ==
   D.delegation.root_version`.
4. **Enforce freshness (§7).** Require not-expired, `sequence >= S.sequence`,
   `generated >= S.generated`, `root_version >= S.root_version`.
5. **Enforce the rollback floor (§7.5).** For every component, `build >= rollback_floor_build`.
6. **Per artifact, before install:** stream the bytes from `artifact.url` into a staging file,
   hashing incrementally, and require the SHA-256 equals `artifact.sha256` (lowercase-hex
   compare). On mismatch → reject that artifact and MUST NOT install it (and remove the staged
   bytes). This is **verify-then-install**, never install-then-verify. The download is bounded by
   a hard size cap of `min(4 × artifact.size, 2 GiB)`: a stream exceeding the cap is rejected
   before the disk can be filled (a disk-fill DoS guard against a hostile CDN). Because it streams
   with a fixed buffer, the beacon's memory does not grow with artifact size.
7. **On success:** install (§9.5), then advance `S` (§6) and persist it. `S` MUST NOT be
   advanced before a successful, health-gated install. (A `check --dry-run` performs steps 1–6 —
   including staging + digest verification — but NEVER installs and NEVER advances `S`.)

Every rejection MUST be a distinct, catalogued reason (bad signature, expired, sequence
regressed, generated regressed, root_version regressed/mismatch, below floor, digest mismatch,
artifact too large, malformed encoding) so failures are diagnosable and machine-classifiable. The
checks fail CLOSED: any error, malformed field, or unmet condition rejects.

### 9.5 Health-gated install + rollback

After installing verified artifacts, the broker MUST run a health check appropriate to each
component (e.g. the service starts and answers a liveness probe). If the health check fails,
the broker MUST roll back to the last known-good build and MUST re-verify the rollback target
against the trust chain before reinstating it (a rollback is an install and gets the same
verification). A rollback MUST NOT downgrade below `rollback_floor_build`. State migrations
MUST be backward-compatible: a build's on-disk state MUST remain readable by the immediately
prior build, so a rollback never bricks on unreadable state and never destroys data
(no destructive down-migration).

---

## 10. The feed + signing (CI)

The signed feed is two UTF-8 JSON documents — `delegation.json` (§5.1) and `manifest.json` (§5.2)
— served under a **feed base URL**. The beacon fetches `{base}/delegation.json` and
`{base}/manifest.json` from each base in its ladder (untrusted transport, §1); the first base that
serves BOTH wins.

### 10.1 Feed URLs

| Tier | Base URL | delegation | manifest |
|------|----------|------------|----------|
| Primary (production) | `https://updates.dig.net/v1/alpha` | `…/v1/alpha/delegation.json` | `…/v1/alpha/manifest.json` |
| Fallback (alpha, baked-in) | `https://github.com/DIG-Network/dig-updater/releases/download/feed` | `…/feed/delegation.json` | `…/feed/manifest.json` |

The alpha channel ships on the FALLBACK — a rolling GitHub release tagged `feed` — so it works with
NO AWS dependency. `updates.dig.net` (its own S3+CloudFront, ticket #504-I(b)) becomes primary by a
deploy-time flip once its OIDC role lands; that is a transport change, not a code change, because
both bases are untrusted (§1).

### 10.2 Cadence + freshness

CI re-signs the feed **every 6 hours** (`cron: 0 */6 * * *`, plus on demand). Each run stamps a
fresh `generated` == `sequence` == the run's unix time, a manifest `expires` = `generated + 12h`
(§7), and a delegation `expires` = `generated + 30d`. The 6-hour cadence against the 12-hour
manifest expiry leaves 6 hours of slack, so a single skipped/failed run never leaves clients without
an unexpired manifest. Because `generated`/`sequence` is the wall-clock time, it is monotonic across
runs and IS the anti-freeze/anti-rollback high-water-mark directly. The `generated` timestamp is
supplied INTO the signer by the workflow (not read from the signer's clock), so a run is
deterministic and reproducible.

### 10.3 What the manifest states

For every configured component the signer resolves the **latest GitHub release**, selects the
per-OS/arch binary assets — named `{prefix}-{version}-{platform-token}` (e.g.
`dig-node-0.29.0-linux-x64`, `digstore-0.13.1-windows-x64.exe`; sibling `.tar.gz`/companion assets
are excluded) — downloads each, and records its SHA-256 + size. The component `build` is the packed
monotonic number `major·10⁶ + minor·10³ + patch`, so a higher release always sorts higher (§5.3);
`minor`/`patch` MUST stay below 1000 to preserve that ordering. The alpha component set is
**dig-node, digstore, dig-updater, dig-dns**; `rollback_floor_build` comes from the committed
`feed-config.json` (alpha default `0`). The component set, floor, and freshness windows all live in
that one reviewable file — never hard-coded in the signer.

### 10.4 Byte-identical serving — NO transform (normative)

A verifier checks the signature over the payload bytes **exactly as received** (§5.4). The feed
objects MUST therefore be served **byte-for-byte as signed** — no re-encoding, re-minification,
whitespace/newline normalization, BOM insertion, or CDN "optimization" of the JSON. Any transform of
`delegation.json`/`manifest.json` in transit invalidates the signature and is a SERVING bug, not a
client bug. Both origins (the GitHub `feed` release and updates.dig.net, #504-I(b)) MUST serve the
objects verbatim with a content type that triggers no transformation.

### 10.5 Signer + secret hygiene

Signing runs ONLY in CI (`.github/workflows/feed.yml`), in the `dig-updater-feedsign` crate — a
CI-only workspace member NEVER packaged into a shipped beacon binary. It signs through the SAME
trust core the beacon verifies with (`SignedManifest::sign` / `SignedDelegation::sign` over
`signing_bytes`, §5.4), so the signer and the verifier cannot drift. The private key exists only as
the `BEACON_SIGNING_KEY` secret (§4.2); it flows secret → env → the signer process and is NEVER
exported or logged (the job summary prints only the sequence, timestamp, and public digests). Before
signing, the signer confirms the key derives the pinned root public key (§4.2) and refuses to sign
otherwise (fail closed). The alpha floor signs the delegation AND the manifest with the one key
(root == targets, §4.3).

**SECURITY (H1):** The signing capability is bound to REVIEWED main code. The workflow's
sign-verify-publish job is guarded by `if: github.ref == 'refs/heads/main'` — a `workflow_dispatch`
trigger or unreviewed-branch push can never sign with the real key or publish to the `feed` release
(the one every beacon trusts). `BEACON_SIGNING_KEY` MUST be a GitHub Environment secret with a
required human reviewer (environment `feed-signing`, #540), enforcing that signing happens only
after main-branch code review. This closes the branch-dispatch bypass vector (H1 from the adversarial
gate).

### 10.6 Self-proving publish

Every run PROVES itself before it publishes: CI has the freshly-built beacon — pinning the REAL root
key — verify the just-signed feed end-to-end (delegation + manifest signatures, freshness, and each
artifact digest) from a clean build. Publish to the `feed` release happens ONLY if that verification
passes, so a feed that does not verify is never served. The `dig-release-resolver` crate (a cleaner
replacement for the inline GitHub-release resolution), the beacon's own native packages, the
installer's registration of the beacon service, and the `dig-node` updater RPC proxy are follow-up
tickets (§12).

---

## 11. Security properties (summary of invariants)

An implementation MUST uphold all of:

1. **Anchored trust.** No artifact installs unless it chains to the pinned root key (§1).
2. **Transport-independence.** Trust never depends on TLS/CDN/DNS/token/runner (§2).
3. **Bounded targets compromise.** A stolen targets key cannot re-delegate, cannot act as
   root, and is rotated out by a higher-`root_version` delegation (§2, §4).
4. **Monotonic freshness.** Expired, replayed, frozen, or downgraded manifests are rejected
   (§6, §7).
5. **Verify-then-install.** Bytes are digest-verified before reaching privileged install (§9).
6. **Least privilege.** The network-facing worker holds no install privilege (§8.3).
7. **No self-replace deadlock.** The transient process model lets the beacon update itself and
   its peers (§8.1).
8. **Fail-closed, diagnosable.** Every check fails closed with a distinct reason (§9).
9. **Safe rollback.** Rollbacks are re-verified, floor-bounded, and never destroy data (§9.5).
10. **Secret hygiene.** The signing private key lives only in CI and is never committed/printed
    (§4.2).

### 11.2 Hardening path (NOT alpha)

The following are explicitly deferred to before public launch and tracked as follow-ups; the
alpha ships on the pinned-key + monotonic-freshness floor without them:

- 2-of-N root threshold with ≥1 offline root key, KMS/HSM-backed signing, and rotation of the
  alpha pinned key.
- A transparency log (e.g. Rekor/tough) recording signed manifests for external auditability.
- A full Windows AppContainer sandbox for the fetch/verify worker (alpha: restricted-token /
  low-integrity).

---

## 12. Conformance + implemented scope

This repository implements the **beacon core** (the trust core plus the wired fetch → verify →
plan pipeline, #504-A/-C/-D):

- **`dig-updater-trust`** — the wire types (§5), the monotonic trust state (§6), the freshness
  checks (§7), the signature + digest verification (§9, no I/O), and the pinned root key (§4.2).
  Signatures are verified over the **received payload bytes** (§5.4), so an additive future field
  still verifies (forward-compatible).
- **`dig-updater-worker`** — the unprivileged fetch/verify worker (the network edge): the feed URL
  ladder, the full §9 chain steps 1–5 against the pinned key + persisted trust state, and per
  artifact streaming SHA-256 download-to-staging with the §9-step-6 size cap. It emits a JSON
  verification report and holds NO install capability. Only this binary pins the root key; the
  library takes the key as a parameter (tested with throwaway keys — no runtime key override).
- **`dig-updater-broker`** — the privileged half: it spawns the worker UNPRIVILEGED (Unix
  `setuid`/`setgid` drop; Windows restricted token, §8.3) and persists the Admin/SYSTEM-only,
  atomic, forward-compatible trust state (§6, §9.3). `Broker::dry_check` runs §9 steps 1–6 and
  NEVER advances the state.
- **`dig-updater` (CLI)** — `check` (a dry verify pass) and `status`, with `--json` and a
  `--feed-base` transport override (the key is never overridable).
- **`dig-updater-feedsign`** — the CI-only feed signer (§10): resolves the latest release per
  component, downloads + digests the per-OS/arch assets, assembles the manifest + delegation, and
  signs them through the trust core (`SignedManifest::sign`/`SignedDelegation::sign`). Its
  `feed.yml` workflow re-signs every 6h, has the freshly-built pinned-key beacon verify the result
  end-to-end, and only then publishes the byte-exact feed to the rolling GitHub `feed` release. It
  is NEVER packaged into a shipped beacon binary.

The following are follow-up tickets under epic #504 and are OUT of scope here:

- **#504-E** enumerate installed components + ACL self-check + install + health gate + rollback
  (broker, §9.5) — the install path that advances the trust state.
- **#504-F** scheduler artifacts (Task Scheduler / systemd timer / launchd) with Admin/SYSTEM
  DACLs, the single-instance lock, boot recovery, and beacon self-update (§8).
- **#504-G/-I(b)/-H/-J/-K/-L** CLI completion, the `updates.dig.net` S3+CloudFront feed origin
  (the signer + nightly CI itself, #504-I(a), ships here — see §10), beacon native packages +
  installer registration, `dig-node` updater RPC proxy, Updates UI, and docs.
- **#534** the full Windows AppContainer worker sandbox (the alpha ships the restricted-token
  floor).

A conformant beacon MUST implement §§1–9 before it installs anything on a user machine.
