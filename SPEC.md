# dig-updater — Specification

**Status:** normative. This document is the authoritative contract for the DIG auto-update
beacon (`dig-updater`). An independent reimplementation MUST be buildable against this
document alone. The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used per RFC 2119.

The beacon keeps every installed DIG binary (`dig-node`, `dig-installer`, `dig-relay`,
future components) current on its configured update **channel** — `stable` (tested releases, the
default) or `nightly` (bleeding-edge builds) (§13.1): once a day it fetches that channel's signed
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
BEACON_ROOT_PUBKEY_B64 = "FIwQOAGI3D0pwEP2oAkvlOqEoM6LoxRliLUxQPjpeJ0="
raw (hex)              = 148c10380188dc3d29c043f6a0092f94ea84a0ce8ba3146588b53140f8e9789d
```

The **private** half is the `feed-signing` GitHub Environment secret on `DIG-Network/dig-updater`,
scoped to the `main` branch. It MUST NEVER be committed to the repository and MUST NEVER be
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

## 6. Monotonic trust state — PER CHANNEL

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
- All four marks — including `rollback_floor_build` — are ENFORCED as monotonic at verify time:
  §7 rejects any manifest that regresses one (`root_version`/`sequence`/`generated`/
  `rollback_floor_build`) against the persisted state, and §9 step 4 applies that enforcement.
- The state MUST be persisted in an Admin/SYSTEM-only location (§9.3) so an unprivileged
  process cannot roll it back to re-enable a downgrade. A persisted state file that EXISTS but is
  missing a known mark (a truncation/tamper) MUST fail closed, NOT be read as a zeroed baseline —
  only a wholly-absent state file is a fresh install.

### 6.1 One independent state PER CHANNEL

Because the feed is published per channel (§10.1), each channel keeps its OWN monotonic trust
state, persisted in a SEPARATE file in the same Admin/SYSTEM-only directory with identical
hardening: `trust-state-nightly.json` and `trust-state-stable.json`. A pass loads AND advances ONLY
the file for the channel it is tracking (§13.1). This yields the per-channel anti-rollback
invariants:

- **A channel switch can never rewind the OTHER channel's floor.** Each channel's four marks are a
  high-water mark WITHIN that channel alone; while a beacon tracks one channel, the other channel's
  file is untouched. A `stable → nightly → stable` switch therefore leaves the stable marks exactly
  where they were — a switch cannot lower any floor. The two floors are structurally independent.
- **A freshly-selected channel's first-manifest replay is bounded by ANTI-FREEZE, not by monotonic
  state.** A channel with no prior state file accepts its first valid, UNEXPIRED manifest as the
  baseline. The `now <= manifest.expires` check (§7.1) is ABSOLUTE (wall-clock vs `expires`),
  independent of monotonic state — so an adversary cannot serve a >12h-stale, validly-signed
  manifest as that "first" baseline after a switch.
- **Cross-channel version movement is an AUTHORIZED operator action, not a rollback exploit.**
  Switching `nightly → stable` installs the last stable `vX.Y.Z` — OLDER code than nightly HEAD — a
  deliberate "downgrade to tested". `channel set` is elevation-gated (§13.1); anti-rollback's job is
  ONLY to stop a network adversary forcing an old build WITHIN a channel, which per-channel state
  keeps entirely separate from the operator's cross-channel choice.
- **Build scales are per channel and never compared across channels.** Stable uses the packed-semver
  `build` (`major·10⁶ + minor·10³ + patch`); nightly uses the UTC build date `YYYYMMDD` (§10.3).
  Because each channel's anti-downgrade comparison is bounded to its own state file, the two scales
  never meet.
- **The last-known-good rollback cache is ALSO per channel.** The cached last-known-good build a
  rollback restores (§9.5) is stored in a per-channel subdirectory (`lkg/<channel>`), mirroring the
  per-channel trust state. A channel's cached build and the rollback floor gating it are therefore
  ALWAYS on the same version scale, so a channel switch can never leave a nightly-dated build
  (`YYYYMMDD`) cached where a later stable-channel restore would compare it against the semver floor
  and pass spuriously. A shared cache would cross the scales that the state files keep separate.

**Legacy migration.** The pre-channel beacon kept a single `trust-state.json`. On the first load
after upgrade the NIGHTLY channel ADOPTS that legacy file (legacy alpha ≡ nightly, §10.1), so an
install already on the bleeding-edge stream keeps its monotonic marks with no reset; STABLE has no
legacy file and starts fresh (its first unexpired manifest is the baseline, bounded by anti-freeze
above). Once a channel's own file exists it is authoritative — the legacy file is never written to
again and never shadows it.

---

## 7. Freshness — anti-rollback, anti-freeze, anti-downgrade

A valid signature is necessary but NOT sufficient. Before acting on a manifest the beacon MUST
enforce, in addition to the signature checks (§9), against the tracked channel's OWN monotonic state
(§6.1):

1. **Not expired.** `now <= manifest.expires`. The delegation MUST also satisfy
   `now <= delegation.expires`. This ABSOLUTE wall-clock check is what bounds a freshly-selected
   channel's first-manifest replay (§6.1) — it does not depend on prior monotonic state, so a fresh
   channel's baseline manifest cannot be a >12h-stale replay.
2. **Anti-rollback (sequence).** `manifest.sequence >= state.sequence`.
3. **Anti-freeze (generated).** `manifest.generated >= state.generated`.
4. **Delegation monotonicity.** `manifest.root_version >= state.root_version`.
5. **Floor monotonicity.** `manifest.rollback_floor_build >= state.rollback_floor_build`. The
   floor is a monotonic high-water-mark (§6): a manifest MAY raise it but MUST NOT lower it. This
   is a distinct check from item 6 — it defends the FLOOR itself, blocking a compromised targets
   key from resetting the floor (e.g. to 0) within a `root_version` epoch to re-open a downgrade
   window; only a higher-`root_version` delegation from the pinned root could legitimately do that.
6. **Anti-downgrade (build floor).** For every component, `component.build >=
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
own running executable on Windows (the image is locked) or safely on Unix. The beacon's own
tracked component is applied through the SAME stage → snapshot → install → health → rollback
pipeline as every other component (§9.5), but MUST be the LAST one applied in a pass, after
every other component has already settled — a self-swap that raced ahead of the rest of the
pass would risk leaving another component's in-flight install inconsistent if the process then
died mid-swap. Applying it at the end of the SAME pass, rather than deferring it to the next
wake, is safe specifically because the pass is about to exit anyway (nothing else in this
process depends on the old image surviving past that point):

- **Unix** replaces the running executable with a single atomic rename. The kernel keeps the OLD
  file open for whichever process is still executing it; the rename only changes which bytes the
  path resolves to for the NEXT invocation.
- **Windows** cannot overwrite a loaded image's bytes in place, so the swap is two plain renames:
  the running image moves aside to a `.old` sibling (permitted — the OS shares delete/rename
  access on the running file even while it executes), then the verified copy takes its name. If
  either half fails, the swap MUST be undone rather than left half-applied, so the beacon is
  never left without a working binary at its own destination.

### 8.2 Single-instance lock

Each pass MUST acquire a single-instance lock before doing any work — before the network is
touched or anything is installed — and release it on exit (including on a crash: the lock MUST
NOT require an explicit clean shutdown to release). If the lock is already held (a prior pass
overran), the new invocation MUST exit immediately without acting, reporting a distinct,
non-error outcome (SPEC §12: `already_running`). The lock MUST live in an Admin/SYSTEM-only
location:

- **Windows:** a named mutex in the session-independent `Global\` namespace (so a
  Task-Scheduler-launched SYSTEM pass in Session 0 and a manually-run pass from an interactive
  elevated console still serialize against each other), DACL'd to Administrators + Local System
  only — an unprivileged process MUST NOT be able to acquire OR query it.
- **Unix:** an advisory exclusive file lock on a file inside the Admin/SYSTEM-only state
  directory (§9.3); the containing directory's own permissions are what keep an unprivileged
  process from ever reaching the lock file at all.

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

The staging directory is writable by the (privilege-dropped) worker, so its contents and the paths
the worker reports are untrusted. The broker therefore MUST:

- **Contain the staged path.** Canonicalize the worker-reported staged path and REJECT (a distinct,
  catalogued error) anything that does not resolve strictly inside the broker-owned staging
  directory, BEFORE reading a byte — an absolute path elsewhere (`/tmp/evil`) or a `..` escape is
  refused.
- **Hash what it installs.** The bytes that are hashed MUST be the bytes that are installed. The
  broker copies the staged artifact ONCE into a broker-private file the worker cannot write, hashing
  from the same read, and installs from that private copy — so a swap of the staging file after the
  hash cannot change what is installed. Equivalently, hash and install from a single held fd. It
  MUST NOT hash a staging path and then re-open it by path to install (a TOCTOU window).
- **Invoke native installers by absolute path.** `msiexec`/`installer`/`dpkg` MUST be run from their
  absolute, trusted locations (e.g. `%SystemRoot%\System32\msiexec.exe`, `/usr/sbin/installer`,
  `/usr/bin/dpkg`), never a bare name resolved through `PATH`/CWD.

### 8.4 Scheduler artifact — what wakes a pass

The beacon does not schedule itself; a per-OS artifact registered OUTSIDE the beacon invokes it
on a schedule. Registering, removing, and reporting on that artifact is itself a privileged
operation (Administrator on Windows, root on Unix) — the same precondition the artifact runs at.

| OS | Artifact | Cadence + jitter | Boot recovery | Runs as |
|----|----------|-------------------|----------------|---------|
| Windows | a Scheduled Task | daily, native `RandomDelay` (re-drawn every occurrence) | `StartWhenAvailable` | `S-1-5-18` (SYSTEM), highest available run level |
| Linux | a systemd `.service` (oneshot) + `.timer` pair | daily, native `RandomizedDelaySec` (re-drawn every run) | `Persistent=true` | root (via systemd) |
| macOS | a `LaunchDaemon` plist | daily at a fixed, per-machine-jittered time-of-day (`StartCalendarInterval`; launchd has no native per-run jitter, so the spread is drawn ONCE at install time) | `RunAtLoad` | root |

Every artifact invokes the SAME command: a full pass (§9), never the dry check. The jitter
spreads fleet-wide load off a single instant; boot recovery ensures a machine that was off past
the scheduled time still gets a prompt update on its next boot rather than waiting a full day
for the next occurrence.

**Discoverable identity (MANDATORY).** The scheduler artifact MUST present the human-readable
display name **`DIG NETWORK: BEACON`** wherever the OS surfaces it, PARALLEL to the OS-service
identities `DIG NETWORK: NODE` (dig-node) and `DIG NETWORK: DNS` (dig-dns) — the ecosystem's
canonical OS-service identity contract (superproject `SYSTEM.md`). Windows carries it in the
Scheduled Task `<RegistrationInfo><Description>` (with the task's canonical `<URI>` = `\DIG\dig-updater`);
systemd carries it in the `.service` + `.timer` `Description=`; launchd's identity IS its canonical
reverse-DNS `Label` (`net.dignetwork.dig-updater` — macOS surfaces no separate friendly name). The
machine identifiers are unchanged (the Windows task path, the systemd unit stem, the launchd label
stay canonical); the display name is a legibility label. `dig-updater status` and `dig-updater
schedule status` MUST echo `DIG NETWORK: BEACON` so the beacon's identity + health are readable
without inspecting the OS scheduler. A change to this display name is a cross-repo contract change
coordinated with `SYSTEM.md` + the `canonical` skill. The Windows Task definition file, and (on Unix) the unit/plist files
themselves, MUST be locked down to the same Admin/SYSTEM-or-root bar as every other guarded path
this beacon depends on (§9.3) — Unix unit/plist files follow the platform convention of
root-owned, mode `0644` (world-readable, root-writable only, matching how `systemctl status`/
`launchctl print` are expected to work for any user).

**Self-heal (MANDATORY).** The artifact is registered by the installer, but a schedule that is
registered exactly ONCE and never re-asserted dies permanently the moment it goes missing — after
which no scheduled pass can ever fire again. Therefore **every full pass, before it does anything
else (before even the pause gate, so a paused beacon keeps its wake alive), MUST ensure its own
schedule is registered**: it queries the artifact's presence and, when the artifact is *provably
absent*, re-registers it. This is best-effort and non-fatal — a pass that cannot register (an
unprivileged invocation) or cannot determine presence continues. Registration is idempotent.

**Presence is TRISTATE, not a boolean.** Querying the artifact MUST distinguish three outcomes:
*registered*, *provably absent* (the OS reported "no such task" — Windows `ERROR_FILE_NOT_FOUND` /
`0x8004131F`, absent unit/plist files), and *undeterminable* (the query failed for another reason,
e.g. access-denied — Windows `0x80070005` — when an unprivileged caller inspects the SYSTEM task).
A status query MUST NOT report *undeterminable* as *absent*: the self-heal MUST re-register ONLY a
*provably absent* artifact (never an *undeterminable* one, or it could clobber a present-but-
unreadable task), and `schedule status` MUST NOT tell a user "NOT REGISTERED" when it merely could
not read the task. Removing the artifact (`schedule uninstall`) MUST also remove the now-empty
containing folder (Windows `\DIG`) so an empty folder cannot masquerade as a partial install.

**External re-arm — the `schedule ensure` verb + the opt-out sentinel (MANDATORY).** The per-pass
self-heal above only fires when the beacon RUNS — but a *dead schedule cannot run itself to re-arm*
(the chicken-and-egg). An always-on privileged component (the `dig-node` OS service) therefore
re-asserts the schedule on its own startup + a periodic tick by invoking a dedicated LIGHTWEIGHT
verb, `dig-updater schedule ensure`. `ensure` runs ONLY the self-heal — the tristate presence probe
plus a re-register of a *provably absent* artifact — with NO feed fetch, install, or self-update, so
it is cheap enough to kick frequently. It reports which branch ran as a stable machine code:
`already_registered`, `left_unknown`, `reregistered`, or `suppressed_by_opt_out`.

To keep an always-on re-arm from FIGHTING a user who removed the schedule ON PURPOSE, the beacon
distinguishes an accidental deletion from a deliberate one with an **opt-out sentinel** — a marker
file (`schedule-optout`) inside the Admin/SYSTEM-only state directory (§13.1):

- `schedule uninstall` WRITES the sentinel (after removing the artifact) and re-hardens it
  Admin/SYSTEM-only; `schedule install` CLEARS it (after registering).
- Both the `ensure` verb AND the per-pass self-heal MUST check the sentinel FIRST: when present,
  they leave the schedule removed (`suppressed_by_opt_out`) and MUST NOT re-register it.
- The check is **fail-OPEN toward availability**: only a marker that *provably exists* suppresses
  the self-heal; a missing OR unreadable/ambiguous marker is treated as "not opted out" (re-arm).
- The sentinel MUST live in the Admin/SYSTEM-only state dir (never the dry-check-relocatable one) so
  a non-privileged process cannot FORGE it to suppress auto-updates — an update-suppression /
  stale-pin vector. Its mere presence is the entire signal; its contents carry no trust.

The always-on driver kicks `schedule ensure` but NEVER touches the OS scheduler directly and NEVER
decides opt-out — the beacon remains the sole authority over the schedule artifact and honors the
sentinel. (The driver MUST resolve the beacon binary only from an Admin-only install root — a
user-writable beacon re-armed as a SYSTEM task would be a local-privilege-escalation vector; that
constraint lives on the `dig-node` side.)

---

## 9. Verification algorithm (normative)

Given the pinned root key `R`, the persisted `TrustState S` — of the TRACKED channel (§6.1), loaded
from that channel's own `trust-state-<channel>.json` — a `SignedDelegation D`, a `SignedManifest M`,
and the current time `now`, a pass MUST proceed in this order and MUST abort (install nothing) on
the first failure:

1. **Verify the delegation.** Decode `D.signature` (base64→64 bytes). Verify it strictly over
   `D`'s **received payload bytes** (§5.4) under `R`. On failure → reject. Then require
   `now <= D.delegation.expires`. Decode `D.delegation.targets_pubkey` (base64→32 bytes) into
   the targets key `T`.
2. **Verify the manifest signature.** Decode `M.signature`. Verify it strictly over `M`'s
   **received payload bytes** (§5.4) under `T`. On failure → reject.
3. **Bind manifest to delegation.** Require `M.manifest.root_version ==
   D.delegation.root_version`.
4. **Enforce freshness (§7).** Require not-expired, `sequence >= S.sequence`,
   `generated >= S.generated`, `root_version >= S.root_version`, and
   `rollback_floor_build >= S.rollback_floor_build` (floor monotonicity, §7.5).
5. **Enforce the rollback floor (§7.6).** For every component, `build >= rollback_floor_build`.
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
verification). A CROSS-PASS rollback (reinstating an older cached
build) MUST NOT downgrade below `rollback_floor_build`; a manual/out-of-band rollback MUST read that
floor from the PERSISTED (Admin/SYSTEM-only) trust state, never a caller-supplied value, since the
last-known-good record's digest is self-recorded beside the cached bytes. The floor gate does NOT
apply to an IN-PASS restore-in-place of the just-captured current snapshot (restoring bytes onto their
own destination can never be a downgrade relative to itself — the exemption that keeps "never left
missing" unconditional even for an un-ageable build). State migrations
MUST be backward-compatible: a build's on-disk state MUST remain readable by the immediately
prior build, so a rollback never bricks on unreadable state and never destroys data
(no destructive down-migration).

**Install root — the SAME location the user's binaries actually live.** The broker MUST install to,
and health-probe, the directory where the installed binaries actually are — NOT a hardcoded path.
The install root is derived from the **running beacon's own executable location**: the universal
installer places every DIG binary (including `dig-updater`) in one install bin dir, so the beacon
resolves that dir as the parent of its own `current_exe()` and installs each component as a SIBLING
of itself (falling back to the conventional per-OS path only if its own path cannot be resolved).
A raw-binary component is replaced at `{root}/{name}` (`.exe` on Windows); a native-package
component's OS installer owns its own target, and `{root}/{name}` is where the beacon PROBES its
installed version. This is the installer↔beacon contract: **the installer and the beacon agree on
the install root because the beacon derives it from where the installer placed the beacon** (recorded
in the superproject `SYSTEM.md`). Installing to a decoupled hardcoded directory — the prior bug —
left the user's real binary un-updated while the beacon reported success against a phantom copy.

**Resilient raw-binary replace — running/in-use targets.** A raw-binary component may be a running
service (e.g. dig-dns) or the beacon's own image, and its file can be transiently held in use by a
scanner/backup. The replace MUST therefore be resilient rather than fail hard: it MUST move any
existing target ASIDE to a `.dig-updater-old` sibling and then rename the verified copy into place
(a running image can be renamed away even where it cannot be overwritten in place). It MUST retry
ONLY the file-in-use class — Windows `ERROR_SHARING_VIOLATION` (32) / `ERROR_LOCK_VIOLATION` (33),
unix `ETXTBSY` (26) — with bounded backoff, and fail fast on any other (terminal) error. If the
target stays locked through the retry budget the pass DEFERS to the next wake (§9.5, a benign
outcome), and if the second rename fails the move-aside MUST be undone — through the SAME retried
rename, not a best-effort one-shot — so the original target is left byte-intact. If that undo ALSO
fails (a double fault that would otherwise leave the target MISSING), the replace MUST report a
FAILED (not deferred) outcome so the caller's last-known-good rollback (§9.5) reinstates the target.
That in-pass rollback restores the snapshot captured at the destination moments earlier in the SAME
pass — a restore-in-place, NOT a downgrade — so it is EXEMPT from the anti-downgrade floor gate and
MUST reinstate the target unconditionally, including when the prior build's version was un-ageable
(unparseable → no build number). The floor gate still applies UNCHANGED to a CROSS-PASS rollback that
reinstates an older cached build. Across every branch the target is NEVER left half-written or missing
— an unconditional invariant, regardless of the installed build's ageability. This is the SAME running-target-safe swap
the beacon's own self-update uses (§8.1); there is ONE implementation shared by every raw-binary
component and the self-update.

**A component is a binary SET — the primary AND its byte-identical aliases — all-or-nothing at the
target version.** A tracked component owns not just its primary executable but every byte-identical
ALIAS it ships under (`digs ≡ digstore`, `digd ≡ dig-dns`, `dign ≡ dig-node` — siblings of the
primary, `.exe` on Windows). The applier MUST treat the set as a unit across enumeration, replace,
health, AND rollback:

- **Replace the whole set from the verified primary.** After the primary lands (a raw-binary
  move-aside OR a native-package install), each alias is refreshed by COPYING the just-installed
  primary bytes — never a re-download, never an extra feed asset (the feed signs only the primary) —
  through the same resilient move-aside. This alias refresh runs for BOTH the raw-binary AND the
  native-package methods, so a package component's alias (dig-node's `dign`) is ALWAYS refreshed
  regardless of what the package itself lays down.
- **Health-check EVERY binary in the set.** A component whose alias is left stale — the primary
  advanced while the alias froze at its install-time version — MUST fail the health gate, NEVER
  report `Installed`.
- **Roll back the WHOLE set together.** The pre-pass snapshot MUST cover the primary AND every alias
  (each cached under a distinct key), so a failed health gate reverts the entire set — never leaving
  a split primary-new / alias-old (or vice-versa) state, which is the very drift this fixes.
- **Enumeration keys on the whole set.** The Install/Update/Skip decision MUST consider every binary
  in the set, not just the primary: if the primary looks current but ANY alias is missing or on a
  different version (e.g. a prior pass's alias replace deferred on a transient lock), the component
  MUST be re-driven as an Update so the stale alias is re-refreshed + re-health-checked on the next
  pass. Keying only on the primary would strand a stale alias forever.

If the primary replace defers or fails, the aliases are left untouched and that outcome propagates
unchanged.

**A service-backed component is stopped before its replace and restarted after — unconditionally.** A
component whose binary runs as an OS service (dig-node → `net.dignetwork.dig-node`) holds its
executable open while the service runs, so a replace attempted against the running service is deferred
(a `/norestart` MSI over the locked file) or fails (unix `ETXTBSY`), the install falsely "succeeds",
and the post-install `--version` probe reads the still-old binary → the health gate rolls it back. The
applier MUST therefore, for a service-backed component: **stop the service → replace → restart →
health-probe**, using the platform service manager resolved by its ABSOLUTE, trusted path (Windows
`sc.exe stop/start <id>`, Linux `systemctl stop/start <unit>` where the systemd unit name is derived
from the reverse-DNS id by dropping the `net.` qualifier + hyphen-joining — `net.dignetwork.dig-node`
→ `dignetwork-dig-node`, macOS `launchctl bootout system/<id>` / `bootstrap system <plist>`), never a
bare name resolved through `PATH`. Availability invariants:

- **An already-stopped / not-loaded service is NOT a stop failure.** `sc stop` (Windows) and
  `launchctl bootout` (macOS) exit non-zero when the service is already down; the applier MUST
  classify that (the platform's not-active / not-loaded signal) as a successful stop and PROCEED,
  so a node that is already down for any reason is not pinned down by a misread "refused to stop"
  (Linux `systemctl` already exits 0 for an inactive unit). Only a genuine refusal (e.g. access
  denied) leaves the service running and defers the pass.
- **Once stopped, the service MUST be restarted on EVERY subsequent path** — a successful update, a
  benign deferral, a rollback, OR a propagated rollback ERROR (an unreadable/corrupt last-known-good
  cache, a re-verify mismatch, a reinstate-write failure). The restart MUST run BEFORE any such error
  propagates, so a stopped node is never left down. A restart failure is surfaced as a warning but
  never turns an otherwise-correct on-disk state into a hard failure (the next scheduled wake + the
  service manager's own boot recovery bring it back).

---

## 10. The feed + signing (CI)

The signed feed is two UTF-8 JSON documents — `delegation.json` (§5.1) and `manifest.json` (§5.2)
— served under a **feed base URL**. The beacon fetches `{base}/delegation.json` and
`{base}/manifest.json` from each base in its ladder (untrusted transport, §1); the first base that
serves BOTH wins.

### 10.1 Feed URLs — per channel

The feed is published as TWO fully independent signed feeds, one per update **channel** — `stable`
and `nightly`. Each channel is a distinct `{base}/{delegation,manifest}.json` pair carrying its OWN
freshness (`generated`/`expires`) and anti-rollback (`sequence`/floor) marks, signed under the SAME
pinned root/targets key (§4.3). Separate paths give each channel its own monotonic trust context
with zero coupling: a client tracking one channel is never affected by the other's marks.

| Channel | Tier | Base URL |
|---------|------|----------|
| stable | Primary | `https://updates.dig.net/v1/stable` |
| stable | Fallback | `https://github.com/DIG-Network/dig-updater/releases/download/feed-stable` |
| nightly | Primary | `https://updates.dig.net/v1/nightly` |
| nightly | Fallback | `https://github.com/DIG-Network/dig-updater/releases/download/feed-nightly` |

Each channel publishes to **both** of its bases each run (§10.7): `updates.dig.net` (its own
S3+CloudFront, #535) is the PRIMARY, and the rolling GitHub `feed-<channel>` release is the
always-available fallback. Because both bases are untrusted transport (§1) and the beacon prefers
the freshest manifest by monotonic `sequence`, keeping them in lock-step is a resilience hedge, not
a trust dependency — a client that reaches either base installs the identical verified bytes.

**Legacy `/v1/alpha` (back-compat).** The pre-channel beacon fetched a single feed at
`https://updates.dig.net/v1/alpha` + the rolling `feed` release. A channel-aware beacon (#604) NO
LONGER fetches these: it derives its ladder from the tracked channel (`/v1/<channel>` + the
`feed-<channel>` release, §13.1), maps a legacy `alpha` config to NIGHTLY (alpha ≡ nightly),
adopting its old single-channel trust state as the nightly per-channel state (§6.1). The legacy
bases MUST nonetheless keep serving for beacons NOT YET upgraded past #604: the `stable` feed is
mirrored to `/v1/alpha` + the rolling `feed` release byte-for-byte, so an un-upgraded beacon keeps
receiving exactly the content it already got. `/v1/alpha` + `feed` retire once every beacon has
upgraded past #604.

### 10.2 Cadence + freshness

CI re-signs BOTH channel feeds **every 6 hours** (`cron: 0 */6 * * *`, plus on demand), each channel
independently (a `channel` job matrix, `fail-fast: false`). Each channel's run stamps a fresh
`generated` == `sequence` == the run's unix time, a manifest `expires` = `generated + 12h` (§7), and
a delegation `expires` = `generated + 30d`. The 6-hour cadence against the 12-hour manifest expiry
leaves 6 hours of slack, so a single skipped/failed run never leaves clients without an unexpired
manifest. Because `generated`/`sequence` is the wall-clock time, it is monotonic across runs and IS
the anti-freeze/anti-rollback high-water-mark directly. The `generated` timestamp is supplied INTO
the signer by the workflow (not read from the signer's clock), so a run is deterministic and
reproducible. The two channels are independent: signing/publishing one never gates the other, so
the nightly leg failing (e.g. a component without a rolling `nightly` release yet) can never stall
the stable feed.

### 10.3 What the manifest states — per-channel selection

For every configured component the signer resolves that channel's GitHub release, selects the
per-OS/arch assets, downloads each, and records its SHA-256 + size. Which release, which version,
and which `build` scale depend on the **channel**:

- **stable** — the newest NON-prerelease release (`releases/latest`). This resolution is
  BRANCH-AGNOSTIC: a stable `vX.Y.Z` originates from a `release/X.Y` branch (§14.2), but is published
  with `make_latest: true`, so it resolves here via `releases/latest` regardless of its origin branch
  — the feed needs no knowledge of the release-branch model. The version is the release tag with any
  leading `v` stripped (`v0.29.0` → `0.29.0`), and the `build` is the packed monotonic number
  `major·10⁶ + minor·10³ + patch`, so a higher release always sorts higher (§5.3); `minor`/`patch`
  MUST stay below 1000 to preserve that ordering.
- **nightly** — the rolling `nightly` release (`releases/tags/nightly`, #590). Its tag carries no
  version, so the version (`X.Y.Z-nightly.YYYYMMDD.<sha>`) is RECOVERED from the asset file names,
  and the FULL prerelease string is recorded as the manifest `version` (so the beacon compares
  against the real installed nightly, not a stripped semver). The `build` is the UTC build date
  `YYYYMMDD` — strictly increasing day-over-day, exactly the "never install an older nightly"
  semantic. The stable packed-semver scale and the nightly date scale are DISTINCT and NEVER
  compared across channels, because each channel keeps its own monotonic trust state (§7.5, #604).

The asset selected within a release depends on the component's **asset kind** — the signer MUST
select the SAME shape the broker will install (§9.5), or the broker stages a mislabelled file (a raw
executable renamed `dig-node.msi`) and its OS installer rejects it (`msiexec` exit 1620):

- **raw binary** (digstore, dig-dns, dig-updater — the default) — `{prefix}-{version}-{os}-{arch}`,
  with `.exe` on Windows (e.g. `digstore-0.13.1-windows-x64.exe`, `dig-node-0.31.1-linux-x64`);
- **native package** (dig-node) — the platform installer's native asset name: Windows
  `{prefix}-{version}-{os}-{arch}.msi`; macOS `{prefix}-{version}-macos.pkg` (ONE universal package,
  no arch token — both macOS arches resolve to it); Linux `{prefix}_{version}_amd64.deb` (the Debian
  convention — underscores, `amd64`, no `linux` token, e.g. `dig-node_0.31.1_amd64.deb`).

Both channels track the SAME component set with the SAME asset kinds — only the release each
resolves differs. Sibling `.tar.gz`/companion assets are excluded by requiring an EXACT
asset-name match. The alpha component set is **dig-node (native package), digstore, dig-updater,
dig-dns (raw binaries)**; each component's `asset_kind` comes from the committed `feed-config.json`
(default kind `raw_binary`). The anti-rollback floor is **per channel** (`channels.stable`,
`channels.nightly` — each on its own build scale, both defaulting to `0` = nothing floored;
raised deliberately to retire a vulnerable build). The component set, per-component asset kind, the
per-channel floors, and the freshness windows all live in that one reviewable file — never hard-coded
in the signer.

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
the `feed-signing` GitHub Environment secret (§4.2), scoped to the `main` branch; it flows secret →
env → the signer process and is NEVER exported or logged (the job summary prints only the sequence,
timestamp, and public digests). Before signing, the signer confirms the key derives the pinned root
public key (§4.2) and refuses to sign otherwise (fail closed). The alpha floor signs the delegation
AND the manifest with the one key (root == targets, §4.3).

**Environment protection (main-only deployment branch policy):** The `feed-signing` secret MUST be
restricted to GitHub environment protection rules that gate signing to the `main` branch ONLY. No
per-run required reviewer is imposed (doing so would block the 6-hour cron re-sign pending human
approval, but a delay >12h would allow the manifest to expire — §7 anti-freeze — structurally
breaking the auto-update heartbeat). Residual risk of unreviewed-branch signing is closed by the
`if: github.ref == 'refs/heads/main'` guard in the workflow, combined with main's branch protection
rules (§10.6 self-proving publish ensures feed verification before serving). The unreviewed-code
merged to main is an alpha-accepted CI-custody residual (§11.2 hardening path); it is closed at
public launch by threshold signing + offline root (tracking follow-up).

### 10.6 Self-proving publish

Every run PROVES itself before it publishes: CI has the freshly-built beacon — pinning the REAL root
key — verify the just-signed feed end-to-end (delegation + manifest signatures, freshness, and each
artifact digest) from a clean build. This keystone runs PER CHANNEL, and publish of a channel to
EITHER of its bases happens ONLY if THAT channel's verification passes, so a feed that does not
verify is never served.

### 10.7 Primary publish + live smoke (updates.dig.net)

After a channel's keystone verify, CI publishes its byte-exact `delegation.json` + `manifest.json`
to the PRIMARY origin `updates.dig.net` (an S3 bucket fronted by CloudFront, #535) at the key prefix
`v1/<channel>/` — EXACTLY the beacon's per-channel feed base — so the objects resolve at
`https://updates.dig.net/v1/<channel>/{delegation,manifest}.json`. CI authenticates to S3 with
short-lived **OIDC** credentials assuming a least-privilege role (`s3:PutObject` on the feed bucket
only); no static AWS keys exist in CI. Objects are written with `Content-Type: application/json` and
no content-encoding so they are served un-transformed (§10.4); CloudFront runs CachingDisabled, so a
fresh feed is served immediately with no invalidation. The S3 publish is a HARD step — a failure
reddens that channel's leg. CI then SMOKE-TESTS the live primary: it fetches
`https://updates.dig.net/v1/<channel>/manifest.json` and byte-compares it to the exact signed
manifest, retrying briefly for propagation; a mismatch fails the leg. The `stable` leg additionally
mirrors + byte-exact-smokes the legacy `/v1/alpha` base (§10.1 back-compat).

The GitHub `feed-<channel>` release (§10.1) is published in the same leg as the fallback base, but
its publish is INDEPENDENT of the primary publish + smoke: it is gated on the keystone verify
(§10.6) ALONE, not on `updates.dig.net` succeeding. A primary-edge outage — the exact failure the
fallback exists to hedge — therefore MUST NOT skip the fallback publish. Both bases remain strictly
downstream of the keystone (an unverified feed is never served to either), and the two refresh
independently since the beacon selects the freshest manifest by monotonic sequence (§7).

### 10.8 Transparency log (alpha: log-only, fail-soft)

Each run records the signed **manifest** in a PUBLIC append-only transparency log
(`rekor.sigstore.dev`, #533), so any observer can independently prove a given manifest was publicly
logged — turning a silent targets-key compromise into a publicly-visible one. The signer emits the
log inputs alongside the feed (`--transparency-out`): the manifest's canonical signed bytes (§5.4,
reused verbatim — not re-serialized), the detached 64-byte Ed25519 signature over them, and the
targets public key as an Ed25519 SubjectPublicKeyInfo PEM. In alpha this is **log-only and
FAIL-SOFT**: a log outage degrades to a warning and NEVER blocks the 6-hour heartbeat (§7), and the
recorded entry index is written beside the feed (`rekor-entry.json`) and into the job summary. The
beacon does NOT yet require an inclusion proof — that verification is a **beta** client obligation
(#533, deferred).

The `dig-release-resolver` crate (a cleaner replacement for the inline GitHub-release resolution),
the beacon's own native packages, the installer's registration of the beacon service, and the
`dig-node` updater RPC proxy are follow-up tickets (§12).

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
   its peers, applying its own swap LAST in a pass so a self-replace can never corrupt another
   component's in-flight install (§8.1).
8. **Fail-closed, diagnosable.** Every check fails closed with a distinct reason (§9).
9. **Safe rollback.** Rollbacks are re-verified, floor-bounded, and never destroy data (§9.5).
10. **Secret hygiene.** The signing private key lives only in CI and is never committed/printed
    (§4.2).
11. **No concurrent passes.** The single-instance lock (§8.2) is Admin/SYSTEM-only, so an
    unprivileged process can neither race a pass nor deny-of-service the schedule by holding it.

### 11.2 Hardening path (NOT alpha)

The following are explicitly deferred to before public launch and tracked as follow-ups; the
alpha ships on the pinned-key + monotonic-freshness floor without them:

- 2-of-N root threshold with ≥1 offline root key, KMS/HSM-backed signing, and rotation of the
  alpha pinned key.
- **Beacon-side transparency verification.** Alpha already records every signed manifest in the
  public `rekor.sigstore.dev` log (§10.8, log-only + fail-soft); beta adds the beacon-side
  inclusion-proof check (fetch the log entry + verify the manifest is included) as a required gate,
  and picks the durable entry type for the Ed25519 key (full-artifact `rekord` or Ed25519ph).
- A full Windows AppContainer sandbox for the fetch/verify worker (alpha: restricted-token /
  low-integrity).

---

## 12. Conformance + implemented scope

This repository implements the **beacon core, the install path, and the scheduling/self-update
surface** (the trust core, the wired fetch → verify → plan pipeline, the privileged enumerate →
install → health-gate → rollback, and the daily scheduler artifact + single-instance lock +
beacon self-update, #504-A/-C/-D/-E/-F):

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
  NEVER advances the state. `Broker::run_once` runs the FULL pass (#504-E): an ACL self-check that
  hardens the state / staging / last-known-good directories and refuses to proceed if the beacon
  binary or those directories are writable by a non-privileged identity (fail-closed); an
  INDEPENDENT re-verification of the whole chain under the broker's OWN pinned root key + persisted
  state (never trusting the worker's report, §8.3); enumeration of the installed components against
  the re-verified manifest (Install/Update/Skip, via the shared `dig-release-resolver` decision
  matrix); a **containment check** that refuses any worker-reported staged path which does not
  canonicalize strictly inside the broker-owned staging directory; a **copy-then-verify** of the
  staged bytes into a broker-private file — the bytes are streamed once into a file the worker
  cannot write while being hashed against the re-verified digest, so the hashed bytes ARE the
  installed bytes (the reverify→install TOCTOU is closed by construction, not by timing); a silent
  per-OS install FROM THAT PRIVATE COPY (`msiexec /qn`, `installer -pkg`, `dpkg -i` — each invoked
  by the installer's ABSOLUTE trusted path, never a bare name resolved through `PATH`; or a
  retry-with-backoff raw-binary rename that DEFERS a locked target to the next pass); a per-component
  health gate; and a re-verified, floor-bounded rollback to a last-known-good snapshot on failure.
  The trust state advances ONLY after every actionable component installs AND passes its health gate,
  and only after the state directory is hardened. The state, last-known-good, and apply directories
  are all created AND explicitly hardened (Admin/SYSTEM-only) up front; staging is a broker-owned,
  non-world-writable directory (NOT `/tmp`); and the broker's file reads on the install path refuse
  to follow symlinks. A manual `Broker::rollback` reads its rollback floor from the PERSISTED trust
  state, never a caller-supplied value, so a below-floor cached build can never be reinstated.
  `Broker::run_once` acquires the single-instance lock (§8.2) BEFORE any of this and reports
  `already_running` rather than an error if a prior pass still holds it. Within a pass, the
  beacon's own tracked component is carved out of the ordinary per-component loop and applied
  LAST, via a platform-specific swap (§8.1) — Unix a plain atomic rename, Windows a two-rename
  dance with automatic rollback of a failed second half — through the IDENTICAL stage → snapshot
  → install → health → rollback skeleton every other component uses; its outcome does NOT gate
  whether the trust state advances for everything else.
- **`dig-updater-broker::scheduler`** — the per-OS scheduler artifact (§8.4): `install`/
  `uninstall`/`status` register, remove, and report a Windows Scheduled Task / systemd timer+
  service pair / launchd LaunchDaemon that invokes `dig-updater run` daily, jittered, with native
  or baked-in boot-recovery. Registering requires the same privilege the artifact runs at.
- **`dig-updater` (CLI, #504-G)** — the operator interface, detailed normatively in §13: `check
  [--now|--dry-run]` (a dry verify pass, or an on-demand full pass), `run` (a full pass — what the
  scheduler artifact invokes), `channel get|set`, `pause [--until <ts>] / resume`, `schedule
  install|uninstall|status`, and `status`, with `--json` and a `--feed-base` transport override
  (the key is never overridable).
- **`dig-updater-feedsign`** — the CI-only feed signer (§10): resolves the latest release per
  component, downloads + digests the per-OS/arch assets, assembles the manifest + delegation, and
  signs them through the trust core (`SignedManifest::sign`/`SignedDelegation::sign`). Its
  `feed.yml` workflow re-signs every 6h, has the freshly-built pinned-key beacon verify the result
  end-to-end, and only then publishes the byte-exact feed to the rolling GitHub `feed` release. It
  is NEVER packaged into a shipped beacon binary.

The following are follow-up tickets under epic #504 and are OUT of scope here:

- **#504-I(b)/-H/-J/-K/-L** the `updates.dig.net` S3+CloudFront feed origin (the signer + nightly
  CI itself, #504-I(a), ships here — see §10), beacon native packages + installer registration,
  the `dig-node` updater RPC proxy (built directly on §13's `status.json` contract), the Updates
  UI, and docs.
- **#534** the full Windows AppContainer worker sandbox (the alpha ships the restricted-token
  floor).

A conformant beacon MUST implement §§1–9 before it installs anything on a user machine.

---

## 13. Operator configuration + status (the CLI contract, #504-G)

This section is the NORMATIVE wire contract for the two JSON files the CLI (§12) reads and
writes, and that follow-up consumers — the `dig-node` updater RPC proxy (#515) and the Updates UI
(#516) — build DIRECTLY on. Both are schema-versioned (a `schema` integer field bumped whenever a
field is added) so a consumer can tell which fields to expect.

### 13.1 `config.json` — the Admin-writable channel + pause state

Persisted at `<state_dir>/config.json` — the SAME Admin/SYSTEM-only directory as the per-channel
`trust-state-<channel>.json` (§6.1, §9.3), so it inherits the identical directory-level lock-down.
Mutating it
is therefore a privileged operation, gated at the CLI layer by the same elevation check the
scheduler artifact's own registration uses (§8.4): on Windows the process token's ACTUAL elevation
state (`GetTokenInformation`/`TokenElevation` — not group membership, and not a `net session` shell-
out, which false-negatives whenever the Server service is stopped), on Unix effective uid `0`.
Reading it is not itself privilege-gated by the beacon — in practice the Admin/SYSTEM-only directory
means only a privileged reader can open it at all.

```jsonc
// config.json
{
  "schema":        1,          // u32, on-disk schema version
  "channel":       "stable",   // "nightly" | "stable" — the update channel this beacon tracks
  "paused":        false,      // bool — auto-updates are suspended
  "paused_until":  null        // u64 unix seconds, or null — an optional pause deadline (a "snooze")
}
```

- `channel` — the update channel this beacon tracks: `"stable"` (tested `vX.Y.Z` releases) or
  `"nightly"` (bleeding-edge `main`-HEAD builds). It selects BOTH which signed feed the beacon
  fetches (`/v1/<channel>`, §10.1) AND which per-channel monotonic trust state it advances (§6.1).
  Both channels are fully servable. The legacy pre-channel token `"alpha"` deserializes to
  `"nightly"` (alpha ≡ nightly, §10.1) and is re-persisted as `"nightly"`, so an old `config.json`
  and an old `channel set alpha` keep working transparently. A conformant CLI accepts `nightly`,
  `stable`, and the `alpha` alias, and refuses any other token with a clear usage error.
- `paused` / `paused_until` — a pass is EFFECTIVELY paused at a given time `now` iff `paused` is
  `true` AND (`paused_until` is absent OR `now < paused_until`). A pause with no `paused_until`
  stays in effect until an explicit `resume`; a pause WITH a `paused_until` lapses on its own once
  `now` reaches it — a caller need not `resume` a timed snooze for it to stop gating passes. This
  is the exact predicate `is_paused_at` in the reference implementation.
- A missing `config.json` is a fresh install: `channel = "stable"` (the safe default — tested
  releases only; nightly is opt-in), `paused = false`, `paused_until = null`. A PRESENT but
  malformed file MUST fail closed (rejected, not silently reset to the fresh-install default) — an
  operator's channel/pause choice is not something a parse error should silently discard.
- **Enforcement point.** `Broker::run_once`/`run_once_with_feed` (a FULL pass — the daily schedule
  OR an on-demand `check --now`) MUST consult the effective pause state, inside the single-instance
  lock (§8.2) and BEFORE the network or the ACL self-check are touched, and MUST return a distinct,
  benign `paused` outcome — structurally identical to `already_running` (§8.2) — rather than acting,
  when paused. A DRY check (`check` / `check --dry-run`) is NOT gated by pause: inspecting what the
  beacon WOULD do must stay available even while paused.

### 13.2 `status.json` — the unprivileged, world-readable mirror

Persisted at a directory DISTINCT from `state_dir` — a sibling with `-status` appended to the
directory name (`/var/lib/dig-updater` → `/var/lib/dig-updater-status`;
`%ProgramData%\DIG\updater` → `%ProgramData%\DIG\updater-status`), so it does NOT inherit
`state_dir`'s Admin/SYSTEM-only ACL (which, on Windows, propagates to everything created inside
it). It MUST be writable ONLY by the broker but READABLE by any local identity — the exact
opposite grant of `state_dir` — so an unprivileged reader (`dig-updater status`, the `dig-node`
updater RPC proxy, the Updates UI) can answer "is the beacon current/paused" without
Administrator/root.

```jsonc
// status.json
{
  "schema":           1,                 // u32, on-disk schema version
  "version":          "0.6.0",            // the beacon binary version that wrote this snapshot
  "channel":          "stable",           // "nightly" | "stable" (the tracked channel)
  "paused":           false,              // the EFFECTIVE value (a lapsed timed pause reports
                                           // false here even before an explicit `resume`)
  "paused_until":     null,
  "last_check":       1730990000,         // u64 unix seconds of the most recent check/run, or null
  "last_check_kind":  "run",              // "dry" | "run", or null if never checked
  "last_outcome":     "applied",          // "verified" | "rejected" | "applied" | "nothing_applied"
  "last_reason":      null,               // a stable code when not a plain success, else null
                                           // (e.g. a worker rejection code, or "already_running" /
                                           // "paused" for a full pass that no-opped)
  "last_detail":      null,               // human-readable detail for the last outcome
  "components": [                         // the last-observed per-component decisions
    {
      "component": "dig-node",
      "action":    "update",              // a dry check reports "would_fetch"; a full pass
                                           // reports its plan action ("install"/"update"/"skip")
      "result":    "installed",           // a dry check reports "staged"; a full pass reports
                                           // "installed"/"skipped"/"deferred"/"rolled_back"
      "detail":    "dig-node now reports dig-node 0.26.0"
    }
  ],
  "next_wake":  1731076400,               // a best-effort ESTIMATE (now + 24h) if the daily
                                           // schedule is registered, else null — not a parse of
                                           // the OS scheduler's own next-run time
  "schedule_opted_out": false,            // ADDITIVE (§8.4): true iff the Admin-only opt-out
                                           // sentinel is present (a deliberate `schedule
                                           // uninstall`), so the self-heal leaves it removed.
                                           // Defaults to false when absent (a pre-#584 mirror)
  "trust_state": {                        // an INFORMATIONAL mirror of the persisted trust marks
    "root_version": 1, "sequence": 42, "generated": 1730990000, "rollback_floor_build": 20
  }
}
```

- **Not authoritative.** `trust_state` here is a read-only COPY (of the TRACKED channel's marks) for
  observability. The ENFORCEMENT copy — the one §7/§9 checks a candidate manifest against — is
  exclusively the Admin-only per-channel `trust-state-<channel>.json` (§6.1). A reader that trusted
  `status.json`'s `trust_state` for a SECURITY decision would be trusting an unauthenticated local
  file; that is acceptable for "should I show a badge", never for "should I install this".
- **Refreshed after every check/run/config change.** A conformant beacon writes a fresh
  `status.json` after `check` (dry or `--now`), `run`, `channel set`, `pause`, and `resume` — a
  config-only mutation refreshes just the `channel`/`paused`/`paused_until` fields, preserving the
  last check/run's `last_check*`/`components` history rather than clobbering it. Writing this file
  is BEST-EFFORT: a failure to persist it MUST NOT fail the check/run/config-change itself — only
  `config.json` + the per-channel `trust-state-<channel>.json` are security-load-bearing;
  `status.json` is informational.
- **An `installed` component's `detail` states VERIFIED reality, never a plan-time prediction.**
  For a full pass, the health gate (§9.5) re-probes the version actually running at the
  component's destination immediately after installing it; the persisted `detail` for a
  `"result": "installed"` entry MUST be built from that re-probed version (e.g. `"dig-node now
  reports dig-node 0.26.0"`), NOT from the pre-install plan's predicted transition (which the
  conformant CLI still shows separately, before the install runs, via `action`). A beacon that
  persists the plan's prediction verbatim as the post-install detail is non-conformant: an
  operator reading `status.json` after the fact would be reading what the pass INTENDED, not what
  it verified actually happened. `last_check`/`last_check_kind` timestamp every snapshot, so a
  reader can always tell a persisted detail is only as current as that timestamp.
- **Always answerable, never an error on absence.** A missing (or, for an unprivileged reader,
  inaccessible) `status.json` MUST be reported as a well-formed "never checked" snapshot — schema
  + version + the default channel/pause + every other field `null`/empty — NOT an error. Only a
  file that IS readable but fails to parse is a genuine error.
- **`channel get` reads this file**, not `config.json` — so it, like `status`, never requires
  elevation; `channel set`/`pause`/`resume` write `config.json` (§13.1) and then immediately
  refresh this mirror so a subsequent unprivileged read reflects the change without waiting for the
  next check/run.

### 13.3 CLI surface (normative summary)

| Command | Reads | Writes | Elevation | Notes |
|---|---|---|---|---|
| `check` / `check --dry-run` | `config.json` (channel), `trust-state-<channel>.json` (freshness compare) | `status.json` (best-effort) | No | Never installs, never advances trust state, never pause-gated. Inspects the tracked channel's feed; state dir honors `$DIG_UPDATER_STATE_DIR` (below); the `status.json` refresh is fail-soft. |
| `check --now` | — | everything a full pass writes | Whatever `run` requires | Identical to `run` — an on-demand trigger of the SAME `Broker::run_once_with_feed`. |
| `run` | `config.json`, `trust-state-<channel>.json` | `trust-state-<channel>.json`, `status.json`, installed binaries | Whatever the per-OS install path requires | Pause-gated (§13.1); fetches the tracked channel's feed (§10.1) and advances THAT channel's state; this is what the scheduler artifact invokes. |
| `channel get` | `status.json` | — | No | |
| `channel set <nightly\|stable>` | `config.json` | `config.json`, `status.json`, each browser's `ExtensionInstallForcelist` (via `dig-installer`, on a CHANGE) | Yes | Accepts `nightly`, `stable`, and the `alpha` alias (→ nightly); rejects any other token (§13.1). On a channel CHANGE it drives the staged extension reinstall (§13.4) — best-effort, never rolls back the channel. |
| `pause [--until <ts>]` | `config.json` | `config.json`, `status.json` | Yes | |
| `resume` | `config.json` | `config.json`, `status.json` | Yes | |
| `status` | `status.json` | — | No | Always answerable (§13.2). |
| `schedule install\|uninstall\|status\|ensure` | OS scheduler state, opt-out sentinel (`state_dir`) | OS scheduler state, opt-out sentinel | `install`/`uninstall`/`ensure` (re-register branch): yes | §8.4. `install` clears the opt-out sentinel; `uninstall` writes it; `ensure` is the LIGHTWEIGHT self-heal an always-on driver kicks (no feed/install), honoring the sentinel. |

Every command MUST offer both a human-readable line and a `--json` machine-readable object (§6.2).
The feed base is overridable per `--feed-base <url>`/`$DIG_UPDATER_FEED_BASE` on `check` and `run`
alike (untrusted transport, §1); the pinned root key has no such override.

**An overridden feed on a real pass installs but MUST NOT advance the tracked channel's trust
state.** The feed override selects the transport (which base the manifest is fetched from), while the
tracked channel — the source of truth for WHICH per-channel state file (§6.1) a pass advances — comes
from `config.json`. A `run --feed-base <other-channel's feed>` therefore fetches marks that may be on
a DIFFERENT channel's build scale (nightly `YYYYMMDD` vs stable packed-semver). Folding those into
the tracked channel's monotonic state would numerically corrupt its anti-rollback floor — e.g. a
nightly-scale mark advancing `trust-state-stable.json` bricks future stable updates below the false
floor (an operator-triggered self-DoS). So on a full pass where the feed was overridden, the beacon
MUST install the verified binaries as normal but MUST NOT advance (and thus MUST NOT persist) the
tracked channel's trust state. A normal (non-overridden) pass advances state as usual (§9 step 7).

**Dry-check state directory (`$DIG_UPDATER_STATE_DIR`).** A DRY `check` MUST run without write access
to the Admin/SYSTEM-only default state directory. Resolution order:

1. `$DIG_UPDATER_STATE_DIR`, when set to a non-empty path — an explicit choice always wins (e.g. the
   signed-feed end-to-end keystone, #540).
2. Otherwise, the hardened OS default — but ONLY when this process can actually use it (elevated
   AND the directory is genuinely writable). An "elevated" console MAY still be denied by an unusual
   ACL, so elevation alone is not sufficient; a conformant beacon PROBES writability rather than
   trusting elevation as a proxy for it.
3. Otherwise, a per-user writable location (`%LOCALAPPDATA%\DIG\updater` on Windows;
   `$XDG_CACHE_HOME/dig-updater`, falling back to `$HOME/.cache/dig-updater`, then the OS temp dir,
   on Unix).

This override/fallback applies ONLY to the dry check — the full pass / install path (`run`,
`check --now`) ALWAYS uses the hardened default and is never relocatable, so the anti-rollback trust
state can never be pointed at a directory an unprivileged process can roll back (§6, §9.3).

Because a dry verify must download and digest-verify each artifact into a staging directory, an
UNWRITABLE state dir makes the worker unable to stage. This is why step 3 exists (#582): without it,
an everyday unprivileged `dig-updater check` would hit the pre-existing Admin/SYSTEM-owned default,
and — because `CreateDirectory`/`mkdir` reports "already exists" for a directory that is genuinely
already there just as readily as for a real collision, while the metadata read `create_dir_all` would
otherwise use to tell the two apart is ITSELF access-denied against that directory — the raw, cryptic
OS error code would propagate verbatim instead of a clean relocation. A conformant worker also
tolerates that "already exists" outcome explicitly rather than trusting the metadata-read recovery,
and proves usability with a real write, so a directory that exists but is genuinely unwritable is
reported as an honest "not writable" detail rather than a bare OS error code. If even the resolved
staging location is unusable (e.g. an explicit `$DIG_UPDATER_STATE_DIR` pointed somewhere unwritable),
the dry check still reports a `staging_io_error` rejection — a conformant CLI's HUMAN-readable
(non-JSON) rendering MUST accompany that specific rejection with an actionable remedy (run elevated;
set `$DIG_UPDATER_STATE_DIR` to a writable directory; or use `status`, which never stages anything) —
the `--json` rendering stays exactly the structured worker report (§9), unchanged.

**Fail-soft status refresh.** The verify VERDICT a `check` reports (`.status`) is authoritative and
independent of whether `status.json` (§13.2) could be written. A failure to refresh the status mirror
(a permission the unprivileged runner lacks) MUST warn and continue — it MUST NOT change the exit code
or suppress the `--json` verdict.

### 13.4 Force-installed extension channel follow — a channel switch is a staged REINSTALL

The universal installer force-installs the DIG Chrome extension into every detected Chromium browser
via each browser's `ExtensionInstallForcelist` managed policy, keyed by the ONE extension id
`mlibddmbhlgogepnjdienclhnkfpkfah`, with only the policy `update_url` differing per channel. The
beacon is the single channel authority (§13.1): when `channel set` CHANGES the tracked channel, the
force-installed extension MUST FOLLOW so every browser ends up pulling from the newly-tracked
channel's `update_url`.

- **A channel switch is a REINSTALL, not a version bump.** The nightly extension version scheme
  `X.Y.Z.N` (`N` = UTC days since 2020-01-01) numerically OUTRANKS the stable `X.Y.Z`, so a browser on
  a nightly build is at a HIGHER version than any stable build and Chromium will NOT auto-downgrade it.
  Rewriting the forcelist entry's `update_url` in place therefore CANNOT cross a nightly→stable switch —
  it leaves the browser stranded on the old, higher-versioned build.
- **The beacon owns only the STAGING; the policy write is single-sourced in `dig-installer`.** On a
  channel change the beacon drives, in strict order, the two elevation-gated `dig-installer` forcelist
  verbs — never re-implementing the per-browser policy write:
  1. **REMOVE** — `dig-installer --uninstall-ext-forcelist` strips the DIG forcelist entry from every
     detected browser, so each browser uninstalls the extension on its next managed-policy refresh.
  2. **AWAIT** — nudge the OS to re-evaluate policy (Windows `gpupdate /target:computer /force`;
     file-based managed policy on Unix is re-read by each browser on its own schedule) and wait a
     bounded interval so the browsers OBSERVE the removal and uninstall the old build BEFORE the re-add.
     Without this gap the re-add races the removal and the downgrade never crosses.
  3. **RE-ADD** — `dig-installer --set-ext-forcelist-channel <channel>` re-adds the entry pointing at
     the target channel's `update_url`. With no extension present this is a FRESH install of the target
     channel, not a blocked downgrade.
- **No-op when unchanged.** A `channel set` that does not change the tracked channel (a re-set to the
  same value, or an unreadable prior channel) performs NO policy writes — the browsers' forcelist is
  never churned needlessly.
- **Best-effort, never fails the `channel set`.** The beacon config is the channel authority and is
  persisted first; a follow failure (e.g. `dig-installer` not present, or a browser policy write error)
  is reported to the operator and left to the deferred daily self-heal reconcile (#602 Piece B) to
  re-assert — it MUST NOT roll back the persisted channel.
- **Trust state is untouched.** This is additive to §6/§6.1: the per-channel monotonic trust state and
  anti-rollback are unchanged. Crossing channels remains an authorized operator action (§6.1), of which
  this forcelist reinstall is the extension-side execution.

---

## 14. Release pipeline — nightly cron + manual dispatch (this repo's OWN releases)

This section governs how **the beacon itself** is built and released — distinct from §10 (the signed
*feed* the beacon reads to update OTHER components). This repo is the ecosystem's **reference
nightlies implementation** for a Rust-binary stack; the shape below is the template other releasing
submodules copy.

Releases follow the **release-branch model** (epic #1049): the **nightly** channel is cut from
`main` HEAD (a nightly cron), and the **stable** channel is cut from deliberate `release/X.Y`
branches — NOT from `main`, and NOT on merge. There are two independent version streams:

- **`main`** — the leading DEV trunk. Its `[workspace.package].version` is always AHEAD of the newest
  release line (`X.(Y+1).0` and up); per-PR bumps accumulate toward the NEXT stable line. Nightlies
  cut here.
- **`release/X.Y`** — a curated STABLE line, branched off `main` at a chosen good commit by
  `cut-release-branch.yml` (§14.7). Its version starts at the deliberate `X.Y.0` set in the
  release-prep commit and walks the patch on stabilization/hotfix (`X.Y.1`, `X.Y.2`, …). Stable
  `vX.Y.Z` tags are cut FROM this branch.

The stable version is DELIBERATE at branch-cut (release-prep), not the accidental sum of per-PR
bumps on `main`.

Two channels ship from one orchestrator (`.github/workflows/nightly-release.yml`):

### 14.1 Trigger

The orchestrator triggers ONLY on:

- `schedule: cron '0 0 * * *'` — **midnight UTC** (GitHub Actions cron is always UTC; a top-of-hour
  cron MAY be delayed under load — acceptable, since the nightly channel is idempotent), and
- `workflow_dispatch` with two inputs: `channel` (`both` | `stable` | `nightly`, default `both`) and
  `force` (boolean, default `false`).

It MUST NOT trigger on `push`. The schedule runs on `main` and cuts ONLY the nightly channel — the
STABLE `vX.Y.Z` tag is cut solely by a manual `workflow_dispatch` (`channel: stable` or `both`)
selected against a `release/X.Y` branch, never by the cron. A fleet-reaching version tag is always a
deliberate human act (CLAUDE.md §3.6).

**Each channel's push-capable job is bound to its curated ref (defense-in-depth).** Every job that
pushes a tag or a changelog commit with `RELEASE_TOKEN` MUST bind its `if:` to the ref its channel is
cut from — mirroring `feed.yml`'s H1 signing guard:

- the `stable` job binds to `startsWith(github.ref, 'refs/heads/release/')` and pushes the changelog
  commit to `github.ref_name` (the dispatched `release/X.Y`), so a dispatch selected against `main`
  (or any non-release ref) is an inert no-op — the changelog + tag land ONLY on a curated release
  line;
- the `nightly-meta` job (the nightly tag/publish gate) stays bound to
  `github.ref == 'refs/heads/main'`, so nightlies are always cut from reviewed `main` HEAD.

`workflow_dispatch` runs the workflow FROM the selected ref, so without these guards a dispatch could
checkout an arbitrary branch and push ITS commits (past protection, since the release changelog
commit rides `enforce_admins=false`/the release ruleset bypass). The cron + production dispatches
always run on the right ref, so the guards cost nothing legitimate. The true boundary remains
who-can-dispatch (write access) + a scoped `RELEASE_TOKEN`; the ref guards are accident/abuse
protection on top.

**60-day auto-disable caveat.** GitHub auto-disables a `schedule:` trigger after 60 days with no
repo activity on a public repo, with no auto-re-enable — and since this cron is the ONLY automatic
release trigger (nightlies), a quiet repo can silently stop cutting nightlies with no error surfaced
anywhere (stable releases are unaffected — they are manual-dispatch-only). Detect
it with `gh api repos/<owner>/<repo>/actions/workflows/nightly-release.yml --jq .state` (a value of
`disabled_inactivity` means it was auto-disabled) and recover with `gh workflow enable
nightly-release.yml` (see `runbooks/release.md`). Any repo activity resets the 60-day counter.

### 14.2 Stable channel

Cut from a `release/X.Y` branch (dispatch selected against that branch, `channel: stable|both`).
Cuts a semver `vX.Y.Z` **stable** release when — and only when — the version in the branch's root
`Cargo.toml` (`[workspace.package].version`) has advanced beyond the newest existing `vX.Y.Z` tag.
The **skip-if-already-tagged** check IS the version-changed check: an unchanged version means the tag
already exists, so the run is a no-op. Cutting a release means: `git-cliff` regenerates
`CHANGELOG.md` from the Conventional-Commit history, commits it to the RELEASE BRANCH
(`github.ref_name`) as `chore(release): vX.Y.Z`, tags THAT commit `vX.Y.Z` (so the changelog is
inside the tag), and pushes commit + tag with `RELEASE_TOKEN`. The pushed `v*` tag fires
`release.yml`, which builds every OS/arch and publishes a GitHub Release with `prerelease: false` +
`make_latest: true` — the stable release is the ONLY one that moves `latest`.

**Branch-agnostic to consumers (beacon coherence, load-bearing).** The tag's origin branch is
invisible downstream: the feed resolves the stable channel via `releases/latest` (§10.3), and
`release.yml` always publishes with `make_latest: true`, so a `vX.Y.Z` cut from `release/X.Y` is
resolved and served identically to one cut from anywhere else — **no feed logic changes for the
release-branch model** (`feed.yml` is untouched). INVARIANT: the stable cut MUST keep
`make_latest: true` on the published release, or the `releases/latest` resolution would pick the
wrong (or a stale) release.

`force: true` on a manual dispatch bypasses the skip-if-tagged guard and re-cuts the current version
(moving the existing tag onto a fresh changelog commit — the release branch is never force-pushed).
This is the manual "re-release this version" escape hatch (e.g. after a failed build).

**Force is guarded against mutating a published release (supply-chain invariant).** A force re-cut
MUST be refused — with a non-zero exit and a clear error — when BOTH: (a) a PUBLISHED (non-draft)
GitHub Release already exists at the version's `vX.Y.Z` tag, AND (b) that tag currently points at a
commit DIFFERENT from the commit this run would build. Moving a published release's tag to
different code would silently replace its shipped binaries with unreviewed code under the same
version number. Force MAY proceed when either condition is false: a same-commit re-cut (the tag
already points at the commit being built — a legitimate "the build failed, re-fire `release.yml`"
retry) or a tag with no published release yet (repairing a bare/failed tag). A version that
genuinely needs new code released MUST bump `Cargo.toml`, not force-move an existing tag.

The "is a published release present?" lookup MUST FAIL CLOSED: a transient GitHub API error
(network / 5xx) MUST NOT be interpreted as "no published release" and thus permission to move the
tag. Only a DEFINITIVE "release not found" answer allows the bare/failed-tag repair path; any other
lookup failure — after a bounded retry — is treated as "assume published", so the guard refuses the
force-move.

### 14.3 Nightly channel

Every night (and on demand) builds `main` HEAD for every OS/arch and publishes a GitHub
**pre-release** — so a fresh nightly always exists regardless of a version bump. It:

- **Synthesizes the version at build time** (nothing is committed): `X.Y.Z-nightly.YYYYMMDD.<shortsha>`
  from the current `Cargo.toml` version + UTC date + `git rev-parse --short HEAD`. As a semver
  prerelease it sorts BELOW the plain `X.Y.Z`, so a nightly never outranks the stable release.
- Publishes under a **dated tag `nightly-YYYYMMDD`** AND force-moves a **rolling `nightly` tag** to
  the same build, with `prerelease: true` and **never** `latest` (title `Nightly YYYY-MM-DD
  (<shortsha>)`). Both the dated and the rolling pre-release carry this run's binaries. Idempotent: a
  same-day re-run refreshes today's dated release + the rolling pointer rather than erroring.
- **Retention:** keeps the newest **14** dated nightlies plus the rolling `nightly`, pruning older
  dated pre-releases AND their `nightly-YYYYMMDD` tags together (`gh release delete --cleanup-tag`).
  `v*` stable tags/releases and the rolling `nightly` are NEVER pruned.

Neither `nightly-*` nor `nightly` matches `release.yml`'s `v*` trigger, so the nightly channel never
fires the stable build; the nightly job builds and publishes directly.

### 14.4 Reusable build

The cross-OS binary build lives once in `.github/workflows/build-binaries.yml` (`on: workflow_call`,
inputs `version` + `ref`). Both `release.yml` (stable) and the nightly channel call it, so the two
paths can never diverge on HOW a binary is produced. It builds both beacon binaries — `dig-updater`
and its sibling `dig-updater-worker` (§8.3) — for `windows-x64`, `linux-x64`, `macos-arm64`, and
`macos-x64`, stamping the caller's `version` into each artifact filename.

### 14.5 RELEASE_TOKEN posture (both channels)

Releasing uses the `RELEASE_TOKEN` org PAT, not the default `GITHUB_TOKEN`: a tag pushed by
`GITHUB_TOKEN` does not trigger downstream workflows (GitHub anti-recursion) and `GITHUB_TOKEN` cannot
push a changelog commit past branch protection. If `RELEASE_TOKEN` is absent, EVERY channel NO-OPS
with a clear `::warning::` — never a half-release. A `concurrency: nightly-release` group
(cancel-in-progress `false`) serializes runs so an overlapping cron + dispatch cannot race on
tags/releases.

### 14.6 Workflow inventory

| Workflow | Trigger | Role |
|---|---|---|
| `cut-release-branch.yml` | `workflow_dispatch` (on `main`) | Opens a stable line: branches `release/X.Y` off main + the `chore(release): prep vX.Y.0` commit + a "next dev cycle" PR bumping main to `X.(Y+1).0`. (§14.7) |
| `nightly-release.yml` | `schedule` (midnight UTC) + `workflow_dispatch` | The orchestrator: stable channel (from `release/X.Y`, changelog + tag) and nightly channel (from `main` HEAD, build + dated/rolling pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the STABLE GitHub Release for a `vX.Y.Z` tag (`make_latest: true`, branch-agnostic). |
| `build-binaries.yml` | `workflow_call` | The reusable cross-OS build both channels invoke. |
| `feed.yml` | `schedule` (every 6h) + dispatch | UNRELATED to this repo's release — signs the update FEED the beacon reads for OTHER components (§10). |

### 14.7 Release-branch cut + `release/*` protection

Opening a stable line is a deliberate act performed by `cut-release-branch.yml` (`workflow_dispatch`
on `main`, inputs `version` = `X.Y.0` + `next_dev_version` = `X.(Y+1).0`). It MUST:

- be bound to `github.ref == 'refs/heads/main'` (cut a line off reviewed `main` only);
- REFUSE (non-zero exit, clear error) when the `release/X.Y` branch OR the `vX.Y.0` tag already
  exists — no re-opening a line, no clobbering a shipped version;
- branch `release/X.Y` off `main` HEAD, set `[workspace.package].version` = `X.Y.0`, sync
  `Cargo.lock` with `cargo update --workspace`, and push the `chore(release): prep vX.Y.0` commit to
  the new branch with `RELEASE_TOKEN`;
- open a NORMAL PR (never a direct push) bumping `main` to `X.(Y+1).0`, so main's leading dev version
  moves past the line and per-PR bumps accumulate toward the NEXT line;
- no-op with a `::warning::` when `RELEASE_TOKEN` is absent (never a half-cut line).

`release/*` branches are protected by a GitHub **ruleset** (`refs/heads/release/*`) carrying the SAME
required-check set as `main` (fmt, clippy ×OS, test ×OS, coverage, build ×OS, scheduler ×OS,
version-increment, commitlint) plus `required_conversation_resolution`, `strict` (up-to-date), and
`required_linear_history`; the repo is squash-merge-only fleet-wide. The `RELEASE_TOKEN` identity is
a scoped bypass actor so the `stable` job's changelog commit + the release-prep commit can land on
the protected line (the same posture `main` uses via `enforce_admins=false`). The PR gates
(`ci.yml`, `commitlint.yml`, `ensure-version-increment.yml`) trigger on `release/**` too, and the
version-increment gate compares against the PR's actual base (`github.base_ref`) so a hotfix PR must
increment vs the release line it targets.
