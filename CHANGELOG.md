# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.13.0] - 2026-07-16

### Bug Fixes
- **broker:** Apply full binary set + stop service before replace (#666) (#22)

## [0.12.0] - 2026-07-16

### Features
- **schedule:** Add `schedule ensure` verb + Admin-only opt-out sentinel (#584) (#21)

## [0.11.0] - 2026-07-16

### Features
- **beacon:** Force-installed ext channel follows the tracked channel (#613) (#20)

## [0.10.1] - 2026-07-16

### Bug Fixes
- **beacon:** Resilient replace-a-running-binary path (#558) (#19)

## [0.10.0] - 2026-07-15

### Features
- **beacon:** Track nightly|stable channel with per-channel anti-rollback state + CLI (#18)

## [0.9.0] - 2026-07-14

### Features
- **feed:** Per-channel signed feeds (stable + nightly) + feedsign nightly selection (#603) (#17)

### CI
- **release:** Nightlies polish (#16)

## [0.8.2] - 2026-07-14

### CI
- **release:** Nightly-cron + manual-dispatch release system; nightly pre-release channel (#590) (#15)

## [0.8.1] - 2026-07-14

### Bug Fixes
- **beacon:** Graceful unprivileged check (no bare os-183) + verified-reality status detail (#582) (#14)

## [0.8.0] - 2026-07-14

### Bug Fixes
- **beacon:** Self-heal schedule + native-package feed + real install root (#546, #580, #581) (#13)

## [0.7.2] - 2026-07-14

### Bug Fixes
- **broker:** Suppress child-process console windows (CREATE_NO_WINDOW) (#577) (#12)

## [0.7.1] - 2026-07-14

### Bug Fixes
- **feed:** Decouple GH-release fallback publish from the S3-primary smoke (availability) (#11)

## [0.7.0] - 2026-07-14

### Features
- S3-primary feed publish to updates.dig.net + Rekor transparency (U4, #535/#533) (#10)

## [0.6.2] - 2026-07-14

### Bug Fixes
- **check:** Run the dry verify against a writable state dir so a valid feed always verifies (#9)

## [0.6.1] - 2026-07-14

### Bug Fixes
- **trust:** Rotate alpha root key to environment-scoped custody (#540) (#8)

## [0.6.0] - 2026-07-14

### Features
- Dig-updater CLI — check --now, channel, pause, status --json (#512) (#7)

## [0.5.1] - 2026-07-13

### Bug Fixes
- **release:** Run the Windows binary build under bash (v0.5.1, #504) (#6)

## [0.5.0] - 2026-07-13

### Features
- Scheduler + single-instance lock + boot-recovery + beacon self-update (#511) (#5)

## [0.4.0] - 2026-07-13

### Features
- Broker install path — enumerate, ACL harden, silent install, health-gate, rollback (#504-E) (#4)

## [0.3.0] - 2026-07-13

### Features
- Nightly signed feed — feed-signer crate + CI (#513-I) (#3)

## [0.2.0] - 2026-07-13

### Features
- Beacon core — fetch, verify, plan (fail-closed) (#509) (#2)

## [0.1.0] - 2026-07-13

### Features
- Dig-updater trust contract + workspace scaffold + CI gates (#504-A, #504-C) (#1)


