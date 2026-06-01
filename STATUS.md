# Status: stable

**Stage:** stable
**Maintenance horizon:** actively maintained through 2026-12-31, status reviewed quarterly
**Maintainer wanted:** no

## Stage rationale

`@opena2a/aicomply 1.0.0` (released 2026-05-28) closes the three v0.x README gaps - adversarial-mutation handling (NFKC + zero-width + targeted whitespace + bounded Base64/URL decode), a measured-accuracy baseline (3200 synthetic samples, per-class P/R/F1 in CI), and NanoMind-Guard IPC wiring (real socket protocol, mock-socket testable). Semver applies from 1.0.0; breaking changes require a major bump and migration note.

The semantic Guard layer is wired but its model binary depends on NanoMind Phase 2b training which is external to this repo. Until that ships, `comply()` falls back to regex-only, which carries the measured accuracy in [SECURITY.md](./SECURITY.md). When the Guard binary publishes, `isAvailable()` will return `true` against `/tmp/nanomind-guard.sock` and dual-layer classification activates with no consumer code change.

## Stage definitions

- **stable**: production-ready, semver honored, breaking changes documented, security patches triaged within 24 hours.
- **beta**: feature-complete or near, breaking changes possible with notice, actively developed.
- **experimental**: early stage, breaking changes expected, use at your own risk.
- **reference-only**: spec or reference implementation, not intended for production use.

## Status changes

| Date | Stage | Reason |
|---|---|---|
| 2026-05-24 | beta   | initial STATUS.md. v0.1.0 first release; v2 readiness gate open. |
| 2026-05-28 | stable | v1.0.0 ships: adversarial normalization, measured accuracy baseline, Guard IPC wired. Semver applies. |
