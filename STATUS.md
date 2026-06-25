# Status: stable

**Stage:** stable
**Maintenance horizon:** actively maintained through 2026-12-31, status reviewed quarterly
**Maintainer wanted:** no

## Stage rationale

`@opena2a/aicomply 1.0.0` (released 2026-05-28) closes the three v0.x README gaps - adversarial-mutation handling (NFKC + zero-width + targeted whitespace + bounded Base64/URL decode), a measured-accuracy baseline (3200 synthetic samples, per-class P/R/F1 in CI), and NanoMind-Guard IPC wiring (real socket protocol, mock-socket testable). Semver applies from 1.0.0; breaking changes require a major bump and migration note.

The semantic Guard layer is wired and the NanoMind model has shipped (`nanomind-security-classifier` tme-v0.5.0, served by `@nanomind/daemon` over HTTP on `127.0.0.1:47200`). However, the current model over-flags benign text (measured 2026-06-25: roughly 70% benign false positives at the 0.8 block threshold, many at near-1.0 confidence), so the Guard remains a **preview** and is not recommended for production gating. The regex layer is the stable production surface and carries the measured accuracy in [SECURITY.md](./SECURITY.md); `comply()` runs regex-only whenever no daemon is reachable, which is the default. Promoting the Guard out of preview is gated on a model recalibration that fixes the benign false-positive rate (scoped in `todo/`).

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
| 2026-06-18 | stable | v2.1.0: adds an `aicomply` CLI (`scan` over files/stdin, `--json`/`--quiet`, masked output, CI exit codes) as a zero-integration try-path. Library API unchanged. npm keywords added for discovery. |
| 2026-06-25 | stable | Guard reclassified as **preview**: the shipped model tme-v0.5.0 over-flags benign text (~70% FP at 0.8). Regex remains the stable production surface. README/CLI corrected (removed a no-longer-reproducing validation block), Python daemon-enable hint fixed (daemon is npm-only, not PyPI). Recalibration scoped in `todo/`. |
