# Security Policy

## Reporting a vulnerability

Email **info@opena2a.org** or open a private security advisory on the
[`aicomply` repo](https://github.com/opena2a-org/aicomply/security/advisories/new).
Do not file public GitHub issues for security reports.

Include:
- A description of the issue and its impact
- Steps to reproduce (minimal code example preferred)
- The version of `@opena2a/aicomply` affected (`npm view @opena2a/aicomply version`)
- Any proof-of-concept artifact (small, scrubbed of real PII)

We acknowledge reports within 3 business days and aim to ship a fix within
30 days of confirmation for HIGH-severity issues. For coordinated disclosure,
we will agree on a public advisory date with the reporter.

## Supported versions

Starting at `1.0.0`, `@opena2a/aicomply` follows [semantic versioning](https://semver.org/):

- **Patch** (`1.0.x`): security and bug fixes; no API surface changes.
- **Minor** (`1.x.0`): additive features; existing exports remain backwards-compatible.
- **Major** (`x.0.0`): breaking changes to `comply()` / `ClassificationSession` /
  result shape, accompanied by a migration note in the release.

Security fixes target the **latest two minor lines** for 90 days after a new
minor ships, and the latest major line indefinitely. Pre-1.0 lines (`0.x`)
are no longer supported as of `1.0.0`. Pin exact versions in production
(`"@opena2a/aicomply": "1.0.0"`, no caret) and consume fixes by bumping.

Breaking changes are announced via the `0.x` -> `1.0.0` transition note in
the release and re-stated in CHANGELOG entries when subsequent majors arrive.

## What this package is and isn't

`@opena2a/aicomply` is a **content classifier**. It inspects strings (agent
inputs, tool outputs) and returns a verdict (`CLEAN` / `VIOLATION` / `DENY`)
plus structured violation records. It is one input to your compliance
posture - not a complete control.

### In threat model scope
- Correctness of the dual-layer merge (`CLEAN` only when both layers are clean;
  `DENY` overrides everything; supply-chain hard block always DENY)
- Signature verification of Guard classifier results (Ed25519 + ML-DSA-44 hybrid,
  parse-to-deny on invalid signatures - contract CR-001)
- Session vault key isolation (AES-256-GCM, keys never persisted to disk)
- Registry intelligence cache integrity (cache-miss treated as unknown, not clean -
  contract AC-002)

### Adversarial-mutation handling (covered in 1.0)

A pre-regex normalization layer canonicalizes input before patterns run.
Covered mutation classes:

- **Unicode homoglyphs** via NFKC compatibility composition (fullwidth
  digits `１２３` → `123`, math-alphanumerics, ligatures `ﬃ` → `ffi`).
- **Zero-width / bidi control injection** (U+200B–200F, U+202A–202E,
  U+2060, U+2066–2069, U+FEFF) - stripped from the canonical stream.
- **Intra-token whitespace injection** (`1 2 3 - 4 5 - 6 7 8 9`) - scanned
  as a compact view in addition to the canonical stream. Whitespace is
  only collapsed between digit/separator characters so prose word
  boundaries are preserved.
- **Base64 / URL-encoded wrapping** of sensitive payloads - extracted as
  decoded views (bounded depth 2, length ≥ 24 chars, ASCII-printable
  round-trip gate).

Findings carry a `view` field (`normalized` / `compact` / `decoded-base64`
/ `decoded-url`) and original-content anchoring so consumers can audit
which canonicalization surfaced each match.

### Measured accuracy (1.0 baseline)

Per-class precision / recall / F1 are measured against the synthetic
corpus at `bench/corpus/*.jsonl` (200 positives + 200 hard-negatives per
class, 3200 records total). The corpus deliberately includes adversarial
variants so the baseline reflects normalization coverage:

| Class      | Precision | Recall | F1   |
|------------|-----------|--------|------|
| SSN        | 1.000     | 1.000  | 1.00 |
| PAN        | 1.000     | 1.000  | 1.00 |
| IBAN       | 0.990     | 1.000  | 0.995 |
| NPI        | 1.000     | 1.000  | 1.00 |
| CUI        | 1.000     | 1.000  | 1.00 |
| CREDENTIAL | 1.000     | 1.000  | 1.00 |
| PASSPORT   | 1.000     | 1.000  | 1.00 |
| MRN        | 1.000     | 1.000  | 1.00 |

These are baseline numbers on the synthetic corpus, not field-rate
guarantees. Real-world inputs may differ; treat the baseline as a CI
regression gate rather than an SLA. The corpus and harness are public
(`bench/`) so consumers can regenerate against their own data.

### Semantic Guard layer (added in 2.0)

When `@nanomind/daemon` is reachable on the configured URL, aicomply
runs every input through the daemon's `/v1/infer` endpoint in addition
to the regex layer. The daemon hosts a Mamba TME classifier
(`nanomind-security-classifier` v0.5.0) and returns a canonical
`attackClass` plus confidence. aicomply maps any `attackClass !== '' &&
confidence > 0.8` to a Guard violation per AIM FGA Step 5.

New attack classes detectable when the Guard is armed:
`prompt_injection`, `exfiltration_pattern`, `tool_misuse`,
`data_extraction`. These are detection categories the regex layer
cannot see by design - they are semantic intents, not syntactic
patterns.

### Trust boundary: the daemon process

The daemon runs as a separate process and its responses are an attack
surface in the same sense Guard's ARP-signed responses are. The
adapter validates every field on the daemon response (canonical
`attackClass` enum, confidence in [0,1], non-empty modelVersion,
non-negative latencyMs); any schema violation falls back to
regex-only.

**Mitigations baked into the adapter:**

- The daemon's `evidence` and `remediation` strings are NEVER copied
  into `Violation.value`. Those fields may reflect attacker-influenced
  bytes (ANSI escapes, log-injection newlines) and could poison
  downstream operator dashboards. Only the canonical attack-class
  enum becomes the violation type. Regression test covers ANSI escape
  + shell-payload bytes in those fields.
- The adapter never writes daemon output to stdout/stderr.
- Per-call timeout (default 5000ms) bounds the impact of a slow
  daemon.

**Operator responsibilities (NOT enforced by the library):**

- Run the daemon as a separate user.
- Socket / port permissions: `chmod 0600` on the IPC path; bind HTTP
  to `127.0.0.1` only (the daemon already enforces this).
- Pin the daemon version (`@nanomind/daemon@0.3.0`) — a daemon at a
  different wire-format version will fail validation and fall back
  silently. There is no automatic upgrade signaling today.
- Health-check the daemon out-of-band (e.g. probe `/health`) if Guard
  presence is a compliance requirement; `comply()` will not surface
  daemon-down conditions as errors.

### Still out of threat model scope (2.0)

- **Steganography, language translation, adversarial LLM rephrasing.**
  These require the Guard semantic layer; the regex tier is a syntactic
  detector by design.
- **Cyrillic / Greek look-alikes that are not NFKC-equivalent** (e.g.
  Cyrillic small letter а at U+0430 vs Latin a at U+0061). NFKC does not
  fold these because they are separate semantic letters. Document-level
  defense requires the Guard layer.
- **Soft hyphen (U+00AD) and combining marks (U+0300–U+036F).** Not
  stripped from the normalized stream - deferred to v1.1. An attacker
  can hide PII by injecting soft hyphens between digits.
- **HTML entities, hex-encoded payloads, base32, ROT13.** Only Base64
  and URL (percent) encoding are decoded in 1.0. Other encodings pass
  through unchanged.
- **Adjacent-prefix Base64 alignment evasion.** v1.0 attempts up to 3
  leading-character trims to align candidate Base64 runs. A more
  sophisticated wrapper (e.g. `wrapper://abcd//<base64>` where `abcd`
  is itself a base64-charset run) may still escape detection.
- **All-letter alphanumeric MRN identifiers.** The MRN regex requires
  at least one digit in the captured group. Some clinical systems
  (e.g. UK NHS ULN-style learner numbers used as MRN aliases, certain
  legacy Epic department-prefix MRNs) use all-letter identifiers and
  will NOT be detected. Tradeoff documented: precision on prose
  ("MRN system was updated") prioritized over recall on all-letter
  MRNs. Customers in those domains should supply a custom regex or
  scan with a dedicated pattern.
- **Guard fallback observability.** When the nanomind-daemon adapter
  cannot reach `http://127.0.0.1:47200/v1/infer` (connection refused,
  timeout, non-2xx, malformed response), it silently falls back to
  regex-only. The library does not log these conditions (no library
  should write to stderr without consent); the Guard is treated as a
  defense-in-depth layer whose presence is
  optional. Operators who need observability should health-check the
  socket out-of-band before relying on Guard for compliance gates.
- **Side-channel resistance.** Timing of `comply()` may leak coarse
  information about input length and pattern density. Not designed
  against timing attacks.
- **Registry availability.** L2 logic (fleet anomaly threshold,
  supply-chain hard block) is best-effort and depends on the configured
  Registry endpoint. Cache miss does not fail closed; it surfaces signals
  so callers decide.
- **NanoMind-Guard semantic classifier.** The IPC client is wired and
  testable as of 1.0, but the real Guard binary depends on NanoMind
  Phase 2b training (external to this repo). Until that ships, `comply()`
  falls back to regex-only - which is sufficient for the syntactic
  classes above but does not provide semantic context detection.

### Out of repo scope
- Vulnerabilities in the Registry server backend (`opena2a-registry` repo).
- Vulnerabilities in agent runtimes that *consume* this package (sandboxing,
  process isolation, secret storage).
- Vulnerabilities in `@noble/post-quantum` (report upstream to
  https://github.com/paulmillr/noble-post-quantum/security).

## Cryptography

- **Hybrid signatures.** ARP signature verification uses Ed25519 + ML-DSA-44,
  implemented via [`@noble/post-quantum`](https://www.npmjs.com/package/@noble/post-quantum).
  This is **not** a FIPS-validated implementation. Do not use this package in
  contexts that require a FIPS 140-3 boundary.
- **FIPS roadmap (post-1.0).** A FIPS-validated backend is planned as a
  pluggable verifier option for consumers under FIPS 140-3 obligations.
  Target: 1.1 with an opt-in option (`{ crypto: 'fips' }`) backed by a
  validated library (AWS LC, BoringSSL FIPS, or equivalent). Until then,
  the only validated path is to verify ARP signatures out-of-band before
  passing classifications to AIComply.
- **Algorithm choice.** ML-DSA-44 (NIST FIPS 204, Dilithium) is the
  AIComply-side verify target. The signer (HMA / ARP issuer) uses ML-DSA-44 as
  well to match. AIM / ATX use ML-DSA-65 for issuer signatures - they are
  separate domains; do not assume one signature verifies in the other system.
- **Session vault.** AES-256-GCM with a per-session 256-bit key derived in
  memory only. Keys are never persisted; process exit destroys the key.
- **Hash collisions and prefix-truncation.** Not applicable to V1 (no Merkle
  proofs or signed commitments are produced by AIComply itself).

## Known limitations affecting security posture

1. **Single-layer until Guard ships.** The IPC client is wired and testable,
   but no NanoMind-Guard binary is published yet. Phase 2b training is the
   external gate. Until then `comply()` is regex-only.
2. **Pattern source is public.** A determined attacker can find regex
   bypasses by inspecting `src/classifier/regex/patterns.ts`. The patterns
   are not secret and not designed to be - they are designed to be reviewed
   and tuned for your context. Combine with the Guard layer (when ready)
   and your own controls for adversarial-input scenarios.
3. **Network endpoints default to `api.oa2a.org`.** Callers using L2 logic
   should configure their own `baseUrl` if they require an air-gapped or
   self-hosted Registry; otherwise traffic egresses to the OpenA2A backend.
4. **Telemetry.** This package does not emit telemetry directly. The
   Registry cache *fetches* from the Registry - the Registry sees those
   reads. No PII content is transmitted from `comply()`.
5. **Synthetic-corpus baseline is not a field SLA.** The accuracy numbers
   in this document are measured against `bench/corpus/*.jsonl`, which is
   designed-attacker-aware but not exhaustive of real-world adversarial
   input. Regression-gating is in CI; field accuracy is a separate
   investment.

## Hardening checklist for consumers

- Pin exact version: `"@opena2a/aicomply": "0.1.0"` (no caret).
- Run `npm audit signatures` after install to verify provenance attestations.
- For high-stakes paths, treat `CLEAN` as advisory and apply your own
  defense-in-depth (length caps, allowlists, downstream sanitization).
- Do not use this package as a sole AML/sanctions/HIPAA control. Combine
  with dedicated tools and human review for regulated workflows.
- If you set a custom Registry `baseUrl`, validate the TLS chain and the
  endpoint's signing key out-of-band before warming the cache.

## Reference IDs

These contract IDs are referenced in source and tests; report them in advisories
if affected:

| ID      | Contract |
|---------|----------|
| AC-002  | Cache miss treated as unknown, never as CLEAN |
| AC-005  | No network I/O in the classification hot path |
| CR-001  | Parse-to-deny on invalid Guard signature |
| CR-007  | Local-verify path for ATX-style credentials (not used in V1) |
| D7      | `@noble/post-quantum` for hybrid signing, not FIPS-validated |
| D9      | Session vault: in-memory AES-256-GCM |
| D17     | ML-DSA-44 verify p99 budget < 1.5 ms |
