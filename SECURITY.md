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

`@opena2a/aicomply` is pre-1.0 and ships from a single supported line.
Security fixes target the latest published minor; older minors do not receive
backports. Pin exact versions in production (`"@opena2a/aicomply": "0.1.0"`)
and consume security fixes by bumping.

## What this package is and isn't

`@opena2a/aicomply` is a **content classifier**. It inspects strings (agent
inputs, tool outputs) and returns a verdict (`CLEAN` / `VIOLATION` / `DENY`)
plus structured violation records. It is one input to your compliance
posture — not a complete control.

### In threat model scope
- Correctness of the dual-layer merge (`CLEAN` only when both layers are clean;
  `DENY` overrides everything; supply-chain hard block always DENY)
- Signature verification of Guard classifier results (Ed25519 + ML-DSA-44 hybrid,
  parse-to-deny on invalid signatures — contract CR-001)
- Session vault key isolation (AES-256-GCM, keys never persisted to disk)
- Registry intelligence cache integrity (cache-miss treated as unknown, not clean —
  contract AC-002)

### Out of threat model scope (V1)
- **Adversarial mutation of regex inputs.** V1 does not normalize Unicode
  homoglyphs (for example, Cyrillic small letter e at U+0435 visually
  resembles Latin small letter e at U+0065), strip whitespace injection
  (`1 2 3-4 5-6 7 8 9`), decode encoded forms (Base64, URL-encoded, HTML
  entities), or handle obfuscation. Treat the regex layer as a
  deterministic-format check, not a semantic detector.
- **Accuracy guarantees.** V1 ships without a measured precision/recall
  baseline against a published PII corpus. False positive and false negative
  rates on your data are not characterized. Do not rely on this package as a
  sole detection control where adversarial users can craft inputs.
- **Side-channel resistance.** Timing of `comply()` may leak coarse information
  about input length and pattern density. Not designed against timing attacks.
- **Registry availability.** L2 logic (fleet anomaly threshold, supply-chain
  hard block) is best-effort and depends on the configured Registry endpoint.
  Cache miss does not fail closed; it surfaces signals so callers decide.
- **Guard classifier (V2).** The `GuardClient` ships as a stub in V1 and
  always reports unavailable. Any V2 guarantees about neural classification
  (semantic context, intent detection) apply only after the NanoMind-Guard
  daemon ships and is reachable.

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
- **Algorithm choice.** ML-DSA-44 (NIST FIPS 204, Dilithium) is the
  AIComply-side verify target. The signer (HMA / ARP issuer) uses ML-DSA-44 as
  well to match. AIM / ATX use ML-DSA-65 for issuer signatures — they are
  separate domains; do not assume one signature verifies in the other system.
- **Session vault.** AES-256-GCM with a per-session 256-bit key derived in
  memory only. Keys are never persisted; process exit destroys the key.
- **Hash collisions and prefix-truncation.** Not applicable to V1 (no Merkle
  proofs or signed commitments are produced by AIComply itself).

## Known limitations affecting security posture

1. **Stub Guard means single-layer in V1.** Until the NanoMind-Guard daemon
   ships, the "dual-layer" classifier is effectively single-layer (regex). The
   dual-layer merge logic is correct; the second layer is absent.
2. **No corpus-validated FP rate.** A determined attacker can probably find
   regex bypasses by inspecting `src/classifier/regex/patterns.ts`. The
   patterns are not secret and not designed to be.
3. **Network endpoints default to `api.oa2a.org`.** Callers using L2 logic
   should configure their own `baseUrl` if they require an air-gapped or
   self-hosted Registry; otherwise traffic egresses to the OpenA2A backend.
4. **Telemetry.** V1 does not emit telemetry from this package directly.
   The Registry cache *fetches* from the Registry — the Registry sees those
   reads. No PII content is transmitted from `comply()`.

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
