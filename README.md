# @opena2a/aicomply

[![Status: stable](https://img.shields.io/badge/status-stable-brightgreen)](./STATUS.md)

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

Inline content classifier for AI agent I/O. Detects PII, credentials, and regulated data before your agent ships it to a cloud LLM, with an optional preview semantic layer that targets prompt-injection and exfiltration patterns. Apache 2.0.

[![npm version](https://img.shields.io/npm/v/@opena2a/aicomply.svg)](https://www.npmjs.com/package/@opena2a/aicomply)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://github.com/opena2a-org/aicomply/actions/workflows/release.yml/badge.svg)](https://github.com/opena2a-org/aicomply/actions/workflows/release.yml)

## Try it (CLI, no integration code)

Evaluate aicomply against real content in one command, before writing any code:

```bash
# scan a file
npx @opena2a/aicomply scan ./support-ticket.txt

# pipe content
echo "My SSN is 123-45-6789, please update the record." | npx @opena2a/aicomply scan
```

```
  VIOLATION  (stdin)   1 finding
    SSN          •••                confidence 0.95  layer regex

  Semantic Guard layer: inactive (preview; no nanomind-daemon on http://127.0.0.1:47200).
  It targets prompt-injection / exfiltration the regex layer cannot see, but the
  current model over-flags benign text - preview only, not for production gating.
  Try it: npm i @nanomind/daemon && npx nanomind-daemon start

Verdict: VIOLATION  ·  1 finding across 1 input. Block, redact, or log before this content reaches an LLM.
```

The CLI prints a detected value's type and none of its characters, so nothing it writes
to your terminal or logs reveals the value. Exit code is `0` for CLEAN and `1` when anything is flagged, so it
drops straight into CI:

```bash
cat transcript.log | npx @opena2a/aicomply scan --json   # machine-readable
git diff --cached | npx @opena2a/aicomply scan -q || echo "sensitive content staged"
```

The CLI is a try-path. The library API below is the production surface.

## How it works

`aicomply` is an inline check between "tool returned content" and "send to model," which most agent stacks lack even though every agent that calls a hosted LLM (Anthropic, OpenAI, Bedrock, Vertex, …) copies the conversation - system prompt, tool outputs, retrieved documents, user input - into a third party's logs. If your agent reads a support ticket containing an SSN, that SSN goes to the provider. If your agent reads `.env` to summarize it, your AWS key goes too.

It runs inline, sub-millisecond. You hand it the content; it returns a verdict (`CLEAN` / `VIOLATION` / `DENY`) and structured findings. You decide what to do next - block, redact, log, or pass.

Two detection layers run one after the other, the regex layer first and then the Guard layer, so a call takes the sum of their latencies:

- A deterministic **regex layer** with adversarial-mutation handling (NFKC homoglyph folding, zero-width strip, targeted whitespace compaction, bounded Base64/URL decode). Always on, ~sub-ms.
- An optional **semantic Guard layer (preview)** powered by [NanoMind](https://huggingface.co/opena2a/nanomind-security-classifier). It targets prompt-injection, tool-misuse, data-extraction, and exfiltration patterns the regex layer can't see. The current model has a high benign false-positive rate and is **not yet production-ready** - see [Guard status](#guard-status-preview-not-production-ready). Active only when `@nanomind/daemon` is running locally; aicomply runs regex-only otherwise.

The Guard attempt is the one network request `comply()` makes. For each non-empty input it POSTs the input verbatim to the loopback address `http://127.0.0.1:47200/v1/infer`, so the request stays on the host, and whichever local process holds that port receives the input. Pass `useGuard: false` to make no request - see [What the Guard attempt sends](#what-the-guard-attempt-sends).

## Install

```bash
npm install @opena2a/aicomply
```

The package reads its pattern pack, `pack/patterns.json`, from the package root at
runtime. When bundling, mark `@opena2a/aicomply` as external so it loads from
`node_modules`; when copying the package, copy `pack/` together with `dist/`.

**Python?** `pip install aicomply` — same detection engine (regex + optional NanoMind
Guard), parity-tested against the same corpus. Ships `@guard_io`/`@guard_output`
decorators and a LangChain callback. See [`python/`](python/).

## Quickstart

```typescript
import { comply } from '@opena2a/aicomply';

const result = await comply({
  content: 'My SSN is 123-45-6789, please update the record.',
});

console.log(result.verdict);     // 'VIOLATION'
console.log(result.violations);  // [{ type: 'SSN', confidence: 0.95, value: '123-...89', ... }]
```

CommonJS works too (the package ships both):

```javascript
const { comply } = require('@opena2a/aicomply');

const result = await comply({ content: 'My SSN is 123-45-6789.' });
console.log(result.verdict); // 'VIOLATION'

// A bare string is shorthand for { content: '...' }.
await comply('My SSN is 123-45-6789.');
```

Drop it into your agent's tool-result handler, your message-egress wrapper, or anywhere content crosses a trust boundary.

## What it detects

### Regex layer (always on)

| Class      | Examples                                                       |
|------------|----------------------------------------------------------------|
| PII        | SSN, passport numbers, medical record numbers, NPI             |
| Financial  | PAN (Luhn-validated), IBAN (mod-97-validated)                  |
| Credentials| AWS keys, GitHub tokens, Bearer tokens, generic `api_key=` |
| Government | `CUI//SP-PRVCY`, `CUI//BASIC`, `CONTROLLED UNCLASSIFIED INFORMATION`, `FOR OFFICIAL USE ONLY` |

Pattern source lives at [`pack/patterns.json`](https://github.com/opena2a-org/aicomply/blob/main/pack/patterns.json), the one pattern pack the TypeScript and Python packages both load (`PACK_VERSION` and `PACK_SHA256` say which one you have) - not secret, designed to be reviewed and tuned for your context. Each runtime must reproduce every case in [`pack/conformance/`](./pack/conformance) exactly: `npm run conformance` and `python python/bench/conformance.py`. The release gates refuse a record that does not match what ships: `npm publish` runs `npm run release:gate` after the conformance run, and `python python/bench/release_gate.py` is the same check for the Python package, run by hand against the wheel and sdist that `python -m build` wrote before an upload; the PyPI workflow does not run it yet.

### Semantic Guard layer (preview, when nanomind-daemon is running)

> **Preview.** The current model over-flags benign text and is not recommended for
> production gating. See [Guard status](#guard-status-preview-not-production-ready).

| AttackClass            | Catches                                                       |
|------------------------|---------------------------------------------------------------|
| `prompt_injection`     | "Ignore previous instructions", role-switching, override prompts |
| `exfiltration_pattern` | Requests crafted to siphon data via tool outputs              |
| `tool_misuse`          | Inputs that pressure the agent into unsanctioned tool calls   |
| `data_extraction`      | Bulk-readout requests targeting sensitive fields              |

When the Guard fires above its confidence threshold, the finding surfaces with `view: undefined`, `classifier: 'guard'`, and `type` equal to the attack class. Block per AIM FGA Step 5: `attackClass !== '' && confidence > 0.8`.

## Enabling the semantic Guard

The Guard is opt-in via `@nanomind/daemon`. Install and run it alongside aicomply:

```bash
npm install @nanomind/daemon
npx nanomind-daemon start &   # listens on http://127.0.0.1:47200
```

aicomply auto-detects the daemon on the default URL. No code change is required in the consumer: as long as the daemon is reachable there, `comply()` returns `classifierResults.guard` populated alongside the regex result. To reach a daemon on another address, pass `guardOptions`:

```typescript
const result = await comply({ content: agentInput, guardOptions: { baseUrl: 'http://10.0.0.5:47200' } });
const session = await ClassificationSession.create({ guardOptions: { baseUrl: 'http://10.0.0.5:47200' } });
```

`guardOptions` also takes `timeoutMs` (default 5000) and `agentId`, and is the same object `classifyWithNanoMindDaemon(content, options)` accepts. The `MOCK_NANOMIND_URL` and `MOCK_GUARD_SOCKET` overrides are for tests and local development: they are honoured only when `NODE_ENV` is `test` or `development` and ignored otherwise, including when `NODE_ENV` is unset.

If the daemon is not installed, not running, or unreachable, aicomply silently falls back to regex-only - the v1.0 behavior. The Guard is a defense-in-depth layer, not a gate.

### What the Guard attempt sends

`comply()` attempts the Guard whether or not a daemon is running. For each non-empty input (empty and whitespace-only input is not sent) it makes one request, `POST http://127.0.0.1:47200/v1/infer`, with the input verbatim in the JSON body:

```json
{"intent":"INTENT_CHECK","input":"My SSN is 123-45-6789."}
```

The address is loopback, so the request does not leave the host, and with nothing listening on port 47200 the connection is refused and the result is regex-only. A local process other than the daemon that holds the port receives every classified input all the same.

To make no request, pass `useGuard: false`:

```typescript
const result = await comply({ content, useGuard: false });

result.layers; // ['normalize', 'regex'] - regex-only, nothing was sent
```

`comply(content, { useGuard: false })`, `classifyDualLayer()` and `ClassificationSession.comply()` take the same option, which matches `use_guard=False` in the Python package. A value that is not a boolean is rejected with a `TypeError`.

### Guard status: preview, not production-ready

The Guard wiring is complete and the daemon runs, but the current model
(`nanomind-security-classifier` tme-v0.5.0) has a high false-positive rate on
benign text. Measured 2026-06-25 against `@nanomind/daemon` 0.3.0: at the default
0.8 block threshold, 7 of 10 ordinary-benign sentences were flagged as an attack
class with greater than 0.99 confidence. For example, "Please summarize this
quarterly report." returns `exfiltration_pattern` at 1.0, and "The weather is nice
today." returns `prompt_injection` at 0.999. True attacks ("Ignore all previous
instructions...") are caught correctly, but the benign false-positive rate makes
the Guard unsuitable for inline production gating today. Raising the threshold does
not fix it, because the false positives arrive at near-1.0 confidence.

Treat the Guard as a preview. The **regex layer is the production surface**: it is
on by default, needs no daemon, and carries the measured accuracy below. Leave the
Guard off (the default whenever no daemon is running) for production filtering until
a recalibrated model ships; enable it only for evaluation.

When you do enable it for evaluation, the wiring is correct end-to-end: a true
`prompt_injection` or `tool_misuse` input surfaces as a `classifierResults.guard`
violation alongside the independent regex result. Recalibrating the model's benign
false-positive rate is tracked as the gating work before the Guard is recommended.

## Adversarial-mutation handling

Inputs are canonicalized before patterns run:

- **Unicode homoglyphs** are folded via NFKC (`１２３-４５-６７８９` → `123-45-6789`).
- **Zero-width and bidi-control characters** are stripped (`1​2​3-4​5-6​7​8​9` → `123-45-6789`).
- **Whitespace-injected** values are scanned in a compact view that strips spaces only between digit/separator characters, so prose word boundaries stay intact (`1 2 3 - 4 5 - 6 7 8 9` matches; `My SSN is 123-45-6789` still works).
- **Base64 / URL-encoded** payloads are extracted and scanned in addition to the canonical stream (bounded recursion, length-gated, ASCII-printable round-trip required).

Every pattern match carries a `view` field (`normalized` / `compact` / `decoded-base64` / `decoded-url`) and best-effort original-content anchoring so you can audit which canonicalization surfaced each match. Findings that do not come from a pattern match have no `view`: Guard findings, `POLICY_DENY` / `POLICY_WARN`, `SUPPLY_CHAIN_ALERT` and `FLEET_ANOMALY_ELEVATED`. The CLI's `--json` output prints `"view": null` for them.

## Measured accuracy

Per-class precision and recall against the synthetic corpus at [`bench/corpus/`](./bench/corpus) (200 positives + 200 hard-negatives per class, including adversarial variants):

| Class      | Precision | Recall | F1    |
|------------|-----------|--------|-------|
| SSN        | 1.000     | 1.000  | 1.000 |
| PAN        | 1.000     | 1.000  | 1.000 |
| IBAN       | 0.990     | 1.000  | 0.995 |
| NPI        | 1.000     | 1.000  | 1.000 |
| CUI        | 1.000     | 1.000  | 1.000 |
| CREDENTIAL | 1.000     | 1.000  | 1.000 |
| PASSPORT   | 1.000     | 1.000  | 1.000 |
| MRN        | 1.000     | 1.000  | 1.000 |

These are baseline numbers on a deterministic synthetic corpus, not a field SLA. Regenerate against your own data: `npm run accuracy:generate && npm run accuracy:measure`. CI fails on any > 2pp drop vs `bench/baseline.json`.

## What this package does NOT detect

For full threat-model scope see [SECURITY.md](./SECURITY.md). The honest list:

- **Semantic / contextual violations.** A request to "summarize all our user emails" is not a regex hit. The semantic Guard layer targets these, but it is a preview: the NanoMind model has shipped and `@nanomind/daemon` serves it, yet it over-flags benign text (see [Guard status](#guard-status-preview-not-production-ready)). The Guard is off unless a daemon is running; when none is reachable over HTTP, `comply()` falls back silently to regex-only.
- **Cyrillic / Greek look-alikes that are not NFKC-equivalent** (e.g. Cyrillic `а` vs Latin `a`). Those are separate semantic letters; NFKC does not fold them.
- **Soft hyphen (U+00AD) and combining marks.** Not stripped from the normalized stream. An attacker can still hide PII by injecting these characters between digits.
- **Encodings other than Base64 and URL.** Hex, base32, ROT13, HTML entities, quoted-printable are not decoded.
- **All-letter alphanumeric MRN identifiers** (e.g. UK NHS ULN-style). The MRN regex requires at least one digit, trading recall on all-letter clinical identifiers for precision on prose mentions ("MRN system was updated"). Custom regex needed for those domains.
- **Steganography and natural-language paraphrasing of sensitive content.** Requires the semantic layer.

## Session-scoped use (optional)

For long-lived agents that want fleet-anomaly thresholds and supply-chain hard-block intelligence from the OpenA2A Registry:

```typescript
import { ClassificationSession } from '@opena2a/aicomply';

const session = await ClassificationSession.create();

const result = await session.comply({
  content: agentInput,
  sourcePackage: 'my-agent-name',
});
```

The cache warms once on `create()`. Subsequent `comply()` calls make no Registry request (contract AC-005 in [SECURITY.md](./SECURITY.md)). Each call still makes the Guard request described in [What the Guard attempt sends](#what-the-guard-attempt-sends) unless you pass `useGuard: false`.

`result.registrySignals.status` says what the Registry had for the package: `hit`, `miss` (not in the index) or `error` (the index did not load, for example because the Registry was unreachable). A `miss` or an `error` leaves the verdict as the classifiers set it. To fail closed, pass `onRegistryUnknown`:

```typescript
const result = await session.comply({
  content: agentInput,
  sourcePackage: 'my-agent-name',
  onRegistryUnknown: 'deny', // or 'violation'
});
```

Either value appends a `REGISTRY_UNKNOWN` violation (contract AC-002).

## Verdict semantics

- **`CLEAN`**: no findings; safe to forward
- **`VIOLATION`**: one or more findings; the `violations` array is the audit trail
- **`DENY`**: hard block (a policy pack triggered, supply-chain Registry said the source package is untrusted, or `onRegistryUnknown: 'deny'` met a package the Registry had no data for); treat as fatal

## Inspecting per-classifier results

Every result also carries a `classifierResults` mirror with each layer's raw verdict, useful for debugging or logging which layer fired:

```typescript
const result = await comply({ content });

result.classifierResults.regex; // { classifier: 'regex', verdict, violations }
result.classifierResults.guard; // defined when GuardClient was reachable
result.layers;                  // ['normalize', 'regex'], plus 'guard' when a Guard result was accepted
result.pack;                    // { version, sha256 }: the pattern pack the regex layer ran
```

`layers` never lists `guard` on the regex-only fallback or when a supplied Guard signature is rejected, and is `[]` for empty content. `pack` equals `{ version: PACK_VERSION, sha256: PACK_SHA256 }`.

Treat `verdict` and `violations` as the stable contract; `classifierResults`, `originalContent`, `normalizedContent`, `normalizations`, `layers` and `pack` are introspection hooks.

## Audit trail

`comply()` preserves the input and the canonical form alongside the verdict:

```typescript
const result = await comply({ content: 'SSN:１２３-４５-６７８９' });

result.originalContent;     // 'SSN:１２３-４５-６７８９'
result.normalizedContent;   // 'SSN:123-45-6789'
result.normalizations;      // [{ transform: 'nfkc', count: 9 }]
result.violations[0].view;  // 'normalized'
```

> Caution: `originalContent` and `normalizedContent` hold the raw input by
> design, so a flagged result carries the very PII or credentials it detected.
> Do not pass them to an audit log, trace, or error reporter unmasked. Log
> `verdict` and the masked `violations` instead, or redact the raw fields before
> persisting them. `violations[i].value` is already masked: a regex finding
> keeps its first 4 and last 2 characters (`123-...89`), or is fully starred at
> 6 characters or fewer, and a Guard finding reads `***GUARD***`.

## License

Apache-2.0 - see [LICENSE](./LICENSE).

## Security

Vulnerability disclosure and threat-model scope: [SECURITY.md](./SECURITY.md).
