# @opena2a/aicomply

[![Status: stable](https://img.shields.io/badge/status-stable-brightgreen)](./STATUS.md)

Inline content classifier for AI agent I/O. Detects PII, credentials, and regulated data before your agent ships it to a cloud LLM, with an optional preview semantic layer that targets prompt-injection and exfiltration patterns.

Two detection layers run in parallel:

- A deterministic **regex layer** with adversarial-mutation handling (NFKC homoglyph folding, zero-width strip, targeted whitespace compaction, bounded Base64/URL decode). Always on, ~sub-ms.
- An optional **semantic Guard layer (preview)** powered by [NanoMind](https://huggingface.co/opena2a/nanomind-security-classifier). It targets prompt-injection, tool-misuse, data-extraction, and exfiltration patterns the regex layer can't see. The current model has a high benign false-positive rate and is **not yet production-ready** - see [Guard status](#guard-status-preview-not-production-ready). Active only when `@nanomind/daemon` is running locally; aicomply runs regex-only otherwise.

## Why this exists

Every agent that calls a hosted LLM (Anthropic, OpenAI, Bedrock, Vertex, …) copies the conversation - system prompt, tool outputs, retrieved documents, user input - into a third party's logs. If your agent reads a support ticket containing an SSN, that SSN goes to the provider. If your agent reads `.env` to summarize it, your AWS key goes too. Most agent stacks have no inline check between "tool returned content" and "send to model."

`aicomply` is that check. It runs inline, sub-millisecond, with no external calls of its own. You hand it the content; it returns a verdict (`CLEAN` / `VIOLATION` / `DENY`) and structured findings. You decide what to do next - block, redact, log, or pass.

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
    SSN          123-•••89          confidence 0.95  layer regex

Verdict: VIOLATION  ·  block, redact, or log before this content reaches an LLM.
```

Detected values are masked in output, so the CLI never prints a full secret to your
terminal or logs. Exit code is `0` for CLEAN and `1` when anything is flagged, so it
drops straight into CI:

```bash
cat transcript.log | npx @opena2a/aicomply scan --json   # machine-readable
git diff --cached | npx @opena2a/aicomply scan -q || echo "sensitive content staged"
```

The CLI is a try-path. The library API below is the production surface.

## Install

```bash
npm install @opena2a/aicomply
```

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
| Government | CUI, FOUO, CONTROLLED markings                                 |

Pattern source lives at [`src/classifier/regex/patterns.ts`](https://github.com/opena2a-org/aicomply/blob/main/src/classifier/regex/patterns.ts) - not secret, designed to be reviewed and tuned for your context.

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
npx nanomind-daemon &   # listens on http://127.0.0.1:47200
```

aicomply auto-detects the daemon on the default URL. Override with `MOCK_NANOMIND_URL` (development) or pass `baseUrl` to `classifyWithNanoMindDaemon()` directly. No code change required in the consumer: as long as the daemon is reachable, `comply()` returns `classifierResults.guard` populated alongside the regex result.

If the daemon is not installed, not running, or unreachable, aicomply silently falls back to regex-only - the v1.0 behavior. The Guard is a defense-in-depth layer, not a gate.

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

Every finding carries a `view` field (`normalized` / `compact` / `decoded-base64` / `decoded-url`) and best-effort original-content anchoring so you can audit which canonicalization surfaced each match.

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

- **Semantic / contextual violations.** A request to "summarize all our user emails" is not a regex hit. The semantic layer ([NanoMind-Guard](./src/classifier/guard-client)) is wired but its model binary depends on external training that has not shipped - the IPC client falls back silently to regex-only when no socket is reachable.
- **Cyrillic / Greek look-alikes that are not NFKC-equivalent** (e.g. Cyrillic `а` vs Latin `a`). Those are separate semantic letters; NFKC does not fold them.
- **Soft hyphen (U+00AD) and combining marks.** Out of scope for 1.0, deferred to 1.1. An attacker can still hide PII by injecting these characters between digits.
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

The cache warms once on `create()`. Subsequent `comply()` calls do no network I/O (contract AC-005 in [SECURITY.md](./SECURITY.md)).

## Verdict semantics

- **`CLEAN`**: no findings; safe to forward
- **`VIOLATION`**: one or more findings; the `violations` array is the audit trail
- **`DENY`**: hard block (a policy pack triggered, or supply-chain Registry said the source package is untrusted); treat as fatal

## Inspecting per-classifier results

Every result also carries a `classifierResults` mirror with each layer's raw verdict, useful for debugging or logging which layer fired:

```typescript
const result = await comply({ content });

result.classifierResults.regex; // { classifier: 'regex', verdict, violations }
result.classifierResults.guard; // defined when GuardClient was reachable
```

Treat `verdict` and `violations` as the stable contract; `classifierResults`, `originalContent`, `normalizedContent`, and `normalizations` are introspection hooks.

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
> persisting them. `violations[i].value` is also raw; mask it (see the CLI's
> `maskValue`) before display.

## License

Apache-2.0 - see [LICENSE](./LICENSE).

## Security

Vulnerability disclosure and threat-model scope: [SECURITY.md](./SECURITY.md).
