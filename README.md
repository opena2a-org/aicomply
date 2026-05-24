# @opena2a/aicomply

Inline content classifier for AI agent I/O. Detects PII, credentials, regulated data, and other sensitive content before your agent ships it to a cloud LLM.

## Why this exists

Every agent that calls a hosted LLM (Anthropic, OpenAI, Bedrock, Vertex, …) copies the conversation — system prompt, tool outputs, retrieved documents, user input — into a third party's logs. If your agent reads a support ticket containing an SSN, that SSN goes to the provider. If your agent reads `.env` to summarize it, your AWS key goes too. Most agent stacks have no inline check between "tool returned content" and "send to model."

`aicomply` is that check. It runs inline, sub-millisecond, with no external calls of its own. You hand it the content; it returns a verdict (`CLEAN` / `VIOLATION` / `DENY`) and structured findings. You decide what to do next — block, redact, log, or pass.

## Install

```bash
npm install @opena2a/aicomply
```

## Quickstart

```typescript
import { comply } from '@opena2a/aicomply';

const result = await comply({
  content: 'My SSN is 123-45-6789, please update the record.',
});

console.log(result.verdict);     // 'VIOLATION'
console.log(result.violations);  // [{ type: 'SSN', confidence: 0.99, ... }]
```

Drop it into your agent's tool-result handler, your message-egress wrapper, or anywhere content crosses a trust boundary.

## What it detects (V1)

| Class | Examples |
|---|---|
| PII | SSN, passport numbers, medical record numbers, NPI |
| Financial | PAN (Luhn-validated), IBAN |
| Credentials | AWS keys, GitHub tokens, Bearer tokens, generic `api_key=` |
| Government markings | CUI, FOUO, CONTROLLED |

Pattern source lives at [`src/classifier/regex/patterns.ts`](./src/classifier/regex/patterns.ts) — not secret, designed to be reviewed and tuned for your context.

## What V1 does NOT do

Stated plainly because false confidence is worse than known gaps. Full disclosure in [SECURITY.md](./SECURITY.md).

- **No adversarial-mutation handling.** Unicode homoglyphs, whitespace injection, encoded forms (Base64, URL-encoded) are not normalized in V1. Treat the regex layer as a format check, not a semantic detector.
- **No semantic classifier.** V1 is regex-only. The neural layer (NanoMind-Guard) ships in V2 — the `GuardClient` export is a stub that always reports unavailable until then.
- **No measured accuracy claim.** No published precision/recall against a labeled corpus. Don't use this as a sole control for adversarial inputs.

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

- **`CLEAN`** — no findings; safe to forward
- **`VIOLATION`** — one or more findings; the `violations` array is the audit trail
- **`DENY`** — hard block (a policy pack triggered, or supply-chain Registry said the source package is untrusted); treat as fatal

## License

Apache-2.0 — see [LICENSE](./LICENSE).

## Security

Vulnerability disclosure and threat-model scope: [SECURITY.md](./SECURITY.md).
