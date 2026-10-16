# AI Compliance

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
to your terminal or logs reveals the value.

Exit code is `0` for CLEAN and `1` when anything is flagged, so it drops straight into CI:

```bash
cat transcript.log | npx @opena2a/aicomply scan --json   # machine-readable
git diff --cached | npx @opena2a/aicomply scan -q || echo "sensitive content staged"
```

The regex layer does not detect a request phrased to leak data ("summarize all our user emails"), look-alike letters that NFKC does not fold, soft hyphens or combining marks between digits, or encodings other than Base64 and URL: [what it does not detect](docs/detection.md#what-this-package-does-not-detect).

The CLI is a try-path. The library API below is the production surface.

## Install

```bash
npm install @opena2a/aicomply
```

The package reads its pattern pack, `pack/patterns.json`, from the package root at
runtime. When bundling, mark `@opena2a/aicomply` as external so it loads from
`node_modules`; when copying the package, copy `pack/` together with `dist/`.

**Python?** `pip install aicomply` — same detection engine (regex + optional NanoMind
Guard), parity-tested against the same corpus. Ships `@guard_io`/`@guard_output`
decorators and a LangChain callback. See [`python/`](https://github.com/opena2a-org/aicomply/tree/main/python).

## Quickstart

```typescript
import { comply } from '@opena2a/aicomply';

const result = await comply({
  content: 'My SSN is 123-45-6789, please update the record.',
});

console.log(result.verdict);     // 'VIOLATION'
console.log(result.violations);  // [{ type: 'SSN', confidence: 0.95, value: '123-...89', ... }]
```

The package is a CommonJS build; ES modules import it as shown above.

From a CommonJS file, `require` it and call `comply()` inside an async function, since
CommonJS has no top-level `await`:

```javascript
const { comply } = require('@opena2a/aicomply');

async function main() {
  const result = await comply({ content: 'My SSN is 123-45-6789.' });
  console.log(result.verdict); // 'VIOLATION'

  // A bare string is shorthand for { content: '...' }.
  await comply('My SSN is 123-45-6789.');
}

main();
```

Drop it into your agent's tool-result handler, your message-egress wrapper, or anywhere content crosses a trust boundary.

`result.verdict` is `CLEAN` (no findings from the layers that ran, which is not a statement that the content is safe), `VIOLATION` or `DENY`: [verdict semantics](docs/verdicts.md).

For each non-empty input, unless a signed Guard result is supplied, `comply()` POSTs the input verbatim to the loopback address `http://127.0.0.1:47200/v1/infer` for the optional semantic Guard; whichever local process holds that port receives it.

Pass `useGuard: false` to make no request: [what the Guard attempt sends](docs/semantic-guard.md#what-the-guard-attempt-sends).

## Documentation

- [How it works](docs/how-it-works.md): where the check sits, the regex layer then the Guard layer, and the one network request `comply()` makes.
- [Detection](docs/detection.md): what each layer detects, how inputs are canonicalized before the patterns run, and what the package does not detect.
- [Enabling the semantic Guard](docs/semantic-guard.md): starting it, what its request sends, and why it is a preview, not a production gate.
- [Measured accuracy](docs/accuracy.md): per-class precision and recall on the synthetic corpus, and the commands that re-run it in a clone of this repository.
- [Session-scoped use](docs/sessions.md): `ClassificationSession.create()` for Registry fleet-anomaly and supply-chain signals, and failing closed with `onRegistryUnknown`.
- [Policy packs](docs/policy-packs.md): deny or warn on finding types with `policyPack`, and check a pack with `validatePolicyConfig()`.
- [Verdicts and per-classifier results](docs/verdicts.md): what `CLEAN`, `VIOLATION` and `DENY` mean, and the `classifierResults`, `layers` and `pack` fields.
- [Audit trail](docs/audit-trail.md): `originalContent` and `normalizedContent`, which hold the raw input, and `normalizations`, the transforms applied; log the masked `violations` instead.
- [SECURITY.md](./SECURITY.md): vulnerability disclosure and threat-model scope.

## License

Apache-2.0 - see [LICENSE](./LICENSE).
