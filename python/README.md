# aicomply (Python)

Inline PII, credential, and regulated-data classifier for AI agent I/O. Catch
sensitive content **before** your agent forwards it to a hosted LLM.

Dual-layer by design: a deterministic regex layer (PII, credentials, controlled
markings) that runs always, plus an optional semantic Guard layer when a local
[nanomind-daemon](https://github.com/opena2a-org) is reachable. The regex layer
sees through common evasions — Unicode homoglyphs (NFKC), zero-width characters,
intra-token whitespace, and bounded Base64 / URL-encoded payloads — by normalizing
the input before matching.

This is the Python port of [`@opena2a/aicomply`](https://www.npmjs.com/package/@opena2a/aicomply).
It reproduces the TypeScript detection baseline against the same shared corpus
(`bench/corpus`), so verdicts agree across languages.

## Install

```bash
pip install aicomply
```

## Try it (CLI)

No integration code required — point it at a file or pipe content in:

```bash
echo "My SSN is 123-45-6789" | aicomply scan
aicomply scan ./support-ticket.txt
cat transcript.log | aicomply scan --json
```

Exit codes make it a drop-in CI gate: `0` CLEAN, `1` findings present, `2` usage error.

## Library API

```python
from aicomply import comply

result = comply("Customer SSN is 516-81-3086, card 5544939082323438.")

print(result.verdict)                       # "VIOLATION"
for v in result.violations:
    print(v.type, v.value, v.confidence)     # SSN 516...86 0.95  (value is masked)
```

`comply()` returns a `ComplyResult` with:

- `verdict` — `"CLEAN"`, `"VIOLATION"`, or `"DENY"`
- `violations` — each with `type`, masked `value`, `confidence`, `classifier`,
  `view` (which content view caught it), and best-effort `original_start/end`
- `original_content` / `normalized_content` / `normalizations` — an audit trail
  (omitted on `DENY`, where the input is treated as untrusted bytes)
- `.to_dict()` — camelCase JSON wire-compatible with the npm package

Empty string short-circuits to `CLEAN`; non-`str` input raises `TypeError`.

## Guard an agent's output

Drop one decorator above any function that emits text bound for an LLM or a user:

```python
from aicomply.integrations import guard_output, ComplianceViolation

@guard_output()                       # raise on any PII/credential egress
def answer(user_msg: str) -> str:
    return call_llm(user_msg)

@guard_output(on_violation="redact")  # or mask findings in place
def answer_redacted(user_msg: str) -> str:
    return call_llm(user_msg)
```

`guard_io()` additionally scans string inputs on the way in.

## LangChain

```bash
pip install 'aicomply[langchain]'
```

```python
from langchain_openai import ChatOpenAI
from aicomply.integrations.langchain import AIComplyCallbackHandler

llm = ChatOpenAI(callbacks=[AIComplyCallbackHandler()])
llm.invoke("Summarize this support ticket: ...")   # raises if the LLM emits PII
```

## Semantic Guard layer (preview, not production-ready)

The regex layer is deterministic, always on, and is the production surface. The
optional Guard layer targets prompt-injection / exfiltration patterns that regex
cannot see, but the current model (`nanomind-security-classifier` tme-v0.5.0)
over-flags benign text: measured 2026-06-25, 7 of 10 ordinary-benign sentences were
flagged as an attack class at greater than 0.99 confidence at the default 0.8
threshold. Treat it as a preview, not for production gating, until a recalibrated
model ships.

The daemon ships on **npm**, not PyPI (`npm i -g @nanomind/daemon && nanomind-daemon
start`); it is a local HTTP server this Python client calls. When it is reachable on
`127.0.0.1:47200` the dual-layer classifier consults it and merges the verdict
(highest severity wins). Its absence never fails a request — the classifier falls
back to regex-only.

## Detection classes

SSN, PAN (Luhn + IIN), credentials (AWS keys, GitHub tokens, Bearer tokens,
`api_key=` patterns), CUI / controlled markings, IBAN (mod-97), passport
numbers, MRN, NPI (Luhn with `80840` prefix).

## Scope

This port covers the deterministic detection layer (regex + normalization +
dual-layer merge + verdict) plus the daemon Guard client. The TypeScript
package's Registry-L2, ARP-signature, policy-pack, and session-vault features are
not yet ported.

## License

Apache-2.0.
