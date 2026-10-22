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
It loads the same pattern pack as the TypeScript package (`aicomply.PACK_VERSION`
and `aicomply.PACK_SHA256` identify it) and reproduces the TypeScript output case by
case on every case of the shared conformance suite (`pack/conformance`). One known
gap lies outside that suite: a value set off from its keyword by a Unicode separator
such as U+2028 (line separator) or U+1680 (Ogham space mark) is reported by the
TypeScript package and not by this one, because JavaScript `\s` matches those
separators and Python's `re.ASCII` does not.

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

Exit codes make it a drop-in CI gate: `0` CLEAN, `1` findings present, `2` usage error or
no input (stdin is a terminal, or every input is 0 bytes). An input of 0 bytes beside
others is not classified and does not decide the overall verdict or the exit code. The
report and `--json` give it the same verdict, `EMPTY`. The report lists it as
`EMPTY      empty.txt   0 bytes, nothing to classify`, and `--json` as
`"bytes": 0`, `"verdict": "EMPTY"`, `"layers": []`.

On three files of 20 MiB, this CLI took 6.1 to 7.0 times as long as the TypeScript CLI.
On one machine, under Python 3.14.3 and Node.js v26.12.0, `aicomply scan -q` took 3.90 s
on one English sentence repeated, 7.18 s on generated log lines and 11.55 s on random
bytes, where the TypeScript CLI built from the same source tree took 0.64, 1.02 and
1.74 s (the median of three runs each). For a file of that size,
`npx @opena2a/aicomply scan <file>` is the faster choice.

## Library API

```python
from aicomply import comply

result = comply("Customer SSN is 516-81-3086, card 5544939082323438.")

print(result.verdict)                       # VIOLATION
for v in result.violations:
    print(v.type, v.value, v.confidence)    # SSN ...86 0.95
                                            # PAN ...3438 0.9
```

`comply()` returns a `ComplyResult` with:

- `verdict` — `"CLEAN"` or `"VIOLATION"`. `"DENY"` is reserved: the `Verdict`
  type names it to match the TypeScript package, where policy packs, the Registry
  supply-chain block, and signature verification return it, but none of those is
  ported yet (see Scope below), so this package never returns it
- `violations` — each with `type`, masked `value`, `confidence`, `classifier`,
  `view` (which content view caught it), and best-effort `original_start/end`
- `original_content` / `normalized_content` / `normalizations` — an audit trail,
  always set today; once `DENY` is returned, the two content fields will be left
  unset on it, since the input is then treated as untrusted bytes
- `layers`: the layers that ran, in order, `["normalize", "regex"]` plus
  `"guard"` only when the Guard daemon answered; `[]` for empty content
- `pack`: `PackIdentity(version, sha256)`, the pattern pack the regex layer ran
  (`PACK_VERSION` and `PACK_SHA256`)
- `.to_dict()` — camelCase JSON wire-compatible with the npm package

Empty string short-circuits to `CLEAN`; `comply()` also accepts a bare string
(`comply("text")` is shorthand for `comply(content="text")`); other non-`str`
input raises `TypeError`.

> Caution: `original_content` and `normalized_content` hold the raw input by
> design, so a flagged result carries the very PII or credentials it detected.
> Do not pass them to an audit log, trace, or error reporter unmasked. Log
> `verdict` and the masked findings instead, or redact the raw fields before
> persisting them.

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
(highest severity wins). Its absence never fails a request: the classifier falls
back to regex-only. To reach a daemon elsewhere, pass
`guard_options=NanoMindAdapterOptions(base_url=...)` to `comply()`. The
`MOCK_NANOMIND_URL` override is for tests and local development: it is honoured
only when `NODE_ENV` is `test` or `development`, and ignored otherwise.

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

Apache-2.0 - see [LICENSE](https://github.com/opena2a-org/aicomply/blob/main/python/LICENSE).
The wheel installs the same file as `aicomply-<version>.dist-info/licenses/LICENSE`.
