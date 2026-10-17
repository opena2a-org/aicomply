# Detection

What the two layers report, how inputs are canonicalized before the patterns run, and what the package does not detect.

## What it detects

### Regex layer (always on)

| Class      | Examples                                                       |
|------------|----------------------------------------------------------------|
| PII        | SSN, passport numbers, medical record numbers, NPI             |
| Financial  | PAN (Luhn-validated), IBAN (mod-97-validated)                  |
| Credentials| AWS keys, GitHub tokens, Bearer tokens, generic `api_key=` |
| Government | `CUI//SP-PRVCY`, `CUI//BASIC`, `CONTROLLED UNCLASSIFIED INFORMATION`, `FOR OFFICIAL USE ONLY` |

Pattern source lives at [`pack/patterns.json`](https://github.com/opena2a-org/aicomply/blob/main/pack/patterns.json), the one pattern pack the TypeScript and Python packages both load (`PACK_VERSION` and `PACK_SHA256` say which one you have) - not secret, designed to be reviewed and tuned for your context. Each runtime must reproduce every case in [`pack/conformance/`](https://github.com/opena2a-org/aicomply/tree/main/pack/conformance) exactly: `npm run conformance` and `python python/bench/conformance.py`. The release gates refuse a record that does not match what ships: `npm publish` runs `npm run release:gate` after the conformance run, and `python python/bench/release_gate.py` is the same check for the Python package, run by hand against the wheel and sdist that `python -m build` wrote before an upload; the PyPI workflow does not run it yet.

### Semantic Guard layer (preview, when nanomind-daemon is running)

> **Preview.** The current model over-flags benign text and is not recommended for
> production gating. See [Guard status](semantic-guard.md#guard-status-preview-not-production-ready).

| AttackClass            | Catches                                                       |
|------------------------|---------------------------------------------------------------|
| `prompt_injection`     | "Ignore previous instructions", role-switching, override prompts |
| `exfiltration_pattern` | Requests crafted to siphon data via tool outputs              |
| `tool_misuse`          | Inputs that pressure the agent into unsanctioned tool calls   |
| `data_extraction`      | Bulk-readout requests targeting sensitive fields              |

When the Guard fires above its confidence threshold, the finding surfaces with `view: undefined`, `classifier: 'guard'`, and `type` equal to the attack class. Block per AIM FGA Step 5: `attackClass !== '' && confidence > 0.8`.

## Adversarial-mutation handling

Inputs are canonicalized before patterns run:

- **Unicode homoglyphs** are folded via NFKC (`１２３-４５-６７８９` → `123-45-6789`).
- **Zero-width and bidi-control characters** are stripped (`123-45-6789` with a zero-width space, U+200B, between each pair of adjacent digits → `123-45-6789`).
- **Whitespace-injected** values are scanned in a compact view that strips spaces only between digit/separator characters, so prose word boundaries stay intact (`1 2 3 - 4 5 - 6 7 8 9` matches; `My SSN is 123-45-6789` still works).
- **Base64 / URL-encoded** payloads are extracted and scanned in addition to the canonical stream (bounded recursion, length-gated, ASCII-printable round-trip required).

Every pattern match carries a `view` field (`normalized` / `compact` / `decoded-base64` / `decoded-url`) and best-effort original-content anchoring so you can audit which canonicalization surfaced each match. Findings that do not come from a pattern match have no `view`: Guard findings, `POLICY_DENY` / `POLICY_WARN`, `SUPPLY_CHAIN_ALERT` and `FLEET_ANOMALY_ELEVATED`. The CLI's `--json` output prints `"view": null` for them. Each CLI finding also carries `line` and `column`, 1-based positions in the original input; a `decoded-base64` or `decoded-url` finding points at the start of the encoded token it was decoded from, and a finding without a `view`, such as a Guard finding, prints `"line": null, "column": null`.

## What this package does NOT detect

For full threat-model scope see [SECURITY.md](../SECURITY.md). The honest list:

- **Semantic / contextual violations.** A request to "summarize all our user emails" is not a regex hit. The semantic Guard layer targets these, but it is a preview: the NanoMind model has shipped and `@nanomind/daemon` serves it, yet it over-flags benign text (see [Guard status](semantic-guard.md#guard-status-preview-not-production-ready)). The Guard is off unless a daemon is running; when none is reachable over HTTP, `comply()` falls back silently to regex-only.
- **Cyrillic / Greek look-alikes that are not NFKC-equivalent** (e.g. Cyrillic small letter a at U+0430 vs Latin `a` at U+0061). Those are separate semantic letters; NFKC does not fold them.
- **Soft hyphen (U+00AD) and combining marks.** Not stripped from the normalized stream. An attacker can still hide PII by injecting these characters between digits.
- **Encodings other than Base64 and URL.** Hex, base32, ROT13, HTML entities, quoted-printable are not decoded.
- **All-letter alphanumeric MRN identifiers** (e.g. UK NHS ULN-style). The MRN regex requires at least one digit, trading recall on all-letter clinical identifiers for precision on prose mentions ("MRN system was updated"). Custom regex needed for those domains.
- **Steganography and natural-language paraphrasing of sensitive content.** Requires the semantic layer.
