# Enabling the semantic Guard

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

## What the Guard attempt sends

`comply()` attempts the Guard whether or not a daemon is running. For each non-empty input (empty and whitespace-only input is not sent), unless a signed Guard result is supplied, it makes one request, `POST http://127.0.0.1:47200/v1/infer`, with the input verbatim in the JSON body:

```json
{"intent":"INTENT_CHECK","input":"My SSN is 123-45-6789."}
```

The address is loopback, so the request does not leave the host, and with nothing listening on port 47200 the connection is refused and the result is regex-only. A local process other than the daemon that holds the port receives every classified input all the same. A signed Guard result passed in the second argument as `guardResult` with `guardVerifyOptions` is verified instead, and no request is made.

To make no request, pass `useGuard: false`:

```typescript
const result = await comply({ content, useGuard: false });

result.layers; // ['normalize', 'regex'] - regex-only, nothing was sent
```

`comply(content, { useGuard: false })`, `classifyDualLayer()` and `ClassificationSession.comply()` take the same option, which matches `use_guard=False` in the Python package. A value that is not a boolean is rejected with a `TypeError`.

## Guard status: preview, not production-ready

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
on by default, needs no daemon, and carries the [measured accuracy](accuracy.md). Leave the
Guard off (the default whenever no daemon is running) for production filtering until
a recalibrated model ships; enable it only for evaluation.

When you do enable it for evaluation, the wiring is correct end-to-end: a true
`prompt_injection` or `tool_misuse` input surfaces as a `classifierResults.guard`
violation alongside the independent regex result. Recalibrating the model's benign
false-positive rate is tracked as the gating work before the Guard is recommended.
