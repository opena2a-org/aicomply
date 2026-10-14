# How it works

`aicomply` is an inline check between "tool returned content" and "send to model," which most agent stacks lack even though every agent that calls a hosted LLM (Anthropic, OpenAI, Bedrock, Vertex, …) copies the conversation - system prompt, tool outputs, retrieved documents, user input - into a third party's logs. If your agent reads a support ticket containing an SSN, that SSN goes to the provider. If your agent reads `.env` to summarize it, your AWS key goes too.

It runs inline. With no Guard daemon running, the default, only the regex layer runs, and that layer is sub-millisecond; with a daemon reachable, a call also waits for the Guard layer. You hand it the content; it returns a verdict (`CLEAN` / `VIOLATION` / `DENY`) and structured findings. You decide what to do next - block, redact, log, or pass.

Two detection layers run one after the other, the regex layer first and then the Guard layer, so a call takes the sum of their latencies:

- A deterministic **regex layer** with adversarial-mutation handling (NFKC homoglyph folding, zero-width strip, targeted whitespace compaction, bounded Base64/URL decode). Always on, ~sub-ms.
- An optional **semantic Guard layer (preview)** powered by [NanoMind](https://huggingface.co/opena2a/nanomind-security-classifier). It targets prompt-injection, tool-misuse, data-extraction, and exfiltration patterns the regex layer can't see. The current model has a high benign false-positive rate and is **not yet production-ready** - see [Guard status](semantic-guard.md#guard-status-preview-not-production-ready). Active only when `@nanomind/daemon` is running locally; aicomply runs regex-only otherwise.

The Guard attempt is the one network request `comply()` makes. For each non-empty input, unless a signed Guard result is supplied, it POSTs the input verbatim to the loopback address `http://127.0.0.1:47200/v1/infer`, so the request stays on the host, and whichever local process holds that port receives the input. Pass `useGuard: false` to make no request - see [What the Guard attempt sends](semantic-guard.md#what-the-guard-attempt-sends).
