# Verdicts and per-classifier results

## Verdict semantics

- **`CLEAN`**: no findings from the layers that ran (`result.layers` lists them). This states what was checked, not that the content is safe: an input the layers do not detect is `CLEAN` too (see [What this package does NOT detect](detection.md#what-this-package-does-not-detect)). On high-stakes paths, treat it as advisory ([hardening checklist](../SECURITY.md#hardening-checklist-for-consumers))
- **`VIOLATION`**: one or more findings; the `violations` array is the audit trail. A pattern the regex engine could not run on the content is a finding as well, `PATTERN_NOT_EVALUATED:<id>`, and its id is listed in `result.unevaluatedPatterns`, so such content is never `CLEAN`
- **`DENY`**: hard block (a policy pack triggered, supply-chain Registry said the source package is untrusted, or `onRegistryUnknown: 'deny'` met a Registry lookup of `miss`, `partial` or `error` for the source package); treat as fatal

## Inspecting per-classifier results

Every result also carries a `classifierResults` mirror with each layer's raw verdict, useful for debugging or logging which layer fired:

```typescript
const result = await comply({ content });

result.classifierResults.regex; // { classifier: 'regex', verdict, violations }
result.classifierResults.guard; // defined when GuardClient was reachable
result.layers;                  // ['normalize', 'regex'], plus 'guard' when a Guard result was accepted
result.pack;                    // { version, sha256 }: the pattern pack the regex layer ran
result.unevaluatedPatterns;     // set when the regex engine could not run a pattern: the pattern ids
```

`layers` never lists `guard` on the regex-only fallback or when a supplied Guard signature is rejected. It is `[]` for empty content, which is not classified, or `['guard']` when a signed Guard result passed with it is accepted; a supplied Guard result is verified for empty content as for any other. `pack` equals `{ version: PACK_VERSION, sha256: PACK_SHA256 }`.

Treat `verdict` and `violations` as the stable contract; `classifierResults`, `originalContent`, `normalizedContent`, `normalizations`, `layers`, `pack` and `unevaluatedPatterns` are introspection hooks.
