# Audit trail

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
> keeps none of its leading characters. At 8 characters or fewer it is fully
> starred, at 9 to 12 it reads `...` and its last 2 characters (`...89` for
> `123-45-6789`), and at 13 or more `...` and its last 4. A Guard finding reads
> `***GUARD***`.
