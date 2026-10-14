# Measured accuracy

Per-class precision and recall against the synthetic corpus at [`bench/corpus/`](../bench/corpus) (200 positives + 200 hard-negatives per class, including adversarial variants):

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
