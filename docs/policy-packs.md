# Policy packs (optional)

A policy pack acts on the violation types in a result. A `DENY` rule whose `patterns` name one of them sets the verdict to `DENY` and appends `POLICY_DENY:<rule id>`; a `WARN` rule appends `POLICY_WARN:<rule id>` and leaves the verdict alone. `REDACT` rules are not applied yet. Pass your own pack as `policyPack` on the second argument:

```typescript
const result = await comply(
  { content: agentInput },
  {
    policyPack: {
      name: 'my-pack',
      version: '1.0.0',
      rules: [
        { id: 'no-ssn', name: 'No SSN', description: 'Block SSNs', patterns: ['SSN'], action: 'DENY', severity: 'critical' },
      ],
    },
  },
);
```

`policyPack` on the first argument takes the name of a built-in pack instead. `'default'` is the only one: it denies `SSN`, `PAN`, `CREDENTIAL`, `CUI`, `IBAN` and `MRN` findings and warns on `NPI`. A name there is used in place of a pack on the second argument. Any other name and a pack object on the first argument are rejected with a `TypeError`. So is a pack on the second argument that is not an object, whose `rules` is not an array, or that has a rule that is not an object or whose `action` is not `DENY`, `REDACT` or `WARN` (a lower-case `'deny'` included). A rule other than a `REDACT` rule also needs an `id` that is a non-empty string and `patterns` that is an array of strings with no empty slots. The error lists the first ten problems with the pack and counts the rest. A pack with no `name` or `version`, or with an empty `rules` array, is applied.

`validatePolicyConfig()` returns every problem with a pack, one message each. That includes the ones the error leaves out, a missing `name` or `version`, an empty `rules` array, and a `REDACT` rule's missing or invalid `id` and `patterns`, which comply() does not read. A message names a rule by its `id` in quotes, or by its index when the `id` is not a non-empty string:

```typescript
import { validatePolicyConfig } from '@opena2a/aicomply';

validatePolicyConfig({ name: 'p', version: '1', rules: [{ action: 'REDACT' }] });
// ['Rule 0: missing id', 'Rule 0: patterns must be an array of strings']

validatePolicyConfig({ name: 'p', version: '1', rules: [{ id: 'block-ssn', action: 'deny', patterns: ['SSN'] }] });
// ["Rule 'block-ssn': invalid action 'deny', expected one of DENY, REDACT, WARN"]
```
