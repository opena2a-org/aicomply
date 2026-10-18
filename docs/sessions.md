# Session-scoped use (optional)

For long-lived agents that want fleet-anomaly thresholds and supply-chain hard-block intelligence from the OpenA2A Registry:

```typescript
import { ClassificationSession } from '@opena2a/aicomply';

const session = await ClassificationSession.create();

const result = await session.comply({
  content: agentInput,
  sourcePackage: 'my-agent-name',
});
```

The cache warms once on `create()`. Subsequent `comply()` calls make no Registry request (contract AC-005 in [SECURITY.md](../SECURITY.md)). `session.comply()` takes the arguments `comply()` takes, a bare string included: `session.comply('text')`. `guardOptions` passed on either argument is used in place of the session's, and so is a `registryCache` passed on the first; a `registryCache` on the second argument is not used, and the session's cache is looked up instead. Each call still makes the Guard request described in [What the Guard attempt sends](semantic-guard.md#what-the-guard-attempt-sends) unless you pass `useGuard: false`.

`result.registrySignals.status` says what the Registry had for the package: `hit`, `miss` (not in the index) or `error` (the index did not load, for example because the Registry was unreachable). A package with an alert in the loaded supply-chain alert list is a `hit` and gets `DENY`, also when the fleet index did not load. The production Registry refuses the fleet request this version sends (checked 2026-10-18), so against it the fleet index does not load and a package with no alert is an `error`. A `miss` or an `error` leaves the verdict as the classifiers set it. To fail closed, pass `onRegistryUnknown`:

```typescript
const result = await session.comply({
  content: agentInput,
  sourcePackage: 'my-agent-name',
  onRegistryUnknown: 'deny', // or 'violation'
});
```

Either value appends a `REGISTRY_UNKNOWN` violation (contract AC-002). The lookup runs for empty content as well, and a [policy pack](policy-packs.md) is applied to what it finds; an empty `sourcePackage` counts as an `error`.
