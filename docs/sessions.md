# Session-scoped use (optional)

For long-lived agents that want fleet-anomaly thresholds and supply-chain hard-block intelligence from the OpenA2A Registry:

```typescript
import { ClassificationSession } from '@opena2a/aicomply';

const session = await ClassificationSession.create({
  // The packages to fetch the fleet anomaly signal for, each with its Registry type.
  sourcePackages: [{ name: 'my-agent-name', type: 'mcp_server' }],
});

const result = await session.comply({
  content: agentInput,
  sourcePackage: 'my-agent-name',
});
```

The cache warms once on `create()`: it fetches the supply-chain alert list, the fleet index, and the fleet anomaly signal of each package in `sourcePackages`, one request per package with its name and type in the query. A package may be listed once; names are compared without case. Subsequent `comply()` calls make no Registry request (contract AC-005 in [SECURITY.md](../SECURITY.md)). `session.comply()` takes the arguments `comply()` takes, a bare string included: `session.comply('text')`. `guardOptions` passed on either argument is used in place of the session's, and so is a `registryCache` passed on the first; a `registryCache` on the second argument is not used, and the session's cache is looked up instead. Each call still makes the Guard request described in [What the Guard attempt sends](semantic-guard.md#what-the-guard-attempt-sends) unless you pass `useGuard: false`.

A package first seen after `create()` is added with `session.addSourcePackages()`, which takes a list of the same form. It requests the fleet anomaly signal of each package that is not listed yet, one request per package as above, and resolves once each request has been answered or has failed. From then on the package is listed, and a refresh started by `session.refreshCache()` requests it too. A package listed already is not requested again, and a name listed already with another type is rejected with a `TypeError`. `comply()` makes no Registry request, so add a package before you classify its input:

```typescript
await session.addSourcePackages([{ name: 'other-agent', type: 'ai_tool' }]);

const later = await session.comply({
  content: agentInput,
  sourcePackage: 'other-agent',
});
```

A cache from `warmRegistryCache()` has the same `addSourcePackages()` method.

`result.registrySignals.status` says what the Registry had for the package: `hit`, `miss` (not in the index) or `error` (the index did not load, for example because the Registry was unreachable). A package with an alert in the loaded supply-chain alert list is a `hit` and gets `DENY`, also when the fleet index did not load. The production Registry refuses the fleet index request, which names no package, and answers the request that names a package and its type (checked 2026-10-18). Against it, only a listed package has a fleet signal, one in `sourcePackages` or added with `addSourcePackages()`: it is a `hit` when the Registry reports fleet events for it, and, without an alert, a `miss` when it reports none, as it does for a package it has no record of. A package with no alert that is not listed is an `error`. A `miss` or an `error` leaves the verdict as the classifiers set it. To fail closed, pass `onRegistryUnknown`:

```typescript
const result = await session.comply({
  content: agentInput,
  sourcePackage: 'my-agent-name',
  onRegistryUnknown: 'deny', // or 'violation'
});
```

Either value appends a `REGISTRY_UNKNOWN` violation (contract AC-002). The lookup runs for empty content as well, and a [policy pack](policy-packs.md) is applied to what it finds; an empty `sourcePackage` counts as an `error`.
