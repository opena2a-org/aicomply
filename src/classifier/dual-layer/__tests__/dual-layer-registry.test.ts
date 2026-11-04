/**
 * Tests for Registry L2 threshold/block logic in classifyDualLayer.
 *
 * The rules (AC-002, AC-005):
 *   - fleetAnomalySignal > 0.30 => threshold -= 0.15 => CLEAN -> VIOLATION
 *   - Any active supply-chain alert on package => hard DENY
 *   - Cache miss => unknown (AC-002), verdict unchanged, signals recorded
 *   - registrySignals.status tells hit, miss and error apart
 *   - A partial lookup (no alert on a page that is not complete for the
 *     package) is unknown as a miss is, carries the page figures, and keeps
 *     the fleet anomaly threshold
 *   - onRegistryUnknown => miss / partial / error becomes VIOLATION or DENY,
 *     and never lowers a DENY the classifiers reached
 *   - An empty source package name is a lookup error
 *   - No registry options => L2 not applied
 */

import { classifyDualLayer } from '..';
import { RegistryIntelligenceCache } from '../../../registry';
import type { FleetAnomalySignal, SupplyChainAlert } from '../../../registry';
import {
  generateTestKeyPair,
  signGuardResult,
  makeVerifyOptions,
} from '../../../arp/__tests__/test-helpers';

// ---------------------------------------------------------------------------
// Helpers to mock the registry cache
// ---------------------------------------------------------------------------
function makeCache(lookupResult: ReturnType<RegistryIntelligenceCache['lookup']>): RegistryIntelligenceCache {
  const cache = new RegistryIntelligenceCache();
  jest.spyOn(cache, 'lookup').mockReturnValue(lookupResult);
  return cache;
}

const SAFE_CONTENT = 'This is safe content with no PII.';

const ALERT: SupplyChainAlert = {
  id: 'sca-status',
  name: 'known-pkg',
  type: 'library',
  severity: 'high',
  reason: 'Status test',
  publishedAt: '2026-04-14T00:00:00Z',
};

function hitWith(alerts: SupplyChainAlert[]): ReturnType<RegistryIntelligenceCache['lookup']> {
  return {
    status: 'hit',
    intelligence: {
      packageName: 'known-pkg',
      fleetAnomalySignal: null,
      supplyChainAlerts: alerts,
      fetchedAt: Date.now(),
    },
  };
}

/** The figures of a page cut from a larger population: 1,000 alerts of 14,002. */
const CUT_PAGE = {
  reason: 'the page holds 1000 of 14002 alerts',
  alertsHeld: 1000,
  total: 14002,
  limit: 1000,
  producerState: 'current',
};

/** The lookup for a package with no alert on that page. */
function partialWith(fleetAnomalySignal: FleetAnomalySignal | null): ReturnType<RegistryIntelligenceCache['lookup']> {
  return { status: 'partial', fleetAnomalySignal, supplyChainPage: CUT_PAGE };
}

const ELEVATED_SIGNAL: FleetAnomalySignal = {
  name: 'suspicious-agent',
  type: 'mcp_server',
  anomalyScore: 0.55,   // above threshold
  eventCount: 12,
  lastSeenAt: '2026-04-14T00:00:00Z',
  formulaVersion: '1.0',
  stale: false,
};

afterEach(() => {
  jest.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Registry L2: no registry options', () => {
  it('L2 not applied when no registryCache provided', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT);
    expect(result.registrySignals).toBeUndefined();
    expect(result.verdict).toBe('CLEAN');
  });
});

describe('Registry L2: fleet anomaly threshold', () => {
  it('CLEAN content stays CLEAN when anomalyScore <= 0.30', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'test-agent',
        fleetAnomalySignal: {
          name: 'test-agent',
          type: 'mcp_server',
          anomalyScore: 0.30,   // at threshold, NOT above
          eventCount: 1,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.thresholdDelta).toBe(0);
    expect(result.registrySignals?.fleetAnomalyScore).toBe(0.30);
  });

  it('CLEAN content promoted to VIOLATION when anomalyScore > 0.30', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'suspicious-agent',
        fleetAnomalySignal: {
          name: 'suspicious-agent',
          type: 'mcp_server',
          anomalyScore: 0.55,   // above threshold
          eventCount: 12,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'suspicious-agent',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
    expect(result.registrySignals?.fleetAnomalyScore).toBe(0.55);
    expect(result.violations.some(v => v.type === 'FLEET_ANOMALY_ELEVATED')).toBe(true);
  });

  it('already-VIOLATION stays VIOLATION (anomaly adds signal but does not double-count)', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'test-agent',
        fleetAnomalySignal: {
          name: 'test-agent',
          type: 'library',
          anomalyScore: 0.80,
          eventCount: 3,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    // Content with SSN => already VIOLATION from regex
    const result = await classifyDualLayer('SSN: 123-45-6789', {
      registryCache: cache,
      sourcePackage: 'test-agent',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
    // FLEET_ANOMALY_ELEVATED violation not added because base was already VIOLATION
    expect(result.violations.some(v => v.type === 'FLEET_ANOMALY_ELEVATED')).toBe(false);
  });
});

describe('Registry L2: supply-chain hard block', () => {
  it('issues DENY when active supply-chain alert exists (regardless of content)', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'compromised-agent',
        fleetAnomalySignal: null,
        supplyChainAlerts: [{
          id: 'alert-99',
          name: 'compromised-agent',
          type: 'library',
          severity: 'critical',
          reason: 'Malicious code injected in v2.3.1',
          publishedAt: '2026-04-13T00:00:00Z',
        }],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'compromised-agent',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
    expect(result.violations.some(v => v.type === 'SUPPLY_CHAIN_ALERT')).toBe(true);
  });

  it('supply-chain block overrides anomaly threshold signal', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'bad-agent',
        fleetAnomalySignal: {
          name: 'bad-agent',
          type: 'skill',
          anomalyScore: 0.95,
          eventCount: 50,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [{
          id: 'sca-007',
          name: 'bad-agent',
          type: 'skill',
          severity: 'high',
          reason: 'Typosquatting',
          publishedAt: '2026-04-14T00:00:00Z',
        }],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'bad-agent',
    });

    // Supply-chain takes priority => DENY
    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
  });
});

describe('Registry L2: AC-002 unknown/miss handling', () => {
  it('records unknown signals on cache miss, does not clear existing verdict', async () => {
    const cache = makeCache({ status: 'miss' });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'unknown-pkg',
    });

    // Verdict is unchanged (CLEAN content stays CLEAN)
    expect(result.verdict).toBe('CLEAN');
    // But signals note the miss
    expect(result.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(result.registrySignals?.supplyChainBlock).toBe(false);
    expect(result.registrySignals?.packageName).toBe('unknown-pkg');
  });

  it('records unknown signals on cache error', async () => {
    const cache = makeCache({ status: 'error', reason: 'registry cache not warmed' });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'some-pkg',
    });

    expect(result.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(result.registrySignals?.packageName).toBe('some-pkg');
  });
});

describe('Registry L2: registrySignals.status names the lookup outcome', () => {
  it('reports miss and error apart, and neither as a hit', async () => {
    const miss = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache({ status: 'miss' }),
      sourcePackage: 'any-package',
    });
    const error = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache({ status: 'error', reason: 'registry cache not warmed' }),
      sourcePackage: 'any-package',
    });

    expect(miss.registrySignals?.status).toBe('miss');
    expect(error.registrySignals?.status).toBe('error');
    expect(miss.registrySignals).not.toEqual(error.registrySignals);
  });

  it('reports hit when the Registry has the package and nothing against it', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(hitWith([])),
      sourcePackage: 'known-pkg',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.status).toBe('hit');
  });

  it('reports hit on a supply-chain block', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(hitWith([ALERT])),
      sourcePackage: 'known-pkg',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('hit');
  });
});

describe('Registry L2: onRegistryUnknown', () => {
  const unknowns: Array<[string, ReturnType<RegistryIntelligenceCache['lookup']>]> = [
    ['miss', { status: 'miss' }],
    ['partial', partialWith(null)],
    ['error', { status: 'error', reason: 'registry cache not warmed' }],
  ];

  it.each(unknowns)('%s: the verdict stays as classified when unset', async (_status, lookup) => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(lookup),
      sourcePackage: 'any-package',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toHaveLength(0);
  });

  it.each(unknowns)("%s: becomes VIOLATION with 'violation'", async (status, lookup) => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(lookup),
      sourcePackage: 'any-package',
      onRegistryUnknown: 'violation',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.status).toBe(status);
    expect(result.violations.filter(v => v.type === 'REGISTRY_UNKNOWN')).toEqual([
      expect.objectContaining({ value: `status=${status}`, confidence: 1.0 }),
    ]);
  });

  it.each(unknowns)("%s: becomes DENY with 'deny'", async (status, lookup) => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(lookup),
      sourcePackage: 'any-package',
      onRegistryUnknown: 'deny',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe(status);
    expect(result.violations.some(v => v.type === 'REGISTRY_UNKNOWN')).toBe(true);
    // Every DENY drops the content echo, whatever raised it.
    expect(result.originalContent).toBeUndefined();
    expect(result.normalizedContent).toBeUndefined();
  });

  it('keeps the classifier findings beside the Registry one', async () => {
    const result = await classifyDualLayer('SSN: 123-45-6789', {
      registryCache: makeCache({ status: 'miss' }),
      sourcePackage: 'any-package',
      onRegistryUnknown: 'violation',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.some(v => v.type === 'SSN')).toBe(true);
    expect(result.violations.some(v => v.type === 'REGISTRY_UNKNOWN')).toBe(true);
  });

  it.each(['violation', 'deny'] as const)('does not touch a hit with %s', async (action) => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(hitWith([])),
      sourcePackage: 'known-pkg',
      onRegistryUnknown: action,
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toHaveLength(0);
  });

  it('counts a source package with no Registry cache to look it up in as an error', async () => {
    const unset = await classifyDualLayer(SAFE_CONTENT, { sourcePackage: 'any-package' });
    expect(unset.verdict).toBe('CLEAN');
    expect(unset.registrySignals).toBeUndefined();

    const deny = await classifyDualLayer(SAFE_CONTENT, {
      sourcePackage: 'any-package',
      onRegistryUnknown: 'deny',
    });
    expect(deny.verdict).toBe('DENY');
    expect(deny.registrySignals?.status).toBe('error');
    expect(deny.registrySignals?.packageName).toBe('any-package');
    expect(deny.violations.some(v => v.type === 'REGISTRY_UNKNOWN')).toBe(true);
  });

  it('counts an empty source package name as an error, not as no source package', async () => {
    const cache = makeCache(hitWith([]));

    const deny = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: '',
      onRegistryUnknown: 'deny',
    });
    expect(deny.verdict).toBe('DENY');
    expect(deny.registrySignals?.status).toBe('error');
    expect(deny.registrySignals?.packageName).toBe('');
    expect(cache.lookup).not.toHaveBeenCalled();

    const noCache = await classifyDualLayer(SAFE_CONTENT, {
      sourcePackage: '',
      onRegistryUnknown: 'violation',
    });
    expect(noCache.verdict).toBe('VIOLATION');
    expect(noCache.registrySignals?.status).toBe('error');

    // Unset, the empty name is reported and the verdict is left alone.
    const unset = await classifyDualLayer(SAFE_CONTENT, { registryCache: cache, sourcePackage: '' });
    expect(unset.verdict).toBe('CLEAN');
    expect(unset.registrySignals?.status).toBe('error');
  });

  it('rejects a source package that is not a string', async () => {
    await expect(
      classifyDualLayer(SAFE_CONTENT, {
        sourcePackage: 0 as unknown as string,
        onRegistryUnknown: 'deny',
      }),
    ).rejects.toThrow(/sourcePackage must be a string \(got number\)/);
  });

  it("keeps a DENY the classifiers reached with 'violation'", async () => {
    // A Guard result signed by a key the verifier does not trust is
    // parse-to-deny (CR-001), so the classifiers reach DENY before the
    // Registry step; 'violation' must not lower it.
    const trusted = generateTestKeyPair();
    const untrusted = generateTestKeyPair();
    const result = await classifyDualLayer(SAFE_CONTENT, {
      guardResult: signGuardResult(untrusted, 'documentation', SAFE_CONTENT),
      guardVerifyOptions: makeVerifyOptions(trusted),
      registryCache: makeCache({ status: 'miss' }),
      sourcePackage: 'any-package',
      onRegistryUnknown: 'violation',
    });

    expect(result.signatureValid).toBe(false);
    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('miss');
    expect(result.violations.some(v => v.type === 'REGISTRY_UNKNOWN')).toBe(true);
  }, 30000);

  it('has nothing to look up without a source package', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache({ status: 'miss' }),
      onRegistryUnknown: 'deny',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals).toBeUndefined();
  });

  it('rejects a value that is neither action, so a typo cannot pass as unset', async () => {
    await expect(
      classifyDualLayer(SAFE_CONTENT, {
        registryCache: makeCache({ status: 'miss' }),
        sourcePackage: 'any-package',
        onRegistryUnknown: 'block' as unknown as 'deny',
      }),
    ).rejects.toThrow(/onRegistryUnknown must be 'violation' or 'deny' \(got "block"\)/);
  });
});

describe('Registry L2: no fleet signal but no supply-chain alert', () => {
  it('returns CLEAN when fleet signal is null and no alerts', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'known-safe-agent',
        fleetAnomalySignal: null,
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'known-safe-agent',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(result.registrySignals?.thresholdDelta).toBe(0);
    expect(result.registrySignals?.supplyChainBlock).toBe(false);
  });
});

describe('Registry L2: a partial alert page', () => {
  it('reports partial with the page figures, not a hit, and leaves the verdict as classified', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(partialWith(null)),
      sourcePackage: 'any-package',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toHaveLength(0);
    expect(result.registrySignals).toEqual({
      status: 'partial',
      fleetAnomalyScore: null,
      effectiveAnomalyScore: null,
      trustSensitivityMultiplier: 1.0,
      thresholdDelta: 0,
      supplyChainBlock: false,
      packageName: 'any-package',
      supplyChainPage: CUT_PAGE,
    });
  });

  it('keeps the fleet anomaly threshold: a score above 0.30 raises CLEAN to VIOLATION', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(partialWith(ELEVATED_SIGNAL)),
      sourcePackage: 'suspicious-agent',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.map(v => v.type)).toEqual(['FLEET_ANOMALY_ELEVATED']);
    expect(result.registrySignals?.status).toBe('partial');
    expect(result.registrySignals?.fleetAnomalyScore).toBe(0.55);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.55);
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
    expect(result.registrySignals?.supplyChainBlock).toBe(false);
    expect(result.registrySignals?.supplyChainPage).toEqual(CUT_PAGE);
  });

  it("adds the Registry finding to the fleet one with onRegistryUnknown: 'deny'", async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(partialWith(ELEVATED_SIGNAL)),
      sourcePackage: 'suspicious-agent',
      onRegistryUnknown: 'deny',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.violations.map(v => [v.type, v.value])).toEqual([
      ['FLEET_ANOMALY_ELEVATED', 'anomalyScore=0.55,effectiveScore=0.55'],
      ['REGISTRY_UNKNOWN', 'status=partial'],
    ]);
  });

  it('blocks a package whose alert is on a partial page: a hit with alerts is DENY', async () => {
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: makeCache(hitWith([ALERT])),
      sourcePackage: 'known-pkg',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('hit');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
    expect(result.registrySignals?.supplyChainPage).toBeUndefined();
  });
});

describe("Registry L2: a listed package's own alert answer, read by name and type when the cache warms", () => {
  const REGISTRY_URL = 'https://registry.invalid';
  const sourcePackages = [
    { name: 'calm-agent', type: 'mcp_server' },
    { name: 'quiet-agent', type: 'mcp_server' },
  ];

  /**
   * Answer every Registry request in process, as the production Registry
   * does; no request leaves the process. The anomaly-signal request that
   * names no package is refused with 400, and the one that names a package
   * and a type gets an anomaly score of 0.1 for calm-agent and no events for
   * any other package. The unfiltered alert request gets the measured page:
   * 1,000 alerts for other packages, of a total of 14,002. The alert request
   * that names a package and a type gets a complete answer for that package,
   * carrying `own(name)`.
   */
  function registryInProcess(own: (name: string) => SupplyChainAlert[]): void {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input));
      const name = url.searchParams.get('name');
      if (url.origin !== REGISTRY_URL) {
        throw new TypeError('fetch failed');
      }
      if (url.pathname === '/api/v1/registry/fleet/anomaly-signal') {
        const type = url.searchParams.get('type');
        if (!name || !type) {
          return new Response(JSON.stringify({ error: 'name and type query params are required' }), { status: 400 });
        }
        const calm = name === 'calm-agent';
        return new Response(JSON.stringify({
          name,
          type,
          anomalyScore: calm ? 0.1 : 0,
          windowHours: 24,
          eventCount: calm ? 3 : 0,
          lastSeenAt: calm ? '2026-10-18T00:00:00Z' : null,
          formulaVersion: 'v1',
          stale: false,
        }));
      }
      if (url.pathname === '/api/v1/intelligence/alerts') {
        const packageType = url.searchParams.get('packageType');
        if (name && packageType) {
          const alerts = own(name);
          return new Response(JSON.stringify({
            alerts,
            total: alerts.length,
            population: { name, packageType },
            limit: 1000,
            producer: { state: 'current' },
          }));
        }
        const alerts = Array.from({ length: 1000 }, (_, i) => ({ ...ALERT, id: `other-${i}`, name: `other-package-${i}` }));
        return new Response(JSON.stringify({
          alerts,
          total: 14002,
          population: { name: null, packageType: null },
          limit: 1000,
          producer: { state: 'current' },
        }));
      }
      throw new TypeError('fetch failed');
    });
  }

  it('blocks a listed package absent from the measured page whose own answer carries one alert row, under the rule in force: any active supply-chain alert on the source package is a hard block (DENY)', async () => {
    const own: SupplyChainAlert = { ...ALERT, id: 'sca-own', name: 'calm-agent', type: 'mcp_server' };
    registryInProcess(name => (name === 'calm-agent' ? [own] : []));
    const cache = new RegistryIntelligenceCache({ baseUrl: REGISTRY_URL, sourcePackages });
    await cache.warm();

    const result = await classifyDualLayer(SAFE_CONTENT, { registryCache: cache, sourcePackage: 'calm-agent' });

    expect(result.verdict).toBe('DENY');
    expect(result.violations.map(v => [v.type, v.value])).toEqual([['SUPPLY_CHAIN_ALERT', 'sca-own']]);
    expect(result.registrySignals?.status).toBe('hit');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
    expect(result.registrySignals?.supplyChainPage).toBeUndefined();
  });

  it('takes the negative from a complete own answer with a total of 0, and adds no REGISTRY_UNKNOWN', async () => {
    registryInProcess(() => []);
    const cache = new RegistryIntelligenceCache({ baseUrl: REGISTRY_URL, sourcePackages });
    await cache.warm();

    const calm = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'calm-agent',
      onRegistryUnknown: 'deny',
    });
    const quiet = await classifyDualLayer(SAFE_CONTENT, { registryCache: cache, sourcePackage: 'quiet-agent' });

    // A hit with no alert and an anomaly score of 0.1: nothing for 'deny' to act on.
    expect(calm.verdict).toBe('CLEAN');
    expect(calm.violations).toEqual([]);
    expect(calm.registrySignals?.status).toBe('hit');
    expect(calm.registrySignals?.fleetAnomalyScore).toBe(0.1);
    expect(calm.registrySignals?.supplyChainBlock).toBe(false);
    expect(calm.registrySignals?.supplyChainPage).toBeUndefined();
    // No anomaly events for the package: a miss, which leaves the verdict as classified.
    expect(quiet.verdict).toBe('CLEAN');
    expect(quiet.registrySignals?.status).toBe('miss');
    expect(quiet.registrySignals?.supplyChainPage).toBeUndefined();
  });
});
