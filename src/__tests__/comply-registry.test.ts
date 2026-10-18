/**
 * Tests for comply() public API with Registry L2 integration and the
 * ClassificationSession / warmRegistryCache warm-start lifecycle helpers.
 *
 * Coverage:
 *   - comply() threads sourcePackage + registryCache through to classifyDualLayer
 *   - Supply-chain hard block => DENY via comply()
 *   - Supply-chain hard block => DENY when the Registry refuses the fleet request
 *   - Fleet anomaly > 0.30 => VIOLATION via comply()
 *   - Fleet anomaly > 0.30 => VIOLATION for a package in sourcePackages when the
 *     Registry answers the fleet request only per package
 *   - Cache miss => signals present, verdict unchanged
 *   - Unreachable Registry and absent package => distinct registrySignals.status
 *   - onRegistryUnknown => miss / error becomes VIOLATION or DENY via comply()
 *   - Empty content and an empty source package name still get the lookup
 *   - comply() without registry options => no L2 signals
 *   - ClassificationSession.comply() uses session cache when caller omits registryCache
 *   - ClassificationSession.comply() respects caller-supplied registryCache override
 *     on the first argument, and uses the session cache in place of one on the second
 *   - ClassificationSession.comply() reads a content getter or an inherited content
 *   - comply() rejects binary data, a boxed primitive and a promise as the first argument
 *   - warmRegistryCache() returns a warmed RegistryIntelligenceCache
 */

import { comply, warmRegistryCache, ClassificationSession } from '..';
import { RegistryIntelligenceCache } from '../registry';
import type { ComplyOptions } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCache(
  lookupResult: ReturnType<RegistryIntelligenceCache['lookup']>,
): RegistryIntelligenceCache {
  const cache = new RegistryIntelligenceCache();
  jest.spyOn(cache, 'lookup').mockReturnValue(lookupResult);
  return cache;
}

const SAFE_CONTENT = 'This is safe content with no PII.';
const SSN_TEXT = 'My SSN is 123-45-6789.';

afterEach(() => {
  jest.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// comply() - no registry options
// ---------------------------------------------------------------------------

describe('comply(): input validation (v1.0 hardening)', () => {
  it('throws TypeError when content is not a string (number)', async () => {
    await expect(comply({ content: 123 as unknown as string })).rejects.toThrow(TypeError);
  });

  it('throws TypeError when content is not a string (object)', async () => {
    await expect(comply({ content: {} as unknown as string })).rejects.toThrow(TypeError);
  });

  it('throws TypeError when options is null', async () => {
    await expect(comply(null as unknown as ComplyOptions)).rejects.toThrow(TypeError);
  });

  it('returns CLEAN on missing content key (no throw, populated audit fields)', async () => {
    const r = await comply({} as ComplyOptions);
    expect(r.verdict).toBe('CLEAN');
    expect(r.originalContent).toBe('');
    expect(r.normalizedContent).toBe('');
    expect(r.normalizations).toEqual([]);
  });

  it('returns CLEAN on undefined content (allowed)', async () => {
    const r = await comply({ content: undefined as unknown as string });
    expect(r.verdict).toBe('CLEAN');
  });

  it('omits classifierResults.guard when Guard is unreachable (key absent, not undefined)', async () => {
    const r = await comply({ content: 'hello world' });
    expect('guard' in r.classifierResults).toBe(false);
    expect(r.classifierResults.regex).toBeDefined();
  });

  it('error message names the expected shape (comply({ content })), not "object"', async () => {
    // A non-string, non-options value (e.g. a number) should fail with a message
    // that tells the caller the actual shape, not the misleading "must be an object".
    await expect(comply(123 as unknown as ComplyOptions)).rejects.toThrow(/content/);
    await expect(comply(123 as unknown as ComplyOptions)).rejects.toThrow(TypeError);
  });
});

describe('comply(): bare-string convenience overload', () => {
  it('accepts a bare string and classifies it as if { content } were passed', async () => {
    const r = await comply('SSN: 123-45-6789');
    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations.some(v => v.type === 'SSN')).toBe(true);
    expect(r.originalContent).toBe('SSN: 123-45-6789');
  });

  it('accepts a bare empty string and returns CLEAN', async () => {
    const r = await comply('');
    expect(r.verdict).toBe('CLEAN');
    expect(r.violations).toHaveLength(0);
    expect(r.originalContent).toBe('');
  });

  it('a clean bare string returns CLEAN with the same shape as the object form', async () => {
    const bare = await comply('hello world');
    const obj = await comply({ content: 'hello world' });
    expect(bare.verdict).toBe('CLEAN');
    expect(bare.verdict).toBe(obj.verdict);
    expect('guard' in bare.classifierResults).toBe(false);
  });
});

describe('comply(): no registry options', () => {
  it('returns CLEAN with no registrySignals for safe content', async () => {
    const result = await comply({ content: SAFE_CONTENT });
    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals).toBeUndefined();
  });

  it('returns CLEAN for empty content', async () => {
    const result = await comply({ content: '' });
    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// comply() - supply-chain hard block
// ---------------------------------------------------------------------------

describe('comply(): supply-chain hard block via L2', () => {
  it('returns DENY when sourcePackage has an active supply-chain alert', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'compromised-pkg',
        fleetAnomalySignal: null,
        supplyChainAlerts: [{
          id: 'sca-001',
          name: 'compromised-pkg',
          type: 'library',
          severity: 'critical',
          reason: 'Malicious code injected in published version',
          publishedAt: '2026-04-13T00:00:00Z',
        }],
        fetchedAt: Date.now(),
      },
    });

    const result = await comply({
      content: SAFE_CONTENT,
      sourcePackage: 'compromised-pkg',
      registryCache: cache,
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
    expect(result.registrySignals?.packageName).toBe('compromised-pkg');
    expect(result.violations.some(v => v.type === 'SUPPLY_CHAIN_ALERT')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// comply() - fleet anomaly threshold promotion
// ---------------------------------------------------------------------------

describe('comply(): fleet anomaly threshold via L2', () => {
  it('promotes CLEAN to VIOLATION when anomalyScore > 0.30', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'suspicious-agent',
        fleetAnomalySignal: {
          name: 'suspicious-agent',
          type: 'mcp_server',
          anomalyScore: 0.55,
          eventCount: 10,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    const result = await comply({
      content: SAFE_CONTENT,
      sourcePackage: 'suspicious-agent',
      registryCache: cache,
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
    expect(result.registrySignals?.fleetAnomalyScore).toBe(0.55);
    expect(result.violations.some(v => v.type === 'FLEET_ANOMALY_ELEVATED')).toBe(true);
  });

  it('stays CLEAN when anomalyScore <= 0.30', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'ok-agent',
        fleetAnomalySignal: {
          name: 'ok-agent',
          type: 'library',
          anomalyScore: 0.20,
          eventCount: 5,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    const result = await comply({
      content: SAFE_CONTENT,
      sourcePackage: 'ok-agent',
      registryCache: cache,
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.thresholdDelta).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// comply() - cache miss (AC-002)
// ---------------------------------------------------------------------------

describe('comply(): cache miss handling', () => {
  it('records signals on cache miss without changing CLEAN verdict', async () => {
    const cache = makeCache({ status: 'miss' });

    const result = await comply({
      content: SAFE_CONTENT,
      sourcePackage: 'unknown-agent',
      registryCache: cache,
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(result.registrySignals?.supplyChainBlock).toBe(false);
    expect(result.registrySignals?.packageName).toBe('unknown-agent');
  });

  it('records signals on cache error without changing verdict', async () => {
    const cache = makeCache({ status: 'error', reason: 'registry cache not warmed' });

    const result = await comply({
      content: SAFE_CONTENT,
      sourcePackage: 'some-agent',
      registryCache: cache,
    });

    expect(result.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(result.registrySignals?.packageName).toBe('some-agent');
  });
});

// ---------------------------------------------------------------------------
// comply() - a package the Registry cannot vouch for (AC-002)
//
// These run the real cache against a stubbed fetch, so the status comes from
// what the Registry returned and not from a mocked lookup().
// ---------------------------------------------------------------------------

describe('comply(): a package the Registry cannot vouch for', () => {
  const BASE_URL = 'https://registry.invalid';

  /** Registry endpoints refuse the connection, as an unreachable host does. */
  function registryUnreachable(): void {
    jest.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fetch failed'));
  }

  /** Registry endpoints answer with empty indexes; every other URL refuses. */
  function registryEmpty(): void {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url === `${BASE_URL}/api/v1/registry/fleet/anomaly-signal`) {
        return new Response(JSON.stringify({ agents: [] }));
      }
      if (url === `${BASE_URL}/api/v1/intelligence/alerts?type=supply_chain`) {
        return new Response(JSON.stringify({ alerts: [], total: 0 }));
      }
      throw new TypeError('fetch failed');
    });
  }

  /**
   * Registry endpoints answer as production does: the fleet request, which
   * names no package, is refused with 400, and the alert list loads with one
   * alert for blocked-pkg. Every other URL refuses.
   */
  function registryRefusesFleetRequest(): void {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url === `${BASE_URL}/api/v1/registry/fleet/anomaly-signal`) {
        return new Response(JSON.stringify({ error: 'name and type query params are required' }), {
          status: 400,
        });
      }
      if (url === `${BASE_URL}/api/v1/intelligence/alerts?type=supply_chain`) {
        const alert = {
          id: 'sca-fleet-refused',
          name: 'blocked-pkg',
          type: 'mcp_server',
          severity: 'critical',
          reason: 'typosquatting',
          publishedAt: '2026-10-18T00:00:00Z',
        };
        return new Response(JSON.stringify({ alerts: [alert], total: 1 }));
      }
      throw new TypeError('fetch failed');
    });
  }

  it('blocks a package with a supply-chain alert when the Registry refuses the fleet request', async () => {
    registryRefusesFleetRequest();
    const session = await ClassificationSession.create({ baseUrl: BASE_URL });

    const blocked = await session.comply({ content: 'hello world', sourcePackage: 'blocked-pkg', useGuard: false });
    const other = await session.comply({ content: 'hello world', sourcePackage: 'any-package', useGuard: false });

    expect(blocked.verdict).toBe('DENY');
    expect(blocked.registrySignals?.status).toBe('hit');
    expect(blocked.registrySignals?.supplyChainBlock).toBe(true);
    expect(blocked.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(blocked.violations.map(v => v.type)).toEqual(['SUPPLY_CHAIN_ALERT']);
    expect(blocked.violations[0].value).toBe('sca-fleet-refused');
    // Without the fleet index, a package with no alert is still unknown.
    expect(other.verdict).toBe('CLEAN');
    expect(other.registrySignals?.status).toBe('error');
    expect(other.registrySignals?.supplyChainBlock).toBe(false);
  });

  /**
   * Registry endpoints answer as production does: the fleet request that
   * names no package is refused with 400, one that names a package and a
   * type gets that package's record (no fleet events for any package but
   * suspicious-agent), and the alert list loads empty. Every other URL
   * refuses.
   */
  function registryAnswersFleetPerPackage(): void {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input));
      if (`${url.origin}${url.pathname}` === `${BASE_URL}/api/v1/registry/fleet/anomaly-signal`) {
        const name = url.searchParams.get('name');
        const type = url.searchParams.get('type');
        if (!name || !type) {
          return new Response(JSON.stringify({ error: 'name and type query params are required' }), {
            status: 400,
          });
        }
        const events = name === 'suspicious-agent'
          ? { anomalyScore: 0.55, eventCount: 12, lastSeenAt: '2026-10-18T00:00:00Z' }
          : { anomalyScore: 0, eventCount: 0, lastSeenAt: null };
        return new Response(JSON.stringify({
          name,
          type,
          windowHours: 24,
          formulaVersion: 'v1',
          stale: false,
          ...events,
        }));
      }
      if (url.href === `${BASE_URL}/api/v1/intelligence/alerts?type=supply_chain`) {
        return new Response(JSON.stringify({ alerts: [], total: 0 }));
      }
      throw new TypeError('fetch failed');
    });
  }

  it('applies the fleet anomaly threshold to a package in sourcePackages when the Registry answers the fleet request only per package', async () => {
    registryAnswersFleetPerPackage();
    const session = await ClassificationSession.create({
      baseUrl: BASE_URL,
      sourcePackages: [
        { name: 'suspicious-agent', type: 'mcp_server' },
        { name: 'quiet-agent', type: 'mcp_server' },
      ],
    });

    const elevated = await session.comply({ content: 'hello world', sourcePackage: 'suspicious-agent', useGuard: false });
    const quiet = await session.comply({
      content: 'hello world',
      sourcePackage: 'quiet-agent',
      useGuard: false,
      onRegistryUnknown: 'deny',
    });
    const unlisted = await session.comply({ content: 'hello world', sourcePackage: 'any-package', useGuard: false });

    expect(elevated.verdict).toBe('VIOLATION');
    expect(elevated.registrySignals?.status).toBe('hit');
    expect(elevated.registrySignals?.fleetAnomalyScore).toBe(0.55);
    expect(elevated.violations.map(v => v.type)).toEqual(['FLEET_ANOMALY_ELEVATED']);
    // No fleet events for the package is no fleet data: it stays unknown, so
    // onRegistryUnknown: 'deny' still fails closed.
    expect(quiet.verdict).toBe('DENY');
    expect(quiet.registrySignals?.status).toBe('miss');
    expect(quiet.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
    expect(unlisted.verdict).toBe('CLEAN');
    expect(unlisted.registrySignals?.status).toBe('error');
  });

  it('tells an unreachable Registry from a package absent from its index', async () => {
    registryUnreachable();
    const down = await ClassificationSession.create({ baseUrl: BASE_URL });
    const unreachable = await down.comply({ content: 'hello world', sourcePackage: 'any-package' });
    jest.restoreAllMocks();

    registryEmpty();
    const up = await ClassificationSession.create({ baseUrl: BASE_URL });
    const absent = await up.comply({ content: 'hello world', sourcePackage: 'any-package' });

    expect(unreachable.registrySignals?.status).toBe('error');
    expect(absent.registrySignals?.status).toBe('miss');
    expect(unreachable.registrySignals).not.toEqual(absent.registrySignals);
    // Neither changes the verdict unless the caller asks for it.
    expect(unreachable.verdict).toBe('CLEAN');
    expect(absent.verdict).toBe('CLEAN');
  });

  it("fails closed on an unreachable Registry with onRegistryUnknown: 'deny'", async () => {
    registryUnreachable();
    const session = await ClassificationSession.create({ baseUrl: BASE_URL });

    const result = await session.comply({
      content: 'hello world',
      sourcePackage: 'any-package',
      onRegistryUnknown: 'deny',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('error');
    expect(result.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
  });

  it("flags a package absent from the index with onRegistryUnknown: 'violation'", async () => {
    registryEmpty();
    const session = await ClassificationSession.create({ baseUrl: BASE_URL });

    const result = await session.comply({
      content: 'hello world',
      sourcePackage: 'any-package',
      onRegistryUnknown: 'violation',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.status).toBe('miss');
    expect(result.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
  });

  it('rejects an onRegistryUnknown value that is neither action, with or without content', async () => {
    const bad = 'block' as unknown as 'deny';
    await expect(comply({ content: SAFE_CONTENT, onRegistryUnknown: bad })).rejects.toThrow(TypeError);
    await expect(comply({ content: '', onRegistryUnknown: bad })).rejects.toThrow(
      /onRegistryUnknown must be 'violation' or 'deny' \(got "block"\)/,
    );
  });

  it('rejects the same value passed in the second argument, with or without content', async () => {
    const bad = 'block' as unknown as 'deny';
    await expect(comply('', { onRegistryUnknown: bad })).rejects.toThrow(
      /onRegistryUnknown must be 'violation' or 'deny' \(got "block"\)/,
    );
    await expect(comply(SAFE_CONTENT, { onRegistryUnknown: bad, useGuard: false })).rejects.toThrow(
      TypeError,
    );
  });

  it("fails closed on an empty source package name with onRegistryUnknown: 'deny'", async () => {
    const result = await comply({
      content: 'hello world',
      sourcePackage: '',
      useGuard: false,
      onRegistryUnknown: 'deny',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('error');
    expect(result.registrySignals?.packageName).toBe('');
    expect(result.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
  });

  it('rejects a source package that is not a string, in either argument', async () => {
    const notString = null as unknown as string;
    await expect(
      comply({ content: 'hello world', sourcePackage: notString, useGuard: false, onRegistryUnknown: 'deny' }),
    ).rejects.toThrow(/sourcePackage must be a string \(got null\)/);
    await expect(comply('', { sourcePackage: 42 as unknown as string })).rejects.toThrow(
      /sourcePackage must be a string \(got number\)/,
    );
  });

  it("fails closed on empty content from an unreachable Registry with onRegistryUnknown: 'deny'", async () => {
    registryUnreachable();
    const session = await ClassificationSession.create({ baseUrl: BASE_URL });

    const result = await session.comply({
      content: '',
      sourcePackage: 'any-package',
      onRegistryUnknown: 'deny',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('error');
    expect(result.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
    // Every DENY drops the content echo, empty content included.
    expect(result.originalContent).toBeUndefined();
    expect(result.normalizedContent).toBeUndefined();
    expect(result.layers).toEqual([]);
  });

  it('reports the lookup for empty content without changing the verdict when unset', async () => {
    const result = await comply({
      content: '',
      sourcePackage: 'any-package',
      registryCache: makeCache({ status: 'miss' }),
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.status).toBe('miss');
    expect(result.originalContent).toBe('');
    expect(result.normalizedContent).toBe('');
  });

  it('applies a supply-chain block to empty content, as to any other content', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'blocked-pkg',
        fleetAnomalySignal: null,
        supplyChainAlerts: [
          {
            id: 'sca-empty',
            name: 'blocked-pkg',
            type: 'library',
            severity: 'critical',
            reason: 'Empty content test',
            publishedAt: '2026-10-11T00:00:00Z',
          },
        ],
        fetchedAt: Date.now(),
      },
    });

    const result = await comply({ content: '', sourcePackage: 'blocked-pkg', registryCache: cache });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// comply() - dualLayerOptions pass-through (no regression)
// ---------------------------------------------------------------------------

describe('comply(): dualLayerOptions not overwritten by registry threading', () => {
  it('dualLayerOptions are preserved alongside registry options', async () => {
    const cache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'agent-x',
        fleetAnomalySignal: null,
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    // No guardResult / guardVerifyOptions supplied - just verify L2 runs normally
    const result = await comply(
      { content: SAFE_CONTENT, sourcePackage: 'agent-x', registryCache: cache },
      { /* empty DualLayerOptions */ },
    );

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.packageName).toBe('agent-x');
  });
});

// ---------------------------------------------------------------------------
// warmRegistryCache()
// ---------------------------------------------------------------------------

describe('warmRegistryCache()', () => {
  it('returns a RegistryIntelligenceCache after warm()', async () => {
    // Prevent real network calls
    const mockWarm = jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);

    const cache = await warmRegistryCache({ baseUrl: 'https://api.example.com' });

    expect(cache).toBeInstanceOf(RegistryIntelligenceCache);
    expect(mockWarm).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// ClassificationSession
// ---------------------------------------------------------------------------

describe('ClassificationSession', () => {
  it('create() warms the cache before returning', async () => {
    const mockWarm = jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);

    const session = await ClassificationSession.create();
    expect(session).toBeInstanceOf(ClassificationSession);
    expect(mockWarm).toHaveBeenCalledTimes(1);
  });

  it('comply() uses session cache when caller omits registryCache', async () => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);

    const mockLookup = jest
      .spyOn(RegistryIntelligenceCache.prototype, 'lookup')
      .mockReturnValue({
        status: 'hit',
        intelligence: {
          packageName: 'session-agent',
          fleetAnomalySignal: {
            name: 'session-agent',
            type: 'skill',
            anomalyScore: 0.60,
            eventCount: 7,
            lastSeenAt: '2026-04-14T00:00:00Z',
            formulaVersion: '1.0',
            stale: false,
          },
          supplyChainAlerts: [],
          fetchedAt: Date.now(),
        },
      });

    const session = await ClassificationSession.create();
    const result = await session.comply({
      content: SAFE_CONTENT,
      sourcePackage: 'session-agent',
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.fleetAnomalyScore).toBe(0.60);
    expect(mockLookup).toHaveBeenCalledWith('session-agent');
  });

  it('comply() respects caller-supplied registryCache over session cache', async () => {
    // Caller-supplied cache says DENY. It is made before the prototype is
    // spied on, so it keeps its own lookup mock: made after, it would get the
    // prototype's mock back and hand the session cache this alert as well.
    const callerCache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'agent-y',
        fleetAnomalySignal: null,
        supplyChainAlerts: [{
          id: 'sca-override',
          name: 'agent-y',
          type: 'library',
          severity: 'high',
          reason: 'Override test',
          publishedAt: '2026-04-14T00:00:00Z',
        }],
        fetchedAt: Date.now(),
      },
    });

    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);

    // Session cache would say CLEAN (no anomaly)
    const sessionLookup = jest
      .spyOn(RegistryIntelligenceCache.prototype, 'lookup')
      .mockReturnValue({
        status: 'hit',
        intelligence: {
          packageName: 'agent-y',
          fleetAnomalySignal: null,
          supplyChainAlerts: [],
          fetchedAt: Date.now(),
        },
      });

    const session = await ClassificationSession.create();
    const result = await session.comply(
      { content: SAFE_CONTENT, sourcePackage: 'agent-y', registryCache: callerCache },
    );

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
    expect(callerCache.lookup).toHaveBeenCalledWith('agent-y');
    expect(sessionLookup).not.toHaveBeenCalled();
  });

  it('comply() classifies a bare string, as the comply() function does', async () => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const session = await ClassificationSession.create();

    const bare = await session.comply('My SSN is 123-45-6789.', { useGuard: false });
    const wrapped = await session.comply({ content: 'My SSN is 123-45-6789.', useGuard: false });

    expect(bare.verdict).toBe('VIOLATION');
    expect(bare.violations.map(v => v.type)).toEqual(['SSN']);
    expect(bare.originalContent).toBe('My SSN is 123-45-6789.');
    expect(bare).toEqual(wrapped);
  });

  it('comply() looks a bare string up in the session cache', async () => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const mockLookup = jest
      .spyOn(RegistryIntelligenceCache.prototype, 'lookup')
      .mockReturnValue({ status: 'miss' });
    const session = await ClassificationSession.create();

    const result = await session.comply(SAFE_CONTENT, {
      useGuard: false,
      sourcePackage: 'session-agent',
      onRegistryUnknown: 'deny',
    });

    expect(mockLookup).toHaveBeenCalledWith('session-agent');
    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.status).toBe('miss');
  });

  it('comply() rejects options that are neither a string nor an options object', async () => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const session = await ClassificationSession.create();

    // Spread into an options object, each of these would lose its content and
    // come back CLEAN without anything having been classified.
    const cases: Array<[unknown, string]> = [
      [123, 'number'],
      [['My SSN is 123-45-6789.'], 'array'],
      [null, 'null'],
      [undefined, 'undefined'],
    ];
    for (const [bad, got] of cases) {
      const call = session.comply(bad as unknown as ComplyOptions, { useGuard: false });
      await expect(call).rejects.toThrow(TypeError);
      await expect(call).rejects.toThrow(
        `comply: expected a string or an options object like comply({ content: '...' }), got ${got}`,
      );
    }
  });

  it('comply() reads a content getter and an inherited content, as the comply() function does', async () => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const session = await ClassificationSession.create();

    class Message {
      constructor(private readonly text: string) {}
      get content(): string {
        return this.text;
      }
    }
    const inherited = Object.create({ content: SSN_TEXT }) as ComplyOptions;

    for (const options of [new Message(SSN_TEXT) as unknown as ComplyOptions, inherited]) {
      const direct = await comply(options, { useGuard: false });
      const viaSession = await session.comply(options, { useGuard: false });

      expect(viaSession.verdict).toBe('VIOLATION');
      expect(viaSession.violations.map(v => v.type)).toEqual(['SSN']);
      expect(viaSession.layers).toEqual(['normalize', 'regex']);
      expect(viaSession).toEqual(direct);
    }
  });

  it('comply() uses the session cache in place of a registryCache passed on the second argument', async () => {
    // The caches passed on the second argument are made first, so each keeps
    // its own lookup mock: spied on after the prototype, an instance would
    // get the prototype's mock back, and its return value would be the
    // session cache's as well.
    const missCache = makeCache({ status: 'miss' });
    const hitCache = makeCache({
      status: 'hit',
      intelligence: {
        packageName: 'agent-z',
        fleetAnomalySignal: null,
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const sessionLookup = jest.spyOn(RegistryIntelligenceCache.prototype, 'lookup');
    const session = await ClassificationSession.create();

    // The session cache has a supply-chain alert for the package; the cache
    // on the second argument has no data for it and is not consulted.
    sessionLookup.mockReturnValue({
      status: 'hit',
      intelligence: {
        packageName: 'agent-z',
        fleetAnomalySignal: null,
        supplyChainAlerts: [{
          id: 'sca-session',
          name: 'agent-z',
          type: 'library',
          severity: 'critical',
          reason: 'Session cache alert',
          publishedAt: '2026-04-14T00:00:00Z',
        }],
        fetchedAt: Date.now(),
      },
    });
    const blocked = await session.comply(
      { content: SAFE_CONTENT, sourcePackage: 'agent-z' },
      { useGuard: false, registryCache: missCache },
    );

    expect(blocked.verdict).toBe('DENY');
    expect(blocked.violations.map(v => v.type)).toEqual(['SUPPLY_CHAIN_ALERT']);
    expect(blocked.registrySignals?.status).toBe('hit');
    expect(missCache.lookup).not.toHaveBeenCalled();

    // The session cache has no data for the package, so onRegistryUnknown
    // decides the verdict, whatever the cache on the second argument holds.
    sessionLookup.mockReturnValue({ status: 'miss' });
    const unknown = await session.comply(
      { content: SAFE_CONTENT, sourcePackage: 'agent-z' },
      { useGuard: false, onRegistryUnknown: 'deny', registryCache: hitCache },
    );

    expect(unknown.verdict).toBe('DENY');
    expect(unknown.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
    expect(unknown.registrySignals?.status).toBe('miss');
    expect(hitCache.lookup).not.toHaveBeenCalled();
    expect(sessionLookup).toHaveBeenCalledTimes(2);
    expect(sessionLookup).toHaveBeenCalledWith('agent-z');
  });

  it('refreshCache() calls refreshIfStale() on the session cache', async () => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const mockRefresh = jest
      .spyOn(RegistryIntelligenceCache.prototype, 'refreshIfStale')
      .mockImplementation(() => { /* no-op */ });

    const session = await ClassificationSession.create();
    session.refreshCache();

    expect(mockRefresh).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// What the first argument of comply() can be
// ---------------------------------------------------------------------------

describe('comply(): the first argument', () => {
  // Each of these is an object, but read as options it has no content, so
  // the call would come back CLEAN without anything having been classified.
  const notOptions: Array<[string, () => unknown, string]> = [
    ['a Buffer', () => Buffer.from(SSN_TEXT), 'Buffer'],
    ['a typed array', () => new Uint8Array(Buffer.from(SSN_TEXT)), 'Uint8Array'],
    ['an ArrayBuffer', () => new ArrayBuffer(8), 'ArrayBuffer'],
    ['a DataView', () => new DataView(new ArrayBuffer(8)), 'DataView'],
    ['a boxed String', () => new String(SSN_TEXT), 'String object'],
    ['a promise', () => Promise.resolve({ content: SSN_TEXT }), 'Promise (await it first)'],
  ];

  it.each(notOptions)('rejects %s, as a number or an array is rejected', async (_label, make, got) => {
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);
    const session = await ClassificationSession.create();
    const message =
      `comply: expected a string or an options object like comply({ content: '...' }), got ${got}`;

    for (const call of [
      comply(make() as ComplyOptions, { useGuard: false }),
      session.comply(make() as ComplyOptions, { useGuard: false }),
    ]) {
      await expect(call).rejects.toThrow(TypeError);
      await expect(call).rejects.toThrow(message);
    }
  });

  it('reads a content getter once, so the value checked is the value classified', async () => {
    let reads = 0;
    const options = {
      get content(): string {
        reads += 1;
        return reads === 1 ? SSN_TEXT : 'nothing to see here';
      },
      useGuard: false,
    } as ComplyOptions;

    const result = await comply(options);

    expect(reads).toBe(1);
    expect(result.verdict).toBe('VIOLATION');
    expect(result.originalContent).toBe(SSN_TEXT);
  });
});
