/**
 * Tests for comply() public API with Registry L2 integration and the
 * ClassificationSession / warmRegistryCache warm-start lifecycle helpers.
 *
 * Coverage:
 *   - comply() threads sourcePackage + registryCache through to classifyDualLayer
 *   - Supply-chain hard block => DENY via comply()
 *   - Fleet anomaly > 0.30 => VIOLATION via comply()
 *   - Cache miss => signals present, verdict unchanged
 *   - comply() without registry options => no L2 signals
 *   - ClassificationSession.comply() uses session cache when caller omits registryCache
 *   - ClassificationSession.comply() respects caller-supplied registryCache override
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
    jest
      .spyOn(RegistryIntelligenceCache.prototype, 'warm')
      .mockResolvedValue(undefined);

    // Session cache would say CLEAN (no anomaly)
    jest
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

    // Caller-supplied cache says DENY
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

    const session = await ClassificationSession.create();
    const result = await session.comply(
      { content: SAFE_CONTENT, sourcePackage: 'agent-y', registryCache: callerCache },
    );

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
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
