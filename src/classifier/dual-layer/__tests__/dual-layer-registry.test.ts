/**
 * Tests for Registry L2 threshold/block logic in classifyDualLayer.
 *
 * Section 3.1, lines 239-263:
 *   - fleetAnomalySignal > 0.30 => threshold -= 0.15 => CLEAN -> VIOLATION
 *   - Any active supply-chain alert on package => hard DENY
 *   - Cache miss => unknown (AC-002), verdict unchanged, signals recorded
 *   - No registry options => L2 not applied
 */

import { classifyDualLayer } from '..';
import { RegistryIntelligenceCache } from '../../../registry';

// ---------------------------------------------------------------------------
// Helpers to mock the registry cache
// ---------------------------------------------------------------------------
function makeCache(lookupResult: ReturnType<RegistryIntelligenceCache['lookup']>): RegistryIntelligenceCache {
  const cache = new RegistryIntelligenceCache();
  jest.spyOn(cache, 'lookup').mockReturnValue(lookupResult);
  return cache;
}

const SAFE_CONTENT = 'This is safe content with no PII.';

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
