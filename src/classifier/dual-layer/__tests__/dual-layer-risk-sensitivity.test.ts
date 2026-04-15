/**
 * Tests for P4: RiskContext → anomaly threshold composition.
 *
 * The trust-level sensitivity multiplier scales the raw fleet anomaly score
 * before comparing against the 0.30 threshold. This allows per-tier tuning
 * of how aggressively L2 flags anomalous packages.
 *
 * Multiplier table:
 *   trustLevel 0 (Blocked)  → 1.00  (ARP handles hard blocks, L2 defers)
 *   trustLevel 1 (Warning)  → 1.35
 *   trustLevel 2 (Listed)   → 1.15
 *   trustLevel 3 (Scanned)  → 1.00  (baseline)
 *   trustLevel 4 (Verified) → 0.80
 *   missing / out-of-range  → 1.00  (safe default)
 *
 * Threshold: effectiveAnomalyScore = rawScore × multiplier
 *   if effectiveAnomalyScore > 0.30 → VIOLATION (FLEET_ANOMALY_ELEVATED)
 */

import { classifyDualLayer } from '..';
import { RegistryIntelligenceCache } from '../../../registry';

function makeCache(anomalyScore: number): RegistryIntelligenceCache {
  const cache = new RegistryIntelligenceCache();
  jest.spyOn(cache, 'lookup').mockReturnValue({
    status: 'hit',
    intelligence: {
      packageName: 'test-agent',
      fleetAnomalySignal: {
        name: 'test-agent',
        type: 'mcp_server',
        anomalyScore,
        eventCount: 5,
        lastSeenAt: '2026-04-14T00:00:00Z',
        formulaVersion: '1.0',
        stale: false,
      },
      supplyChainAlerts: [],
      fetchedAt: Date.now(),
    },
  });
  return cache;
}

const SAFE_CONTENT = 'This is safe content with no PII.';

afterEach(() => {
  jest.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Borderline raw score (0.32): just above threshold without a multiplier
// ---------------------------------------------------------------------------

describe('sensitivityMultiplier: trustLevel 1 (Warning) amplifies anomaly', () => {
  it('0.32 × 1.35 = 0.43 > 0.30 → VIOLATION', async () => {
    const cache = makeCache(0.32);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      riskContext: { trustLevel: 1 },
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.35);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.432);
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
    expect(result.violations.some(v => v.type === 'FLEET_ANOMALY_ELEVATED')).toBe(true);
  });
});

describe('sensitivityMultiplier: trustLevel 4 (Verified) dampens anomaly', () => {
  it('0.32 × 0.80 = 0.26 < 0.30 → CLEAN', async () => {
    const cache = makeCache(0.32);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      riskContext: { trustLevel: 4 },
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(0.80);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.256);
    expect(result.registrySignals?.thresholdDelta).toBe(0);
    expect(result.violations.some(v => v.type === 'FLEET_ANOMALY_ELEVATED')).toBe(false);
  });

  it('0.55 × 0.80 = 0.44 > 0.30 → still VIOLATION despite Verified tier', async () => {
    const cache = makeCache(0.55);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      riskContext: { trustLevel: 4 },
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(0.80);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.44);
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
    expect(result.violations.some(v => v.type === 'FLEET_ANOMALY_ELEVATED')).toBe(true);
  });
});

describe('sensitivityMultiplier: missing trustLevel → baseline (1.00)', () => {
  it('no riskContext → same result as trustLevel 3 for anomalyScore 0.32', async () => {
    const cache = makeCache(0.32);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      // no riskContext
    });

    // 0.32 × 1.00 = 0.32 > 0.30 → VIOLATION (unchanged baseline behaviour)
    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.00);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.32);
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
  });

  it('riskContext with no trustLevel → safe default 1.00', async () => {
    const cache = makeCache(0.32);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      riskContext: { agentId: 'agent-x' }, // trustLevel intentionally absent
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.00);
  });
});

describe('sensitivityMultiplier: trustLevel 0 (Blocked) → L2 defers (1.00)', () => {
  it('0.32 × 1.00 = 0.32 > 0.30 → VIOLATION (hard-block is ARP\'s job)', async () => {
    const cache = makeCache(0.32);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      riskContext: { trustLevel: 0 },
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.00);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.32);
  });
});

describe('sensitivityMultiplier: trustLevel 2 (Listed)', () => {
  it('0.28 × 1.15 = 0.32 > 0.30 → VIOLATION (raw score was below threshold)', async () => {
    const cache = makeCache(0.28);
    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'test-agent',
      riskContext: { trustLevel: 2 },
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.15);
    expect(result.registrySignals?.effectiveAnomalyScore).toBeCloseTo(0.322);
    expect(result.registrySignals?.thresholdDelta).toBe(-0.15);
  });
});

describe('sensitivityMultiplier: supply-chain hard block ignores multiplier', () => {
  it('supply-chain DENY is unaffected by trustLevel', async () => {
    const cache = new RegistryIntelligenceCache();
    jest.spyOn(cache, 'lookup').mockReturnValue({
      status: 'hit',
      intelligence: {
        packageName: 'blocked-agent',
        fleetAnomalySignal: {
          name: 'blocked-agent',
          type: 'mcp_server',
          anomalyScore: 0.10, // low raw anomaly — would be CLEAN without supply-chain alert
          eventCount: 1,
          lastSeenAt: '2026-04-14T00:00:00Z',
          formulaVersion: '1.0',
          stale: false,
        },
        supplyChainAlerts: [{
          id: 'sca-42',
          name: 'blocked-agent',
          type: 'mcp_server',
          severity: 'critical',
          reason: 'Backdoor discovered',
          publishedAt: '2026-04-14T00:00:00Z',
        }],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'blocked-agent',
      riskContext: { trustLevel: 4 }, // Verified tier should not rescue a supply-chain block
    });

    expect(result.verdict).toBe('DENY');
    expect(result.registrySignals?.supplyChainBlock).toBe(true);
    expect(result.violations.some(v => v.type === 'SUPPLY_CHAIN_ALERT')).toBe(true);
  });
});

describe('registrySignals fields: effectiveAnomalyScore and trustSensitivityMultiplier always present on L2 hit', () => {
  it('fields present on cache miss (null + default multiplier)', async () => {
    const cache = new RegistryIntelligenceCache();
    jest.spyOn(cache, 'lookup').mockReturnValue({ status: 'miss' });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'unknown',
      riskContext: { trustLevel: 3 },
    });

    expect(result.registrySignals?.effectiveAnomalyScore).toBeNull();
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.00);
  });

  it('fields present when fleet signal is null but package is known', async () => {
    const cache = new RegistryIntelligenceCache();
    jest.spyOn(cache, 'lookup').mockReturnValue({
      status: 'hit',
      intelligence: {
        packageName: 'no-signal-agent',
        fleetAnomalySignal: null,
        supplyChainAlerts: [],
        fetchedAt: Date.now(),
      },
    });

    const result = await classifyDualLayer(SAFE_CONTENT, {
      registryCache: cache,
      sourcePackage: 'no-signal-agent',
      riskContext: { trustLevel: 1 },
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.registrySignals?.fleetAnomalyScore).toBeNull();
    expect(result.registrySignals?.effectiveAnomalyScore).toBeNull();
    expect(result.registrySignals?.trustSensitivityMultiplier).toBe(1.35);
  });
});
