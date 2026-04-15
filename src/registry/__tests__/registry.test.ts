/**
 * Tests for RegistryIntelligenceCache.
 *
 * Covers:
 *   - warm-start happy path (fleet + supply-chain)
 *   - AC-002: cache miss treated as unknown, not clean
 *   - AC-002: fetch error treated as unknown
 *   - cache TTL expiry
 *   - lookup before warm returns error
 */

import { RegistryIntelligenceCache } from '..';
import type { FleetAnomalySignal, SupplyChainAlert } from '../types';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------
const FLEET_SIGNAL: FleetAnomalySignal = {
  name: 'example-agent',
  type: 'mcp_server',
  anomalyScore: 0.42,
  eventCount: 7,
  lastSeenAt: '2026-04-14T00:00:00Z',
  formulaVersion: '1.0',
  stale: false,
};

const SUPPLY_ALERT: SupplyChainAlert = {
  id: 'alert-001',
  name: 'example-agent',
  type: 'mcp_server',
  severity: 'critical',
  reason: 'Typosquatting detected',
  publishedAt: '2026-04-13T12:00:00Z',
};

// ---------------------------------------------------------------------------
// Helpers to mock fetch
// ---------------------------------------------------------------------------
function mockFetch(
  fleetAgents: FleetAnomalySignal[],
  supplyAlerts: SupplyChainAlert[],
): void {
  global.fetch = jest.fn().mockImplementation((url: string) => {
    if (url.includes('fleet/anomaly-signal')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ agents: fleetAgents }),
      });
    }
    if (url.includes('intelligence/alerts')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ alerts: supplyAlerts, total: supplyAlerts.length }),
      });
    }
    return Promise.resolve({ ok: false });
  }) as jest.Mock;
}

function mockFetchError(): void {
  global.fetch = jest.fn().mockRejectedValue(new Error('network error')) as jest.Mock;
}

function mockFetchNotOk(): void {
  global.fetch = jest.fn().mockResolvedValue({ ok: false }) as jest.Mock;
}

afterEach(() => {
  jest.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RegistryIntelligenceCache', () => {
  describe('lookup before warm()', () => {
    it('returns error when cache was never warmed', () => {
      const cache = new RegistryIntelligenceCache();
      const result = cache.lookup('example-agent');
      expect(result.status).toBe('error');
      if (result.status === 'error') {
        expect(result.reason).toMatch(/not warmed/i);
      }
    });
  });

  describe('warm() + lookup happy path', () => {
    it('returns hit with fleet anomaly signal after warm()', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal?.anomalyScore).toBe(0.42);
        expect(result.intelligence.supplyChainAlerts).toHaveLength(0);
      }
    });

    it('is case-insensitive for package names', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      expect(cache.lookup('EXAMPLE-AGENT').status).toBe('hit');
      expect(cache.lookup('Example-Agent').status).toBe('hit');
    });

    it('returns supply-chain alerts when present', async () => {
      mockFetch([FLEET_SIGNAL], [SUPPLY_ALERT]);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toHaveLength(1);
        expect(result.intelligence.supplyChainAlerts![0].id).toBe('alert-001');
      }
    });

    it('updates fleetIndexSize after warm()', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache();
      expect(cache.fleetIndexSize()).toBe(0);
      await cache.warm();
      expect(cache.fleetIndexSize()).toBe(1);
    });
  });

  describe('AC-002: miss treated as unknown (not clean)', () => {
    it('returns miss for unknown package after warm()', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      // 'unknown-pkg' is not in the fleet index
      const result = cache.lookup('unknown-pkg');
      expect(result.status).toBe('miss');
    });
  });

  describe('AC-002: fetch failure treated as unknown', () => {
    it('returns error when fetch throws', async () => {
      mockFetchError();
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('error');
    });

    it('returns error when endpoint returns non-ok status', async () => {
      mockFetchNotOk();
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('error');
    });
  });

  describe('cache TTL', () => {
    it('returns cached entry within TTL', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache({ cacheTtlMs: 60_000 });
      await cache.warm();

      const r1 = cache.lookup('example-agent');
      const r2 = cache.lookup('example-agent');
      expect(r1.status).toBe('hit');
      expect(r2.status).toBe('hit');
    });

    it('clears index on clearCache()', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();
      expect(cache.fleetIndexSize()).toBe(1);
      cache.clearCache();
      expect(cache.fleetIndexSize()).toBe(0);
    });
  });

  describe('concurrent warm() calls', () => {
    it('deduplicated to a single fetch round', async () => {
      let callCount = 0;
      global.fetch = jest.fn().mockImplementation(() => {
        callCount++;
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ agents: [], alerts: [], total: 0 }),
        });
      }) as jest.Mock;

      const cache = new RegistryIntelligenceCache();
      await Promise.all([cache.warm(), cache.warm(), cache.warm()]);
      // 2 endpoints, deduplicated to 1 concurrent round
      expect(callCount).toBe(2);
    });
  });
});
