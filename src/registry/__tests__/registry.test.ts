/**
 * Tests for RegistryIntelligenceCache.
 *
 * Covers:
 *   - warm-start happy path (fleet + supply-chain)
 *   - AC-002: cache miss treated as unknown, not clean
 *   - AC-002: fetch error treated as unknown
 *   - a refused fleet request: a loaded supply-chain alert is still a hit
 *   - sourcePackages: the fleet signal requested per package by name and type,
 *     a package the Registry has no fleet events for is a miss, and a list
 *     warm() could not request is rejected
 *   - addSourcePackages(): a package first seen after the cache was created
 *     is listed and requested as one in sourcePackages is
 *   - a package with no alert on the supply-chain alert page has none only
 *     when the page is complete for it; otherwise the lookup is partial, with
 *     the page's figures, and never a hit with no alerts (AC-002)
 *   - AC-005: lookup() does no network I/O
 *   - cache TTL expiry
 *   - lookup before warm returns error
 */

import { RegistryIntelligenceCache } from '..';
import type { FleetAnomalySignal, RegistryCacheOptions, RegistrySourcePackage, SupplyChainAlert } from '../types';

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

/**
 * The supply-chain alert page as the production Registry serves it: the
 * alerts, the size of the population they come from (`total`), that
 * population (no name or type filter: every package), the most alerts a page
 * carries, and the state of the detector that writes the alerts. `overrides`
 * replaces any of them.
 */
function alertPage(alerts: SupplyChainAlert[], overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    alerts,
    total: alerts.length,
    population: { name: null, packageType: null },
    limit: 1000,
    producer: { state: 'current' },
    ...overrides,
  };
}

/** `count` alerts, each for a package of its own, none of them example-agent. */
function otherAlerts(count: number): SupplyChainAlert[] {
  return Array.from({ length: count }, (_, i) => ({
    ...SUPPLY_ALERT,
    id: `other-${i}`,
    name: `other-package-${i}`,
  }));
}

/**
 * A page cut from a larger population: 1,000 alerts, the limit, of 14,002.
 * `rows` replaces the 1,000 alerts, which are for other packages.
 */
function cutPage(rows: SupplyChainAlert[] = otherAlerts(1000)): Record<string, unknown> {
  return alertPage(rows, { total: 14002 });
}

/** The supply-chain alert request that names no package: the unfiltered page. */
const ALERTS_URL = 'https://api.oa2a.org/api/v1/intelligence/alerts?type=supply_chain';

/** A Registry answer to the alert request for one package: the HTTP status and the JSON body. */
interface AlertAnswer {
  status: number;
  body: unknown;
}

/**
 * The Registry's answer to the alert request for one package by name and
 * type, as it serves it: the alerts filed under that name and type, `total`
 * their count, the population it counts (that name and type), the most alerts
 * a page carries, and the state of the detector. `overrides` replaces any of
 * them.
 */
function packageAnswer(
  name: string,
  packageType: string,
  alerts: SupplyChainAlert[],
  overrides: Record<string, unknown> = {},
): AlertAnswer {
  return { status: 200, body: alertPage(alerts, { population: { name, packageType }, ...overrides }) };
}

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
        json: () => Promise.resolve(alertPage(supplyAlerts)),
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

/**
 * Answer as the production Registry does: the fleet request, which names no
 * package, is refused with 400, and the supply-chain alert list loads.
 */
function mockFleetRefused(supplyAlerts: SupplyChainAlert[]): void {
  global.fetch = jest.fn().mockImplementation((url: string) => {
    if (url.includes('fleet/anomaly-signal')) {
      return Promise.resolve({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: 'name and type query params are required' }),
      });
    }
    if (url.includes('intelligence/alerts')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(alertPage(supplyAlerts)),
      });
    }
    return Promise.resolve({ ok: false });
  }) as jest.Mock;
}

/** A Registry answer to a fleet request: the HTTP status and the JSON body. */
interface FleetAnswer {
  status: number;
  body: unknown;
}

/**
 * The record the production Registry answers for a package it has no fleet
 * events for (checked 2026-10-18), the same for a package it has no record of.
 */
function noEventsRecord(name: string, type: string): Record<string, unknown> {
  return {
    name,
    type,
    anomalyScore: 0,
    windowHours: 24,
    eventCount: 0,
    lastSeenAt: null,
    formulaVersion: 'v1',
    stale: false,
  };
}

/** A list of length 2 with no element at index 0. */
function withHoleAtZero(): unknown[] {
  const list: unknown[] = [];
  list[1] = { name: 'example-agent', type: 'mcp_server' };
  return list;
}

/** No fleet events for any package. */
function noEventsAnswer(name: string, type: string): FleetAnswer {
  return { status: 200, body: noEventsRecord(name, type) };
}

/** FLEET_SIGNAL for example-agent, and no fleet events for any other package. */
function asProduction(name: string, type: string): FleetAnswer {
  return {
    status: 200,
    body: name === FLEET_SIGNAL.name ? { ...FLEET_SIGNAL, windowHours: 24 } : noEventsRecord(name, type),
  };
}

/**
 * Answer as the production Registry does: a fleet request that names a
 * package and a type gets `answer(name, type)`, and the supply-chain alert
 * request gets `page`: a list of alerts is served as a complete page of them,
 * an object is served as it is, and null is answered with 503. The fleet
 * request that names no package is refused with 400, or, given `index`,
 * answered with it as an older Registry did. Given `packageAlerts`, the alert
 * request that names a package and a type gets `packageAlerts(name,
 * packageType)`, and a null from it fails that request on the network;
 * without it, that request gets `page`, as from a cache that ignores the
 * query.
 */
function mockFleetPerPackage(
  answer: (name: string, type: string) => FleetAnswer,
  page: SupplyChainAlert[] | Record<string, unknown> | null = [],
  index?: FleetAnomalySignal[],
  packageAlerts?: (name: string, packageType: string) => AlertAnswer | null,
): void {
  global.fetch = jest.fn().mockImplementation((url: string) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/api/v1/registry/fleet/anomaly-signal') {
      const name = searchParams.get('name');
      const type = searchParams.get('type');
      let reply: FleetAnswer;
      if (name && type) {
        reply = answer(name, type);
      } else if (index) {
        reply = { status: 200, body: { agents: index } };
      } else {
        reply = { status: 400, body: { error: 'name and type query params are required' } };
      }
      return Promise.resolve({
        ok: reply.status >= 200 && reply.status < 300,
        status: reply.status,
        json: () => Promise.resolve(reply.body),
      });
    }
    if (pathname === '/api/v1/intelligence/alerts') {
      const name = searchParams.get('name');
      const packageType = searchParams.get('packageType');
      if (packageAlerts && name && packageType) {
        const reply = packageAlerts(name, packageType);
        if (reply === null) {
          return Promise.reject(new TypeError('fetch failed'));
        }
        return Promise.resolve({
          ok: reply.status >= 200 && reply.status < 300,
          status: reply.status,
          json: () => Promise.resolve(reply.body),
        });
      }
      if (page === null) {
        return Promise.resolve({ ok: false, status: 503 });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(Array.isArray(page) ? alertPage(page) : page),
      });
    }
    return Promise.resolve({ ok: false });
  }) as jest.Mock;
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

  describe('fleet request refused, supply-chain alert list loaded', () => {
    it('returns hit with the alerts for a package that has one', async () => {
      mockFleetRefused([SUPPLY_ALERT]);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      const result = cache.lookup('Example-Agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal).toBeNull();
        expect(result.intelligence.supplyChainAlerts?.map(a => a.id)).toEqual(['alert-001']);
      }
      expect(cache.fleetIndexSize()).toBe(0);
    });

    it('returns error naming the fleet signal for a package without one', async () => {
      mockFleetRefused([SUPPLY_ALERT]);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      const result = cache.lookup('unknown-pkg');
      expect(result.status).toBe('error');
      if (result.status === 'error') {
        expect(result.reason).toBe('fleet anomaly signal not loaded');
      }
    });
  });

  describe('sourcePackages: fleet signal requested per package', () => {
    const FLEET_URL = 'https://api.oa2a.org/api/v1/registry/fleet/anomaly-signal';

    it('requests the fleet signal of each listed package with its name and type in the query', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [
          { name: 'example-agent', type: 'mcp_server' },
          { name: '@scope/tool', type: 'ai_tool' },
        ],
      });
      await cache.warm();

      const urls = (global.fetch as jest.Mock).mock.calls.map(([url]) => url);
      expect(urls).toHaveLength(6);
      expect(urls).toEqual(expect.arrayContaining([
        FLEET_URL,
        `${FLEET_URL}?name=example-agent&type=mcp_server`,
        `${FLEET_URL}?name=%40scope%2Ftool&type=ai_tool`,
        'https://api.oa2a.org/api/v1/intelligence/alerts?type=supply_chain',
        `${ALERTS_URL}&name=example-agent&packageType=mcp_server`,
        `${ALERTS_URL}&name=%40scope%2Ftool&packageType=ai_tool`,
      ]));
    });

    it('returns hit with the signal the Registry answered for a listed package', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      const result = cache.lookup('Example-Agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal?.anomalyScore).toBe(0.42);
        expect(result.intelligence.fleetAnomalySignal?.eventCount).toBe(7);
        expect(result.intelligence.supplyChainAlerts).toEqual([]);
      }
    });

    it('returns miss, not hit, for a listed package the Registry has no fleet events for', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'quiet-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });
    });

    it('returns hit with the alerts for a listed package that has one and no fleet events', async () => {
      const alert = { ...SUPPLY_ALERT, name: 'quiet-agent' };
      mockFleetPerPackage(asProduction, [alert]);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'quiet-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      const result = cache.lookup('quiet-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal).toBeNull();
        expect(result.intelligence.supplyChainAlerts?.map(a => a.id)).toEqual(['alert-001']);
      }
    });

    it('returns error for a package that is not listed', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      expect(cache.lookup('unknown-pkg')).toEqual({ status: 'error', reason: 'fleet anomaly signal not loaded' });
    });

    it.each<[string, (name: string, type: string) => FleetAnswer]>([
      ['refused with 429', () => ({ status: 429, body: { error: 'Rate limit exceeded' } })],
      ['answered for another package', (_name, type) => ({ status: 200, body: { ...FLEET_SIGNAL, name: 'other-agent', type } })],
      ['answered without a score or an event count', (name, type) => ({ status: 200, body: { name, type } })],
      ['answered with a body that is not an object', () => ({ status: 200, body: null })],
    ])('returns error for a listed package whose request is %s', async (_label, answer) => {
      mockFleetPerPackage(answer);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'fleet anomaly signal not loaded' });
    });

    it('returns error for a listed package whose request fails on the network', async () => {
      mockFleetPerPackage(asProduction);
      const answering = global.fetch as jest.Mock;
      global.fetch = jest.fn().mockImplementation((url: string) =>
        url.includes('?name=') ? Promise.reject(new TypeError('fetch failed')) : answering(url),
      ) as jest.Mock;
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'fleet anomaly signal not loaded' });
    });

    it('keeps the last answer for a listed package when a later request fails, until clearCache()', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();
      mockFleetPerPackage(() => ({ status: 429, body: { error: 'Rate limit exceeded' } }));
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal?.anomalyScore).toBe(0.42);
      }
      cache.clearCache();
      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'registry cache not warmed' });
    });

    it('keeps the signal from the fleet index when the listed request reports no fleet events', async () => {
      mockFleetPerPackage(noEventsAnswer, [], [FLEET_SIGNAL]);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal?.anomalyScore).toBe(0.42);
      }
    });

    it('does no network I/O in lookup() for a listed package (AC-005)', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        cacheTtlMs: 0,
        sourcePackages: [
          { name: 'example-agent', type: 'mcp_server' },
          { name: 'quiet-agent', type: 'mcp_server' },
        ],
      });
      await cache.warm();
      const fetched = (global.fetch as jest.Mock).mock.calls.length;
      // warm() sent six requests: the fleet index, the unfiltered alert page,
      // and the fleet request and the alert request of each listed package.
      expect(fetched).toBe(6);
      expect((global.fetch as jest.Mock).mock.calls.map(([url]) => String(url)).sort()).toEqual([
        FLEET_URL,
        `${FLEET_URL}?name=example-agent&type=mcp_server`,
        `${FLEET_URL}?name=quiet-agent&type=mcp_server`,
        ALERTS_URL,
        `${ALERTS_URL}&name=example-agent&packageType=mcp_server`,
        `${ALERTS_URL}&name=quiet-agent&packageType=mcp_server`,
      ].sort());

      expect(cache.lookup('example-agent').status).toBe('hit');
      expect(cache.lookup('quiet-agent').status).toBe('miss');
      expect(cache.lookup('unknown-pkg').status).toBe('error');
      expect((global.fetch as jest.Mock).mock.calls.length).toBe(fetched);

      // A listed name with an upper-case letter adds one request: its alert
      // request again, with the name lower-cased. lookup() still sends none.
      mockFleetPerPackage(asProduction);
      const mixed = new RegistryIntelligenceCache({
        cacheTtlMs: 0,
        sourcePackages: [
          { name: 'Example-Agent', type: 'mcp_server' },
          { name: 'quiet-agent', type: 'mcp_server' },
        ],
      });
      await mixed.warm();
      const mixedUrls = (global.fetch as jest.Mock).mock.calls.map(([url]) => String(url));
      expect(mixedUrls).toHaveLength(fetched + 1);
      expect(mixedUrls).toEqual(expect.arrayContaining([
        `${ALERTS_URL}&name=Example-Agent&packageType=mcp_server`,
        `${ALERTS_URL}&name=example-agent&packageType=mcp_server`,
      ]));

      // The Registry reports no events for the name as listed, so it is a miss.
      expect(mixed.lookup('Example-Agent').status).toBe('miss');
      expect(mixed.lookup('quiet-agent').status).toBe('miss');
      expect(mixed.lookup('unknown-pkg').status).toBe('error');
      expect((global.fetch as jest.Mock).mock.calls).toHaveLength(fetched + 1);
    });

    it('refreshIfStale() fetches again once a listed answer is past the TTL, not while it is within it', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        cacheTtlMs: 60_000,
        sourcePackages: [{ name: 'example-agent', type: 'mcp_server' }],
      });
      await cache.warm();
      const calls = (global.fetch as jest.Mock).mock.calls;
      const fetched = calls.length;

      // The fleet index request was refused, but the listed answer is fresh.
      cache.refreshIfStale();
      expect(calls).toHaveLength(fetched);

      jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_001);
      cache.refreshIfStale();
      expect(calls).toHaveLength(fetched * 2);
      await cache.warm(); // waits for the refresh in flight; starts no other
      expect(calls).toHaveLength(fetched * 2);
    });

    it.each<[string, unknown, RegExp]>([
      ['a string', 'example-agent', /^sourcePackages must be an array \(got string\)$/],
      ['null', null, /^sourcePackages must be an array \(got null\)$/],
      ['an entry that is a string', ['example-agent'], /^sourcePackages\[0\] must be an object .* \(got string\)$/],
      ['an array with a hole', withHoleAtZero(), /^sourcePackages\[0\] must be an object .* \(got undefined\)$/],
      ['an entry without a type', [{ name: 'example-agent' }], /^sourcePackages\[0\]\.type must be a non-empty string \(got undefined\)$/],
      ['an entry with an empty name', [{ name: '', type: 'mcp_server' }], /^sourcePackages\[0\]\.name must be a non-empty string \(got ""\)$/],
      [
        'a name listed twice',
        [{ name: 'example-agent', type: 'mcp_server' }, { name: 'Example-Agent', type: 'library' }],
        /^sourcePackages\[1\] names "Example-Agent", which sourcePackages\[0\] names already/,
      ],
    ])('rejects a sourcePackages value that is %s', (_label, sourcePackages, message) => {
      const options = { sourcePackages } as unknown as RegistryCacheOptions;
      expect(() => new RegistryIntelligenceCache(options)).toThrow(TypeError);
      expect(() => new RegistryIntelligenceCache(options)).toThrow(message);
    });
  });

  describe('addSourcePackages(): a package first seen after the cache was created', () => {
    const FLEET_URL = 'https://api.oa2a.org/api/v1/registry/fleet/anomaly-signal';

    it('requests the fleet signal of each added package by name and type, and lookup() reports it as a listed one', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache();
      await cache.warm();
      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'fleet anomaly signal not loaded' });
      const calls = (global.fetch as jest.Mock).mock.calls;
      const fetched = calls.length;

      await cache.addSourcePackages([
        { name: 'example-agent', type: 'mcp_server' },
        { name: 'quiet-agent', type: 'mcp_server' },
      ]);

      expect(calls.slice(fetched).map(([url]) => url)).toEqual([
        `${FLEET_URL}?name=example-agent&type=mcp_server`,
        `${ALERTS_URL}&name=example-agent&packageType=mcp_server`,
        `${FLEET_URL}?name=quiet-agent&type=mcp_server`,
        `${ALERTS_URL}&name=quiet-agent&packageType=mcp_server`,
      ]);
      const result = cache.lookup('Example-Agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal?.anomalyScore).toBe(0.42);
      }
      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });
      // lookup() made no request (AC-005).
      expect(calls).toHaveLength(fetched + 4);
    });

    it('requests an added package again when the cache warms later', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache();
      await cache.addSourcePackages([{ name: '@scope/tool', type: 'ai_tool' }]);
      const calls = (global.fetch as jest.Mock).mock.calls;
      expect(calls.map(([url]) => url)).toEqual([
        `${FLEET_URL}?name=%40scope%2Ftool&type=ai_tool`,
        `${ALERTS_URL}&name=%40scope%2Ftool&packageType=ai_tool`,
      ]);

      await cache.warm();

      expect(calls.slice(2).map(([url]) => url)).toEqual(expect.arrayContaining([
        FLEET_URL,
        `${FLEET_URL}?name=%40scope%2Ftool&type=ai_tool`,
        'https://api.oa2a.org/api/v1/intelligence/alerts?type=supply_chain',
        `${ALERTS_URL}&name=%40scope%2Ftool&packageType=ai_tool`,
      ]));
      expect(calls).toHaveLength(6);
    });

    it('does not request a package listed already, and waits for a request for it that is in flight', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'quiet-agent', type: 'mcp_server' }],
      });
      await cache.warm();
      const calls = (global.fetch as jest.Mock).mock.calls;
      const fetched = calls.length;

      await cache.addSourcePackages([{ name: 'Quiet-Agent', type: 'mcp_server' }]);
      expect(calls).toHaveLength(fetched);

      const first = cache.addSourcePackages([{ name: 'example-agent', type: 'mcp_server' }]);
      await cache.addSourcePackages([{ name: 'example-agent', type: 'mcp_server' }]);
      // The second call resolved after the answers the first one requested.
      expect(cache.lookup('example-agent').status).toBe('hit');
      await first;
      expect(calls).toHaveLength(fetched + 2);
    });

    it('resolves when the request for an added package fails, which lookup() reports as error', async () => {
      mockFleetPerPackage(asProduction);
      const answering = global.fetch as jest.Mock;
      global.fetch = jest.fn().mockImplementation((url: string) =>
        url.includes('?name=') ? Promise.reject(new TypeError('fetch failed')) : answering(url),
      ) as jest.Mock;
      const cache = new RegistryIntelligenceCache();
      await cache.warm();

      await expect(cache.addSourcePackages([{ name: 'example-agent', type: 'mcp_server' }])).resolves.toBeUndefined();

      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'fleet anomaly signal not loaded' });
    });

    it('sends one request for a package that warm() asks for while addSourcePackages() has one in flight', async () => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache();
      const calls = (global.fetch as jest.Mock).mock.calls;

      const adding = cache.addSourcePackages([{ name: 'example-agent', type: 'mcp_server' }]);
      await cache.warm();
      await adding;

      const urls = calls.map(([url]) => url);
      expect(urls.filter(url => url === `${FLEET_URL}?name=example-agent&type=mcp_server`)).toHaveLength(1);
      expect(urls.filter(url => url === `${ALERTS_URL}&name=example-agent&packageType=mcp_server`)).toHaveLength(1);
      expect(urls).toHaveLength(4);
      expect(cache.lookup('example-agent').status).toBe('hit');
    });

    it.each<[string, unknown, RegExp]>([
      ['undefined', undefined, /^sourcePackages must be an array \(got undefined\)$/],
      ['an entry without a type', [{ name: 'new-agent' }], /^sourcePackages\[0\]\.type must be a non-empty string \(got undefined\)$/],
      [
        'a name given twice',
        [{ name: 'new-agent', type: 'mcp_server' }, { name: 'NEW-AGENT', type: 'mcp_server' }],
        /^sourcePackages\[1\] names "NEW-AGENT", which sourcePackages\[0\] names already/,
      ],
      [
        'a name listed already with another type',
        [{ name: 'new-agent', type: 'mcp_server' }, { name: 'Quiet-Agent', type: 'library' }],
        /^sourcePackages\[1\] names "Quiet-Agent" with type "library", which is listed already with type "mcp_server"/,
      ],
    ])('rejects %s, and lists and requests no package of the call', async (_label, sourcePackages, message) => {
      mockFleetPerPackage(asProduction);
      const cache = new RegistryIntelligenceCache({
        sourcePackages: [{ name: 'quiet-agent', type: 'mcp_server' }],
      });
      const packages = sourcePackages as RegistrySourcePackage[];

      await expect(cache.addSourcePackages(packages)).rejects.toThrow(TypeError);
      await expect(cache.addSourcePackages(packages)).rejects.toThrow(message);
      expect(global.fetch).not.toHaveBeenCalled();

      await cache.warm();
      const urls = (global.fetch as jest.Mock).mock.calls.map(([url]) => String(url));
      expect(urls.filter(url => url.includes('new-agent'))).toEqual([]);
    });
  });

  describe('AC-005: lookup() does no network I/O', () => {
    it('does not fetch before warm()', () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache();
      cache.lookup('example-agent');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('does not fetch on a hit, a miss or an entry past its TTL', async () => {
      mockFetch([FLEET_SIGNAL], []);
      const cache = new RegistryIntelligenceCache({ cacheTtlMs: 0 });
      await cache.warm();
      const fetched = (global.fetch as jest.Mock).mock.calls.length;

      expect(cache.lookup('example-agent').status).toBe('hit');
      expect(cache.lookup('example-agent').status).toBe('hit');
      expect(cache.lookup('unknown-package').status).toBe('miss');
      expect((global.fetch as jest.Mock).mock.calls.length).toBe(fetched);
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

  describe('a package with no alert on the page has none only when the page is complete for it', () => {
    const listed: RegistryCacheOptions = {
      sourcePackages: [
        { name: 'example-agent', type: 'mcp_server' },
        { name: 'quiet-agent', type: 'mcp_server' },
      ],
    };
    const exampleSignal = expect.objectContaining({ name: 'example-agent', anomalyScore: 0.42 });

    it('is partial, with both numbers, on a page that holds fewer alerts than its total', async () => {
      mockFleetPerPackage(asProduction, cutPage());
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result).toEqual({
        status: 'partial',
        fleetAnomalySignal: exampleSignal,
        supplyChainPage: {
          reason: 'the page holds 1000 of 14002 alerts',
          alertsHeld: 1000,
          total: 14002,
          limit: 1000,
          producerState: 'current',
        },
      });
      // Never a hit with an empty alert list.
      expect(result.status === 'hit' && result.intelligence.supplyChainAlerts?.length === 0).toBe(false);
    });

    it.each([
      ['listed with no fleet events', 'quiet-agent'],
      ['not listed', 'unknown-pkg'],
    ])('is partial on that page for a package %s as well', async (_case, name) => {
      mockFleetPerPackage(asProduction, cutPage());
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup(name)).toEqual({
        status: 'partial',
        fleetAnomalySignal: null,
        supplyChainPage: expect.objectContaining({ alertsHeld: 1000, total: 14002 }),
      });
    });

    it('is a hit with its alerts for a package that has one on that page', async () => {
      mockFleetPerPackage(asProduction, cutPage([...otherAlerts(999), SUPPLY_ALERT]));
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('Example-Agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts?.map(a => a.id)).toEqual(['alert-001']);
      }
    });

    it("is partial on a page from a producer whose state is 'stale', and names the state", async () => {
      mockFleetPerPackage(asProduction, alertPage([], { producer: { state: 'stale' } }));
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({
        status: 'partial',
        fleetAnomalySignal: exampleSignal,
        supplyChainPage: {
          reason: "the page's producer state is 'stale'",
          alertsHeld: 0,
          total: 0,
          limit: 1000,
          producerState: 'stale',
        },
      });
    });

    it.each<[string, Record<string, unknown>, string]>([
      ["a producer state of 'incomplete'", alertPage([], { producer: { state: 'incomplete' } }), "the page's producer state is 'incomplete'"],
      ['no producer state', alertPage([], { producer: undefined }), 'the page states no producer state'],
      ['a producer with no state', alertPage([], { producer: {} }), 'the page states no producer state'],
      ['no total', alertPage([], { total: undefined }), 'the page states no total'],
      ['a total that is not a count', alertPage([], { total: '0' }), 'the page states no total'],
      [
        'the population of another package',
        alertPage([], { population: { name: 'other-package', packageType: 'mcp_server' } }),
        'the page counts another population',
      ],
      [
        'a population named without a type',
        alertPage([], { population: { name: 'example-agent', packageType: null } }),
        'the page counts another population',
      ],
      [
        'the population of one type',
        alertPage([], { population: { name: null, packageType: 'mcp_server' } }),
        'the page counts another population',
      ],
      ['no population', alertPage([], { population: undefined }), 'the page states no population'],
      [
        'only the alerts and the total',
        { alerts: [], total: 0 },
        'the page states no producer state; the page states no population',
      ],
    ])('is partial on a page that states %s', async (_case, page, reason) => {
      mockFleetPerPackage(asProduction, page);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({
        status: 'partial',
        fleetAnomalySignal: exampleSignal,
        supplyChainPage: expect.objectContaining({ reason, alertsHeld: 0 }),
      });
    });

    it('has none on a complete unfiltered page: its total is not above its alerts and its producer is current', async () => {
      mockFleetPerPackage(asProduction, alertPage(otherAlerts(3)));
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.fleetAnomalySignal?.anomalyScore).toBe(0.42);
        expect(result.intelligence.supplyChainAlerts).toEqual([]);
      }
      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });
      expect(cache.lookup('unknown-pkg')).toEqual({ status: 'error', reason: 'fleet anomaly signal not loaded' });
    });

    it("has none on the page for the package itself, and that page shows nothing about another package", async () => {
      mockFleetPerPackage(
        asProduction,
        alertPage([], { population: { name: 'Example-Agent', packageType: 'mcp_server' } }),
      );
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([]);
      }
      expect(cache.lookup('quiet-agent')).toEqual({
        status: 'partial',
        fleetAnomalySignal: null,
        supplyChainPage: {
          reason: 'the page counts another population',
          alertsHeld: 0,
          total: 0,
          limit: 1000,
          producerState: 'current',
        },
      });
    });

    it('is partial on the page for the package when that page holds fewer alerts than its total', async () => {
      mockFleetPerPackage(
        asProduction,
        alertPage([], { population: { name: 'example-agent', packageType: 'mcp_server' }, total: 2 }),
      );
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({
        status: 'partial',
        fleetAnomalySignal: exampleSignal,
        supplyChainPage: expect.objectContaining({ reason: 'the page holds 0 of 2 alerts', alertsHeld: 0, total: 2 }),
      });
    });

    it('is partial for a package with a fleet signal while no page has loaded', async () => {
      mockFleetPerPackage(asProduction, null);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({
        status: 'partial',
        fleetAnomalySignal: exampleSignal,
        supplyChainPage: {
          reason: 'no page has loaded',
          alertsHeld: 0,
          total: null,
          limit: null,
          producerState: null,
        },
      });
      // Without a fleet signal the package stays a miss, as before.
      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });
    });

    it('reads each page as it loads: complete after partial, then partial again', async () => {
      const cache = new RegistryIntelligenceCache(listed);

      mockFleetPerPackage(asProduction, cutPage());
      await cache.warm();
      expect(cache.lookup('example-agent').status).toBe('partial');

      mockFleetPerPackage(asProduction, alertPage([]));
      await cache.warm();
      expect(cache.lookup('example-agent').status).toBe('hit');

      mockFleetPerPackage(asProduction, cutPage());
      await cache.warm();
      expect(cache.lookup('example-agent').status).toBe('partial');
    });

    it('keeps the last page when a later alert request fails', async () => {
      const cache = new RegistryIntelligenceCache(listed);

      mockFleetPerPackage(asProduction, cutPage());
      await cache.warm();
      mockFleetPerPackage(asProduction, null);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual(
        expect.objectContaining({ status: 'partial', supplyChainPage: expect.objectContaining({ total: 14002 }) }),
      );
    });

    it('forgets the page on clearCache()', async () => {
      mockFleetPerPackage(asProduction, cutPage());
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();
      cache.clearCache();

      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'registry cache not warmed' });
    });
  });

  describe("a listed package's own alert answer, read by name and type when the cache warms, decides its result", () => {
    const FLEET_URL = 'https://api.oa2a.org/api/v1/registry/fleet/anomaly-signal';
    const listed: RegistryCacheOptions = {
      sourcePackages: [
        { name: 'example-agent', type: 'mcp_server' },
        { name: 'quiet-agent', type: 'mcp_server' },
      ],
    };
    const exampleSignal = expect.objectContaining({ name: 'example-agent', anomalyScore: 0.42 });
    /** The figures of the measured page (1,000 alerts of 14,002), which holds no alert for a listed package. */
    const MEASURED = {
      reason: 'the page holds 1000 of 14002 alerts',
      alertsHeld: 1000,
      total: 14002,
      limit: 1000,
      producerState: 'current',
    };
    /** A complete answer for each package: SUPPLY_ALERT for example-agent, no alert for any other. */
    const ownAlert = (name: string, packageType: string): AlertAnswer =>
      packageAnswer(name, packageType, name === 'example-agent' ? [SUPPLY_ALERT] : []);
    /** A complete answer with a total of 0 for each package. */
    const noAlert = (name: string, packageType: string): AlertAnswer => packageAnswer(name, packageType, []);

    it('is a hit with the alert row of its own answer while it is absent from the measured page', async () => {
      mockFleetPerPackage(asProduction, cutPage(), undefined, ownAlert);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([SUPPLY_ALERT]);
        expect(result.intelligence.fleetAnomalySignal).toEqual(exampleSignal);
      }
      // A package that is not listed keeps the page's answer: absent from that page, it is partial.
      expect(cache.lookup('unknown-pkg')).toEqual({ status: 'partial', fleetAnomalySignal: null, supplyChainPage: MEASURED });
    });

    it('takes the negative from its own complete answer with a total of 0: a miss without anomaly events, a hit with no alerts beside an anomaly signal', async () => {
      mockFleetPerPackage(asProduction, cutPage(), undefined, noAlert);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });
      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([]);
        expect(result.intelligence.fleetAnomalySignal).toEqual(exampleSignal);
      }
    });

    it.each<[string, AlertAnswer | null]>([
      ['answered with 500', { status: 500, body: { error: 'Failed to retrieve supply chain alerts' } }],
      ['answered with 429', { status: 429, body: { error: 'Rate limit exceeded' } }],
      ['not answered', null],
      ['answered with a body that is no alert page', { status: 200, body: { error: 'unexpected' } }],
      ['answered with the unfiltered page, as from a cache that ignores the query', { status: 200, body: cutPage() }],
    ])('is partial with the page figures, as before, when its own request is %s', async (_label, reply) => {
      mockFleetPerPackage(asProduction, cutPage(), undefined, () => reply);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({ status: 'partial', fleetAnomalySignal: exampleSignal, supplyChainPage: MEASURED });
      expect(cache.lookup('quiet-agent')).toEqual({ status: 'partial', fleetAnomalySignal: null, supplyChainPage: MEASURED });
    });

    it.each<[string, (name: string, packageType: string) => AlertAnswer, Record<string, unknown>]>([
      [
        "a producer state of 'stale'",
        (name, packageType) => packageAnswer(name, packageType, [], { producer: { state: 'stale' } }),
        { reason: "the page's producer state is 'stale'", alertsHeld: 0, total: 0, limit: 1000, producerState: 'stale' },
      ],
      [
        'the population of another package, even with a row that names this one',
        (_name, packageType) => packageAnswer('other-package', packageType, [{ ...SUPPLY_ALERT, id: 'misfiled' }]),
        { reason: 'the page counts another population', alertsHeld: 1, total: 1, limit: 1000, producerState: 'current' },
      ],
      [
        'a total above the alerts it carries',
        (name, packageType) => packageAnswer(name, packageType, [], { total: 2 }),
        { reason: 'the page holds 0 of 2 alerts', alertsHeld: 0, total: 2, limit: 1000, producerState: 'current' },
      ],
    ])('is partial, with the reason, when its own answer states %s', async (_label, own, supplyChainPage) => {
      mockFleetPerPackage(asProduction, cutPage(), undefined, own);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      expect(cache.lookup('example-agent')).toEqual({ status: 'partial', fleetAnomalySignal: exampleSignal, supplyChainPage });
    });

    it.each<[string, Record<string, unknown>]>([
      ["a producer state of 'stale'", { producer: { state: 'stale' } }],
      ['a total above the alerts it carries', { total: 5 }],
    ])('is a hit with the alert row of its own answer when that answer states %s', async (_label, overrides) => {
      mockFleetPerPackage(asProduction, cutPage(), undefined, (name, packageType) =>
        packageAnswer(name, packageType, name === 'example-agent' ? [SUPPLY_ALERT] : [], overrides));
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([SUPPLY_ALERT]);
      }
    });

    it('is a hit with a row the page holds for its name in another case and its type, beside its own answer of a total of 0', async () => {
      const otherCase: SupplyChainAlert = { ...SUPPLY_ALERT, id: 'alert-case', name: 'Example-Agent' };
      mockFleetPerPackage(asProduction, cutPage([...otherAlerts(999), otherCase]), undefined, noAlert);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([otherCase]);
      }

      // A row on both is counted once, by id.
      mockFleetPerPackage(asProduction, cutPage([...otherAlerts(998), SUPPLY_ALERT, otherCase]), undefined, ownAlert);
      await cache.warm();
      const united = cache.lookup('example-agent');
      expect(united.status).toBe('hit');
      if (united.status === 'hit') {
        expect(united.intelligence.supplyChainAlerts).toEqual([SUPPLY_ALERT, otherCase]);
      }
    });

    it('takes no row the page holds for its name with another type once its own answer is complete', async () => {
      const otherType: SupplyChainAlert = { ...SUPPLY_ALERT, id: 'alert-library', type: 'library' };
      mockFleetPerPackage(asProduction, cutPage([...otherAlerts(999), otherType]), undefined, noAlert);
      const cache = new RegistryIntelligenceCache(listed);
      await cache.warm();

      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([]);
      }
    });

    it('reads its own answer again each time the cache warms, keeps the last one when a later request fails, and forgets it on clearCache()', async () => {
      const cache = new RegistryIntelligenceCache(listed);
      const alertsOf = (name: string) => {
        const result = cache.lookup(name);
        return result.status === 'hit' ? result.intelligence.supplyChainAlerts : result.status;
      };

      mockFleetPerPackage(asProduction, cutPage(), undefined, ownAlert);
      await cache.warm();
      expect(alertsOf('example-agent')).toEqual([SUPPLY_ALERT]);

      mockFleetPerPackage(asProduction, cutPage(), undefined, noAlert);
      await cache.warm();
      expect(alertsOf('example-agent')).toEqual([]);

      mockFleetPerPackage(asProduction, cutPage(), undefined, () => null);
      await cache.warm();
      expect(alertsOf('example-agent')).toEqual([]);
      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });

      cache.clearCache();
      expect(cache.lookup('example-agent')).toEqual({ status: 'error', reason: 'registry cache not warmed' });
    });

    it('sends the alert request of a package added with addSourcePackages() once, and none for a package listed already', async () => {
      mockFleetPerPackage(asProduction, cutPage(), undefined, ownAlert);
      const cache = new RegistryIntelligenceCache({ sourcePackages: [{ name: 'quiet-agent', type: 'mcp_server' }] });
      await cache.warm();
      const calls = (global.fetch as jest.Mock).mock.calls;
      const fetched = calls.length;

      await cache.addSourcePackages([
        { name: 'example-agent', type: 'mcp_server' },
        { name: 'Quiet-Agent', type: 'mcp_server' },
      ]);
      await cache.addSourcePackages([{ name: 'example-agent', type: 'mcp_server' }]);

      expect(calls.slice(fetched).map(([url]) => String(url))).toEqual([
        `${FLEET_URL}?name=example-agent&type=mcp_server`,
        `${ALERTS_URL}&name=example-agent&packageType=mcp_server`,
      ]);
      const result = cache.lookup('example-agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([SUPPLY_ALERT]);
      }
      expect(cache.lookup('quiet-agent')).toEqual({ status: 'miss' });
      // lookup() sent none (AC-005).
      expect(calls).toHaveLength(fetched + 2);
    });

    it('reads a listed name with an upper-case letter as listed and lower-cased, and takes a negative only from both answers', async () => {
      const filedLower: SupplyChainAlert = { ...SUPPLY_ALERT, id: 'alert-lower' };
      const mixedCase: RegistryCacheOptions = { sourcePackages: [{ name: 'Example-Agent', type: 'mcp_server' }] };

      // A row filed under the lower-cased name stands.
      mockFleetPerPackage(asProduction, cutPage(), undefined, (name, packageType) =>
        packageAnswer(name, packageType, name === 'example-agent' ? [filedLower] : []));
      const cache = new RegistryIntelligenceCache(mixedCase);
      await cache.warm();
      const result = cache.lookup('Example-Agent');
      expect(result.status).toBe('hit');
      if (result.status === 'hit') {
        expect(result.intelligence.supplyChainAlerts).toEqual([filedLower]);
      }

      // Both answers complete with a total of 0: the negative. The Registry
      // reports no anomaly events for the name as listed, so it is a miss.
      mockFleetPerPackage(asProduction, cutPage(), undefined, noAlert);
      await cache.warm();
      expect(cache.lookup('Example-Agent')).toEqual({ status: 'miss' });

      // Without the answer under the lower-cased name: partial, with the page figures.
      mockFleetPerPackage(asProduction, cutPage(), undefined, (name, packageType) =>
        name === 'example-agent' ? null : packageAnswer(name, packageType, []));
      const fresh = new RegistryIntelligenceCache(mixedCase);
      await fresh.warm();
      expect(fresh.lookup('Example-Agent')).toEqual({ status: 'partial', fleetAnomalySignal: null, supplyChainPage: MEASURED });
    });
  });
});
