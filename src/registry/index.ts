/**
 * Registry intelligence cache client.
 *
 * Queries the OpenA2A Registry for fleet anomaly signals and supply-chain
 * alerts, caches results in-process, and surfaces them to the dual-layer
 * classifier for L2 threshold/block logic.
 *
 * Design constraints:
 *   AC-002: cache miss != clean. Missing or failed data => "unknown" risk.
 *   AC-005: never called in the classification hot path. Callers must
 *           warm-start the cache before classifying (warm()) and may
 *           trigger a background refresh on miss.
 *
 * Endpoints (production, verified live 2026-04-14):
 *   GET /api/v1/registry/fleet/anomaly-signal
 *   GET /api/v1/intelligence/alerts?type=supply_chain
 */

import type {
  RegistryIntelligence,
  RegistryCacheOptions,
  RegistryLookupResult,
  FleetAnomalySignal,
  SupplyChainAlert,
} from './types';

export type { RegistryIntelligence, RegistryLookupResult, FleetAnomalySignal, SupplyChainAlert };
export type { RegistryCacheOptions };

interface FleetAnomalyResponse {
  agents?: FleetAnomalySignal[];
  // Registry may also return a top-level array
  [key: string]: unknown;
}

interface SupplyChainResponse {
  alerts: SupplyChainAlert[];
  total: number;
}

export class RegistryIntelligenceCache {
  private readonly baseUrl: string;
  private readonly cacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly cache = new Map<string, RegistryIntelligence>();

  /**
   * Indexed by package name (lowercased) for O(1) lookup.
   * Populated by warm() or refreshed on demand.
   */
  private fleetIndex: Map<string, FleetAnomalySignal> = new Map();
  private supplyChainIndex: Map<string, SupplyChainAlert[]> = new Map();
  private lastFleetFetch = 0;
  private lastSupplyChainFetch = 0;
  private fetchInProgress: Promise<void> | null = null;

  constructor(options: RegistryCacheOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.oa2a.org';
    this.cacheTtlMs = options.cacheTtlMs ?? 5 * 60 * 1000;
    this.timeoutMs = options.timeoutMs ?? 8_000;
  }

  /**
   * Warm the cache by fetching both endpoints.
   *
   * Call this once before entering the classification hot path (AC-005).
   * Resolves when both fetches complete (or fail gracefully).
   */
  async warm(): Promise<void> {
    if (this.fetchInProgress) {
      return this.fetchInProgress;
    }
    this.fetchInProgress = this._fetchAll().finally(() => {
      this.fetchInProgress = null;
    });
    return this.fetchInProgress;
  }

  /**
   * Look up Registry intelligence for a package.
   *
   * Returns a typed result - callers MUST handle the 'miss' and 'error'
   * cases as elevated risk, not as clean (AC-002).
   *
   * This method is intentionally synchronous after warm-start (cache read).
   * It does NOT trigger network I/O to preserve hot-path latency (AC-005).
   */
  lookup(packageName: string): RegistryLookupResult {
    const key = packageName.toLowerCase();
    const now = Date.now();

    const cached = this.cache.get(key);
    if (cached && now - cached.fetchedAt < this.cacheTtlMs) {
      return { status: 'hit', intelligence: cached };
    }

    // Check if fleet data is available but package is simply not in the index
    const fleetDataLoaded = this.lastFleetFetch > 0;
    if (!fleetDataLoaded) {
      // Cache was never warmed - report as error so caller elevates risk
      return { status: 'error', reason: 'registry cache not warmed' };
    }

    const fleetSignal = this.fleetIndex.get(key) ?? null;
    const supplyAlerts = this.supplyChainIndex.get(key) ?? null;

    if (fleetSignal === null && supplyAlerts === null) {
      // Package not found in either index => unknown (AC-002: elevate risk)
      return { status: 'miss' };
    }

    const intel: RegistryIntelligence = {
      packageName,
      fleetAnomalySignal: fleetSignal,
      supplyChainAlerts: supplyAlerts ?? [],
      fetchedAt: Math.max(this.lastFleetFetch, this.lastSupplyChainFetch),
    };
    this.cache.set(key, intel);
    return { status: 'hit', intelligence: intel };
  }

  /**
   * Trigger a background refresh if the cache is stale.
   * Does not block - returns immediately. Safe to call after lookup()
   * reveals a cache miss or stale entry.
   */
  refreshIfStale(): void {
    const now = Date.now();
    const stale =
      now - this.lastFleetFetch > this.cacheTtlMs ||
      now - this.lastSupplyChainFetch > this.cacheTtlMs;

    if (stale && !this.fetchInProgress) {
      this.warm().catch(() => {
        // Background refresh failures are silent; next lookup will retry
      });
    }
  }

  /** Cache size for diagnostics. */
  cacheSize(): number {
    return this.cache.size;
  }

  /** Fleet index size (number of known packages). */
  fleetIndexSize(): number {
    return this.fleetIndex.size;
  }

  /** Clear all cached data. */
  clearCache(): void {
    this.cache.clear();
    this.fleetIndex.clear();
    this.supplyChainIndex.clear();
    this.lastFleetFetch = 0;
    this.lastSupplyChainFetch = 0;
  }

  // ---------------------------------------------------------------------------
  // Private fetch helpers
  // ---------------------------------------------------------------------------

  private async _fetchAll(): Promise<void> {
    await Promise.allSettled([this._fetchFleet(), this._fetchSupplyChain()]);
    // Invalidate per-package cache entries so next lookup() rebuilds them
    this.cache.clear();
  }

  private async _fetchFleet(): Promise<void> {
    const url = `${this.baseUrl}/api/v1/registry/fleet/anomaly-signal`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) {
        return; // leave lastFleetFetch at 0 so callers know data is unavailable
      }

      const body: FleetAnomalyResponse = await res.json() as FleetAnomalyResponse;
      const agents: FleetAnomalySignal[] = Array.isArray(body)
        ? (body as FleetAnomalySignal[])
        : (body.agents ?? []);

      const index = new Map<string, FleetAnomalySignal>();
      for (const agent of agents) {
        index.set(agent.name.toLowerCase(), agent);
      }
      this.fleetIndex = index;
      this.lastFleetFetch = Date.now();
    } catch {
      // Network/timeout error - leave lastFleetFetch unchanged
    } finally {
      // Always clear the abort timer so it doesn't keep the event loop alive
      // when fetch resolves successfully OR when it rejects/aborts.
      clearTimeout(timer);
    }
  }

  private async _fetchSupplyChain(): Promise<void> {
    const url = `${this.baseUrl}/api/v1/intelligence/alerts?type=supply_chain`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, { signal: controller.signal });

      if (!res.ok) {
        return;
      }

      const body: SupplyChainResponse = await res.json() as SupplyChainResponse;
      const alerts: SupplyChainAlert[] = body.alerts ?? [];

      // Group alerts by package name for O(1) lookup
      const index = new Map<string, SupplyChainAlert[]>();
      for (const alert of alerts) {
        const key = alert.name.toLowerCase();
        const existing = index.get(key) ?? [];
        existing.push(alert);
        index.set(key, existing);
      }
      this.supplyChainIndex = index;
      this.lastSupplyChainFetch = Date.now();
    } catch {
      // Network/timeout error - leave lastSupplyChainFetch unchanged
    } finally {
      clearTimeout(timer);
    }
  }
}
