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
 *
 * Checked 2026-10-18: production answers the fleet request above, which names
 * no package, with 400 ("name and type query params are required"), so the
 * fleet index does not load from it. lookup() reports supply-chain alerts
 * without the fleet index. The fleet request that names a package,
 *   GET /api/v1/registry/fleet/anomaly-signal?name=<name>&type=<type>
 * answers 200 with that package's signal; warm() sends it for each package in
 * the sourcePackages option.
 */

import { showString } from '../show-string';
import type {
  RegistryIntelligence,
  RegistryCacheOptions,
  RegistryLookupResult,
  RegistrySourcePackage,
  FleetAnomalySignal,
  SupplyChainAlert,
} from './types';

export type { RegistryIntelligence, RegistryLookupResult, FleetAnomalySignal, SupplyChainAlert };
export type { RegistryCacheOptions, RegistrySourcePackage };

interface FleetAnomalyResponse {
  agents?: FleetAnomalySignal[];
  // Registry may also return a top-level array
  [key: string]: unknown;
}

interface SupplyChainResponse {
  alerts: SupplyChainAlert[];
  total: number;
}

/**
 * The Registry's answer to the fleet request for one listed package. A null
 * signal means the Registry reported no fleet events for it.
 */
interface PackageFleetAnswer {
  signal: FleetAnomalySignal | null;
  fetchedAt: number;
}

export class RegistryIntelligenceCache {
  private readonly baseUrl: string;
  private readonly cacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly sourcePackages: readonly RegistrySourcePackage[];
  private readonly cache = new Map<string, RegistryIntelligence>();

  /**
   * Indexed by package name (lowercased) for O(1) lookup.
   * Populated by warm() or refreshed on demand.
   */
  private fleetIndex: Map<string, FleetAnomalySignal> = new Map();
  private supplyChainIndex: Map<string, SupplyChainAlert[]> = new Map();
  /** Answers to the fleet request for each package in sourcePackages. */
  private packageFleet: Map<string, PackageFleetAnswer> = new Map();
  private lastFleetFetch = 0;
  private lastSupplyChainFetch = 0;
  private fetchInProgress: Promise<void> | null = null;

  constructor(options: RegistryCacheOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.oa2a.org';
    this.cacheTtlMs = options.cacheTtlMs ?? 5 * 60 * 1000;
    this.timeoutMs = options.timeoutMs ?? 8_000;
    this.sourcePackages = readSourcePackages(options.sourcePackages);
  }

  /**
   * Warm the cache by fetching both endpoints, and the fleet signal of each
   * package in sourcePackages.
   *
   * Call this once before entering the classification hot path (AC-005).
   * Resolves when every fetch completes (or fails gracefully).
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

    // A listed package's own answer comes first; one that reported no fleet
    // events leaves a signal from the fleet index in place.
    const answer = this.packageFleet.get(key);
    const fleetSignal = answer?.signal ?? this.fleetIndex.get(key) ?? null;
    const supplyAlerts = this.supplyChainIndex.get(key) ?? null;

    // The supply-chain hard block needs only the alert list, so an alert for
    // the package is a hit whether or not the fleet index loaded. Without the
    // fleet index or an answer for the package, a package with no alert is an
    // error, not a miss, so the caller elevates risk (AC-002).
    if (this.lastFleetFetch === 0 && answer === undefined && supplyAlerts === null) {
      return {
        status: 'error',
        reason: this.lastSupplyChainFetch > 0 ? 'fleet anomaly signal not loaded' : 'registry cache not warmed',
      };
    }

    if (fleetSignal === null && supplyAlerts === null) {
      // Package not found in either index => unknown (AC-002: elevate risk)
      return { status: 'miss' };
    }

    const intel: RegistryIntelligence = {
      packageName,
      fleetAnomalySignal: fleetSignal,
      supplyChainAlerts: supplyAlerts ?? [],
      fetchedAt: Math.max(this.lastFleetFetch, this.lastSupplyChainFetch, answer?.fetchedAt ?? 0),
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
      now - this.fleetFetchedAt() > this.cacheTtlMs ||
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

  /**
   * Fleet index size: the number of packages the fleet request that names no
   * package loaded. Answers for sourcePackages are not counted.
   */
  fleetIndexSize(): number {
    return this.fleetIndex.size;
  }

  /** Clear all cached data. */
  clearCache(): void {
    this.cache.clear();
    this.fleetIndex.clear();
    this.supplyChainIndex.clear();
    this.packageFleet.clear();
    this.lastFleetFetch = 0;
    this.lastSupplyChainFetch = 0;
  }

  // ---------------------------------------------------------------------------
  // Private fetch helpers
  // ---------------------------------------------------------------------------

  /**
   * When the fleet data last loaded: the fleet index, or while it has never
   * loaded, the oldest answer for a package in sourcePackages (0 while one is
   * missing). Against a Registry that refuses the fleet index request, the
   * listed answers then set how often refreshIfStale() fetches again.
   */
  private fleetFetchedAt(): number {
    if (this.lastFleetFetch > 0 || this.sourcePackages.length === 0) {
      return this.lastFleetFetch;
    }
    let oldest = Infinity;
    for (const pkg of this.sourcePackages) {
      const answer = this.packageFleet.get(pkg.name.toLowerCase());
      if (answer === undefined) return 0;
      oldest = Math.min(oldest, answer.fetchedAt);
    }
    return oldest;
  }

  private async _fetchAll(): Promise<void> {
    await Promise.allSettled([
      this._fetchFleet(),
      this._fetchSupplyChain(),
      ...this.sourcePackages.map(pkg => this._fetchPackageFleet(pkg)),
    ]);
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

  private async _fetchPackageFleet(pkg: RegistrySourcePackage): Promise<void> {
    const query = new URLSearchParams({ name: pkg.name, type: pkg.type });
    const url = `${this.baseUrl}/api/v1/registry/fleet/anomaly-signal?${query}`;
    const key = pkg.name.toLowerCase();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) {
        return; // keep the last answer for the package, if there is one
      }

      const body: unknown = await res.json();
      // An answer for another name, as from a cache that ignores the query,
      // is not this package's.
      if (!isFleetAnswerFor(body, key)) {
        return;
      }
      // The Registry answers a package it has no record of as it answers one
      // with no events in its window: eventCount 0. Only an answer with events
      // is a fleet signal; the other leaves the package a miss (AC-002).
      this.packageFleet.set(key, {
        signal: body.eventCount > 0 ? body : null,
        fetchedAt: Date.now(),
      });
    } catch {
      // Network/timeout error - keep the last answer for the package
    } finally {
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

/** Whether `body` is a fleet signal for the package whose lowercased name is `key`. */
function isFleetAnswerFor(body: unknown, key: string): body is FleetAnomalySignal {
  if (typeof body !== 'object' || body === null) return false;
  const { name, anomalyScore, eventCount } = body as Record<string, unknown>;
  return (
    typeof name === 'string' &&
    name.toLowerCase() === key &&
    Number.isFinite(anomalyScore) &&
    Number.isFinite(eventCount)
  );
}

/**
 * Copy the sourcePackages option, rejecting a list warm() could not request
 * from: an entry without a non-empty name and type, or a name listed twice,
 * which lookup(), matching names without case, could not tell apart.
 */
function readSourcePackages(list: unknown): RegistrySourcePackage[] {
  if (list === undefined) return [];
  if (!Array.isArray(list)) {
    throw new TypeError(`sourcePackages must be an array (got ${list === null ? 'null' : typeof list})`);
  }
  const packages: RegistrySourcePackage[] = [];
  const listedAt = new Map<string, number>();
  // An index loop, so a hole in the array is rejected rather than skipped.
  for (let i = 0; i < list.length; i++) {
    const entry: unknown = list[i];
    if (typeof entry !== 'object' || entry === null) {
      throw new TypeError(
        `sourcePackages[${i}] must be an object like { name: 'my-agent', type: 'mcp_server' } ` +
          `(got ${entry === null ? 'null' : typeof entry})`,
      );
    }
    const { name, type } = entry as Record<string, unknown>;
    const pkg = {
      name: nonEmptyString(name, `sourcePackages[${i}].name`),
      type: nonEmptyString(type, `sourcePackages[${i}].type`),
    };
    const key = pkg.name.toLowerCase();
    const first = listedAt.get(key);
    if (first !== undefined) {
      throw new TypeError(
        `sourcePackages[${i}] names ${showString(pkg.name, '"')}, which sourcePackages[${first}] names already; ` +
          'lookup() matches names without case, so list each package once',
      );
    }
    listedAt.set(key, i);
    packages.push(pkg);
  }
  return packages;
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value === 'string' && value !== '') return value;
  const got = typeof value === 'string' ? showString(value, '"') : value === null ? 'null' : typeof value;
  throw new TypeError(`${label} must be a non-empty string (got ${got})`);
}
