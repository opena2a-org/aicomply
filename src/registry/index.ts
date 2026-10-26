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
 * answers 200 with that package's signal; warm() sends it for each listed
 * package: one in the sourcePackages option, or one added later with
 * addSourcePackages(), which sends it when it lists the package.
 */

import { showString } from '../show-string';
import type {
  RegistryIntelligence,
  RegistryCacheOptions,
  RegistryLookupResult,
  RegistrySourcePackage,
  FleetAnomalySignal,
  SupplyChainAlert,
  PartialSupplyChainPage,
} from './types';

export type { RegistryIntelligence, RegistryLookupResult, FleetAnomalySignal, SupplyChainAlert };
export type { RegistryCacheOptions, RegistrySourcePackage, PartialSupplyChainPage };

interface FleetAnomalyResponse {
  agents?: FleetAnomalySignal[];
  // Registry may also return a top-level array
  [key: string]: unknown;
}

/**
 * The Registry's answer to the supply-chain alert request. The fields beside
 * the alerts are read as sent and checked before use.
 */
interface SupplyChainResponse {
  alerts: SupplyChainAlert[];
  /** The size of the population the alerts come from, counted before the limit cut. */
  total?: unknown;
  /** The most alerts a page carries. */
  limit?: unknown;
  /** What `total` counts: `name` and `packageType`, each null when the request set no such filter. */
  population?: unknown;
  /** The detector that writes the alerts: `state` is 'current' when its latest cycle is recent and complete. */
  producer?: unknown;
}

/**
 * What a page's total counts: every package (no name or type filter), the
 * package with the lowercased `name` (a name and a type), another population
 * (any other filter), or nothing the page states.
 */
type PagePopulation =
  | { kind: 'every package' }
  | { kind: 'package'; name: string }
  | { kind: 'another' }
  | { kind: 'unstated' };

/** The supply-chain alert page the cache holds, as the page states itself. */
interface HeldSupplyChainPage {
  alertsHeld: number;
  total: number | null;
  limit: number | null;
  producerState: string | null;
  population: PagePopulation;
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
  /**
   * The listed packages, whose fleet signal warm() requests: those in the
   * sourcePackages option and those added with addSourcePackages(). Keyed by
   * package name (lowercased), as lookup() matches names.
   */
  private readonly sourcePackages = new Map<string, RegistrySourcePackage>();
  private readonly cache = new Map<string, RegistryIntelligence>();

  /**
   * Indexed by package name (lowercased) for O(1) lookup.
   * Populated by warm() or refreshed on demand.
   */
  private fleetIndex: Map<string, FleetAnomalySignal> = new Map();
  private supplyChainIndex: Map<string, SupplyChainAlert[]> = new Map();
  /**
   * The page supplyChainIndex was read from, as it states itself; null until
   * a page loads. A package with no alert in the index has none only when this
   * page is complete for it (supplyChainGap()).
   */
  private supplyChainPage: HeldSupplyChainPage | null = null;
  /** Answers to the fleet request for each listed package. */
  private packageFleet: Map<string, PackageFleetAnswer> = new Map();
  /** Fleet requests for listed packages that have not settled, by key. */
  private readonly packageRequests = new Map<string, Promise<void>>();
  private lastFleetFetch = 0;
  private lastSupplyChainFetch = 0;
  private fetchInProgress: Promise<void> | null = null;

  constructor(options: RegistryCacheOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.oa2a.org';
    this.cacheTtlMs = options.cacheTtlMs ?? 5 * 60 * 1000;
    this.timeoutMs = options.timeoutMs ?? 8_000;
    if (options.sourcePackages !== undefined) {
      for (const pkg of readSourcePackages(options.sourcePackages)) {
        this.sourcePackages.set(pkg.name.toLowerCase(), pkg);
      }
    }
  }

  /**
   * Warm the cache by fetching both endpoints, and the fleet signal of each
   * listed package.
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
   * List packages first seen after the cache was created, and request the
   * fleet signal of each by name and type, as warm() does for the
   * sourcePackages option; warm() requests them from then on. Resolves once
   * each request has been answered or has failed, so lookup() then reports
   * the packages as it reports those listed in the option.
   *
   * A package listed already, in the option or by an earlier call, is not
   * requested again; if a request for it is in flight, the call waits for
   * it. The list is checked as the option is, and a name listed already with
   * another type is rejected too: with a TypeError, before any package of
   * the call is listed or requested.
   *
   * Call it outside the classification hot path, as warm() (AC-005).
   */
  async addSourcePackages(sourcePackages: readonly RegistrySourcePackage[]): Promise<void> {
    const packages = readSourcePackages(sourcePackages);
    for (const [i, pkg] of packages.entries()) {
      const listed = this.sourcePackages.get(pkg.name.toLowerCase());
      if (listed !== undefined && listed.type !== pkg.type) {
        throw new TypeError(
          `sourcePackages[${i}] names ${showString(pkg.name, '"')} with type ${showString(pkg.type, '"')}, ` +
            `which is listed already with type ${showString(listed.type, '"')}; ` +
            'lookup() matches names without case, so list each package with one type',
        );
      }
    }
    const requests: Promise<void>[] = [];
    for (const pkg of packages) {
      const key = pkg.name.toLowerCase();
      if (!this.sourcePackages.has(key)) {
        this.sourcePackages.set(key, pkg);
        requests.push(this.requestPackageFleet(key, pkg));
        continue;
      }
      const inFlight = this.packageRequests.get(key);
      if (inFlight !== undefined) requests.push(inFlight);
    }
    await Promise.allSettled(requests);
  }

  /**
   * Look up Registry intelligence for a package.
   *
   * Returns a typed result - callers MUST handle the 'miss', 'partial' and
   * 'error' cases as elevated risk, not as clean (AC-002).
   *
   * An alert for the package on the supply-chain alert page is a hit. No alert
   * for it shows it has none only when the page is complete for it; otherwise
   * the lookup is 'partial', with the page's figures, never a hit with no
   * alerts.
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

    // No alert for the package on a page that is not complete for it is no
    // negative: the lookup is partial, whatever the fleet data. Before any
    // page has loaded, a package with a fleet signal, which would otherwise be
    // a hit with no alerts, is partial too; one without stays an error or a
    // miss, as below.
    if (supplyAlerts === null && (this.supplyChainPage !== null || fleetSignal !== null)) {
      const reason = supplyChainGap(this.supplyChainPage, key);
      if (reason !== null) {
        return {
          status: 'partial',
          supplyChainPage: {
            reason,
            alertsHeld: this.supplyChainPage?.alertsHeld ?? 0,
            total: this.supplyChainPage?.total ?? null,
            limit: this.supplyChainPage?.limit ?? null,
            producerState: this.supplyChainPage?.producerState ?? null,
          },
          fleetAnomalySignal: fleetSignal,
        };
      }
    }

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
   * package loaded. Answers for listed packages are not counted.
   */
  fleetIndexSize(): number {
    return this.fleetIndex.size;
  }

  /** Clear all cached data. */
  clearCache(): void {
    this.cache.clear();
    this.fleetIndex.clear();
    this.supplyChainIndex.clear();
    this.supplyChainPage = null;
    this.packageFleet.clear();
    this.lastFleetFetch = 0;
    this.lastSupplyChainFetch = 0;
  }

  // ---------------------------------------------------------------------------
  // Private fetch helpers
  // ---------------------------------------------------------------------------

  /**
   * When the fleet data last loaded: the fleet index, or while it has never
   * loaded, the oldest answer for a listed package (0 while one is missing).
   * Against a Registry that refuses the fleet index request, the listed
   * answers then set how often refreshIfStale() fetches again.
   */
  private fleetFetchedAt(): number {
    if (this.lastFleetFetch > 0 || this.sourcePackages.size === 0) {
      return this.lastFleetFetch;
    }
    let oldest = Infinity;
    for (const key of this.sourcePackages.keys()) {
      const answer = this.packageFleet.get(key);
      if (answer === undefined) return 0;
      oldest = Math.min(oldest, answer.fetchedAt);
    }
    return oldest;
  }

  private async _fetchAll(): Promise<void> {
    await Promise.allSettled([
      this._fetchFleet(),
      this._fetchSupplyChain(),
      ...Array.from(this.sourcePackages, ([key, pkg]) => this.requestPackageFleet(key, pkg)),
    ]);
    // Invalidate per-package cache entries so next lookup() rebuilds them
    this.cache.clear();
  }

  /**
   * Request the fleet signal of a listed package, or join the request for it
   * that is in flight. Once the request settles, the package's cached
   * lookup() result is dropped, so the next lookup() rebuilds it from what
   * loaded.
   */
  private requestPackageFleet(key: string, pkg: RegistrySourcePackage): Promise<void> {
    let request = this.packageRequests.get(key);
    if (request === undefined) {
      request = this._fetchPackageFleet(pkg).finally(() => {
        this.packageRequests.delete(key);
        this.cache.delete(key);
      });
      this.packageRequests.set(key, request);
    }
    return request;
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
      this.supplyChainPage = readSupplyChainPage(body, alerts.length);
      this.lastSupplyChainFetch = Date.now();
    } catch {
      // Network/timeout error - leave lastSupplyChainFetch unchanged
    } finally {
      clearTimeout(timer);
    }
  }
}

/** The page's own statement of what it answers for, read from the Registry's answer. */
function readSupplyChainPage(body: SupplyChainResponse, alertsHeld: number): HeldSupplyChainPage {
  const state = isRecord(body.producer) ? body.producer.state : undefined;
  return {
    alertsHeld,
    total: isCount(body.total) ? body.total : null,
    limit: isCount(body.limit) ? body.limit : null,
    producerState: typeof state === 'string' ? state : null,
    population: readPopulation(body.population),
  };
}

/**
 * What a page's `population` says its total counts. A filter the request did
 * not set is null: no name and no type is every package, and a name with a
 * type is that package.
 */
function readPopulation(population: unknown): PagePopulation {
  if (!isRecord(population)) return { kind: 'unstated' };
  const { name, packageType } = population;
  const unset = (value: unknown): boolean => value === null || value === undefined;
  if (unset(name) && unset(packageType)) return { kind: 'every package' };
  if (typeof name === 'string' && name !== '' && typeof packageType === 'string' && packageType !== '') {
    return { kind: 'package', name: name.toLowerCase() };
  }
  return { kind: 'another' };
}

/**
 * Why `page` cannot show that the package whose lowercased name is `key` has
 * no open supply-chain alert, or null when it can. A page can only when it is
 * complete for the package: its producer state is 'current', its total is not
 * above the alerts it carries, and its population is every package or that
 * package.
 */
function supplyChainGap(page: HeldSupplyChainPage | null, key: string): string | null {
  if (page === null) return 'no page has loaded';
  const gaps: string[] = [];
  if (page.total === null) {
    gaps.push('the page states no total');
  } else if (page.total > page.alertsHeld) {
    gaps.push(`the page holds ${page.alertsHeld} of ${page.total} alerts`);
  }
  if (page.producerState === null) {
    gaps.push('the page states no producer state');
  } else if (page.producerState !== 'current') {
    gaps.push(`the page's producer state is ${showString(page.producerState, "'")}`);
  }
  const { population } = page;
  if (population.kind === 'unstated') {
    gaps.push('the page states no population');
  } else if (population.kind === 'another' || (population.kind === 'package' && population.name !== key)) {
    gaps.push('the page counts another population');
  }
  return gaps.length > 0 ? gaps.join('; ') : null;
}

/** Whether `value` is a count: a whole number that is not negative. */
function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
 * Copy a sourcePackages list (the option, or the argument of
 * addSourcePackages()), rejecting one warm() could not request from: a value
 * that is not an array, an entry without a non-empty name and type, or a name
 * listed twice, which lookup(), matching names without case, could not tell
 * apart.
 */
function readSourcePackages(list: unknown): RegistrySourcePackage[] {
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
