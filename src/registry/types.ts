/**
 * Types for Registry intelligence cache client.
 */

/** Agent/package type as returned by the Registry fleet endpoint. */
export type RegistryAgentType = 'library' | 'mcp_server' | 'ai_tool' | 'llm' | 'skill';

/** Fleet anomaly signal for a single package from the Registry. */
export interface FleetAnomalySignal {
  name: string;
  type: RegistryAgentType;
  anomalyScore: number;     // 0..1
  eventCount: number;
  lastSeenAt: string;       // ISO 8601
  formulaVersion: string;
  stale: boolean;
}

/** Single supply-chain alert from the Registry intelligence endpoint. */
export interface SupplyChainAlert {
  id: string;
  name: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  reason: string;
  cve?: string;
  publishedAt: string;      // ISO 8601
  referenceUrl?: string;
}

/** Combined intelligence for a package from both Registry endpoints. */
export interface RegistryIntelligence {
  packageName: string;
  /**
   * Fleet anomaly signal. null means the package was not found in the
   * fleet index - treat as "unknown", not clean (AC-002).
   */
  fleetAnomalySignal: FleetAnomalySignal | null;
  /**
   * Active supply-chain alerts for this package.
   * Empty array = no active alerts. null = fetch failed (AC-002: treat as unknown).
   */
  supplyChainAlerts: SupplyChainAlert[] | null;
  fetchedAt: number;        // epoch ms
}

export interface RegistryCacheOptions {
  baseUrl?: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
}

/** Result of a registry intelligence lookup (after AC-002 semantics applied). */
export type RegistryLookupResult =
  | { status: 'hit'; intelligence: RegistryIntelligence }
  | { status: 'miss' }           // package not in fleet index
  | { status: 'error'; reason: string };  // fetch failed
