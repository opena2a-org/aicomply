/**
 * Registry intelligence cache client.
 *
 * Queries the OpenA2A Registry for threat intelligence
 * and caches results locally for low-latency lookups.
 *
 * STUB: V1 returns empty intelligence. V2 wires to Registry API.
 */

import type { RegistryIntelligence, RegistryCacheOptions } from './types';

export class RegistryIntelligenceCache {
  private readonly baseUrl: string;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, { data: RegistryIntelligence; fetchedAt: number }>();

  constructor(options: RegistryCacheOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.oa2a.org';
    this.cacheTtlMs = options.cacheTtlMs ?? 5 * 60 * 1000;
  }

  /**
   * Query intelligence for a package.
   * V1: returns null (stub). V2: fetches from Registry API.
   */
  async query(_packageName: string): Promise<RegistryIntelligence | null> {
    // V2: fetch from ${this.baseUrl}/v1/intelligence/${packageName}
    return null;
  }

  /**
   * Clear the local cache.
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Cache size for diagnostics.
   */
  cacheSize(): number {
    return this.cache.size;
  }
}
