/**
 * Types for Registry intelligence cache client.
 */

export interface RegistryIntelligence {
  packageName: string;
  trustLevel: number;
  riskScore: number;
  threats: string[];
  lastUpdated: number;
}

export interface RegistryCacheOptions {
  baseUrl?: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
}
