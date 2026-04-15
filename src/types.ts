/**
 * Core types for the AIComply compliance classifier.
 */

import type { RegistryIntelligenceCache, RegistryCacheOptions } from './registry';
export type { RegistryCacheOptions };

export type Verdict = 'CLEAN' | 'VIOLATION' | 'DENY';

export interface Violation {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
  classifier: 'regex' | 'guard';
}

export interface ClassifierResult {
  classifier: 'regex' | 'guard';
  verdict: Verdict;
  violations: Violation[];
}

export interface RiskContext {
  agentId?: string;
  sessionId?: string;
  trustLevel?: number;
  sourceRegistry?: string;
  behavioralRiskScore?: number;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  patterns: string[];
  action: 'DENY' | 'REDACT' | 'WARN';
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface PolicyPack {
  name: string;
  version: string;
  rules: PolicyRule[];
}

export interface ComplyOptions {
  content: string;
  policyPack?: string;
  riskContext?: RiskContext;
  /**
   * Name of the source package/agent for Registry L2 lookup.
   * Required (along with registryCache) to activate L2 threshold/block logic.
   */
  sourcePackage?: string;
  /**
   * Pre-warmed Registry intelligence cache. Must be warmed before calling
   * comply() — use ClassificationSession or warmRegistryCache() to ensure
   * warm() has completed (AC-005: no network I/O in the hot path).
   */
  registryCache?: RegistryIntelligenceCache;
}

export interface ComplyResult {
  verdict: Verdict;
  violations: Violation[];
  classifierResults: {
    regex: ClassifierResult;
    guard?: ClassifierResult;
  };
  signatureValid?: boolean;
  verifyError?: {
    code: string;
    reason: string;
  };
  /**
   * Registry intelligence signals applied during L2 threshold/block logic.
   * Present when registry data was consulted (Task 6 / Section 3.1).
   */
  registrySignals?: {
    fleetAnomalyScore: number | null;
    thresholdDelta: number;
    supplyChainBlock: boolean;
    packageName?: string;
  };
}
