/**
 * Core types for the AIComply compliance classifier.
 */

import type { RegistryIntelligenceCache, RegistryCacheOptions } from './registry';
import type { NormalizationStep } from './normalize/types';
export type { RegistryCacheOptions };
export type { NormalizationStep, NormalizationTransform, DecodedExtraction } from './normalize/types';

export type Verdict = 'CLEAN' | 'VIOLATION' | 'DENY';

/**
 * Where a regex match was found. Derived structurally from
 * `DecodedExtraction['source']` so that adding a new view type (e.g.
 * `'decoded-hex'` in a future release) updates this union in lockstep
 * without a manual edit. `'normalized'` is the canonical view; the
 * others mirror the discriminated set of extra content views.
 */
import type { DecodedExtraction as DecodedExtractionT } from './normalize/types';
export type ViolationView = 'normalized' | DecodedExtractionT['source'];

export interface Violation {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
  classifier: 'regex' | 'guard';
  /**
   * Which content view this match came from. 'normalized' is the default
   * (NFKC + zero-width-stripped). 'compact' / 'decoded-*' indicate the
   * match only surfaced after additional adversarial-mutation handling.
   */
  view?: ViolationView;
  /**
   * Best-effort start position in the ORIGINAL (pre-normalization) content.
   * May equal `start` when no transforms changed offsets. For decoded
   * extractions, points at the enclosing encoded token in the original.
   */
  originalStart?: number;
  /**
   * Best-effort end position in the ORIGINAL content.
   */
  originalEnd?: number;
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
    /** Anomaly score after applying the trust-level sensitivity multiplier. */
    effectiveAnomalyScore: number | null;
    /** Multiplier applied to fleetAnomalyScore based on Registry trust tier. */
    trustSensitivityMultiplier: number;
    thresholdDelta: number;
    supplyChainBlock: boolean;
    packageName?: string;
  };
  /**
   * The input as received, byte-identical to the caller's `content`.
   * Always set in v1.0+ so consumers can build their own audit trails.
   */
  originalContent?: string;
  /**
   * The canonicalized form after NFKC + zero-width / bidi-control stripping.
   * Equals originalContent when no transforms applied.
   */
  normalizedContent?: string;
  /**
   * Ordered list of normalization transforms applied to produce
   * normalizedContent and the compact / decoded views that were scanned.
   * Empty when the input required no canonicalization.
   */
  normalizations?: NormalizationStep[];
}
