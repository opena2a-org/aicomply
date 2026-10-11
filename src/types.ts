/**
 * Core types for the AIComply compliance classifier.
 */

import type { RegistryIntelligenceCache, RegistryCacheOptions, RegistryLookupResult } from './registry';
import type { NormalizationStep } from './normalize/types';
import type { NanoMindAdapterOptions } from './classifier/guard-client/nanomind-adapter';
export type { RegistryCacheOptions };

/**
 * What the Registry cache had for a source package. Derived structurally
 * from `RegistryLookupResult['status']` so the two cannot drift.
 *   - 'hit':   the package is in the fleet index or has supply-chain alerts.
 *   - 'miss':  the fleet index loaded and the package is in neither index.
 *   - 'error': the fleet index has never loaded (cache not warmed, or every
 *              fetch so far failed), or no cache was supplied to look the
 *              package up in.
 */
export type RegistryLookupStatus = RegistryLookupResult['status'];

/** The verdict a caller asks for when the Registry lookup is a miss or an error. */
export type RegistryUnknownAction = 'violation' | 'deny';
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
   * Which content view this match came from. 'normalized' is the canonical
   * stream (NFKC + zero-width-stripped). 'compact' / 'decoded-*' indicate the
   * match only surfaced after additional adversarial-mutation handling.
   * Set on every pattern match; absent on Guard, POLICY_DENY / POLICY_WARN,
   * SUPPLY_CHAIN_ALERT and FLEET_ANOMALY_ELEVATED findings, which do not
   * come from a content view.
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
   * comply() - use ClassificationSession or warmRegistryCache() to ensure
   * warm() has completed (AC-005: no Registry network I/O in the hot path).
   */
  registryCache?: RegistryIntelligenceCache;
  /**
   * Whether to attempt the semantic Guard layer. Defaults to true: comply()
   * sends one POST carrying the content verbatim to the nanomind-daemon
   * address (`http://127.0.0.1:47200/v1/infer`) for each non-empty input and
   * falls back to regex-only when nothing answers. Set to false to make no
   * such request; the result is then regex-only. A signed Guard result
   * supplied through the second argument is still verified.
   */
  useGuard?: boolean;
  /**
   * What to do when the Registry cannot vouch for `sourcePackage`: the lookup
   * is a miss or an error (see `registrySignals.status`). Unset, the verdict
   * is left as the classifiers set it. 'violation' raises CLEAN to VIOLATION;
   * 'deny' sets DENY. Either appends a REGISTRY_UNKNOWN violation. With
   * `sourcePackage` set and no `registryCache`, the lookup counts as an error.
   */
  onRegistryUnknown?: RegistryUnknownAction;
  /**
   * Where to reach the nanomind daemon for the Guard layer, e.g.
   * `{ baseUrl: 'http://10.0.0.5:47200' }`. Defaults to
   * `http://127.0.0.1:47200`. An unreachable address falls back to
   * regex-only, as the default address does.
   */
  guardOptions?: NanoMindAdapterOptions;
}

/**
 * Options for `ClassificationSession.create()`: the Registry cache settings
 * plus the Guard daemon settings every `session.comply()` call uses unless
 * the call passes its own `guardOptions`.
 */
export interface ClassificationSessionOptions extends RegistryCacheOptions {
  guardOptions?: NanoMindAdapterOptions;
}

/** A processing layer that ran on the content. */
export type ComplyLayer = 'normalize' | 'regex' | 'guard';

/** The pattern pack the regex layer ran, as exported by PACK_VERSION and PACK_SHA256. */
export interface PackIdentity {
  /** The pack's `packVersion`. */
  version: string;
  /** SHA-256 (hex) of the pack file's exact bytes. */
  sha256: string;
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
    /**
     * Outcome of the Registry lookup. Always set when registrySignals is
     * present. Only 'hit' means the Registry had data for the package: on
     * 'miss' and 'error' the scores below are null, and the verdict reflects
     * the lookup only when the caller set `onRegistryUnknown`.
     */
    status?: RegistryLookupStatus;
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
  /**
   * The pattern pack the regex layer ran. Always set by comply(), including
   * on DENY and on the empty-content short-circuit.
   */
  pack?: PackIdentity;
  /**
   * The layers that ran on the content, in order. 'guard' is listed only
   * when a Guard classification was accepted into the result (the daemon
   * answered, or a supplied Guard result passed signature verification), so
   * a regex-only fallback or a rejected signature never claims it. Empty when
   * there was no content to classify. Always set by comply().
   */
  layers?: ComplyLayer[];
}
