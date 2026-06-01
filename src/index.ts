/**
 * @opena2a/aicomply -- Dual-layer compliance classifier for AI agent communications.
 *
 * Public API: comply() is the main entry point. Pass content and optional
 * policy/risk context, get back a verdict with violations.
 */

export type {
  ComplyOptions,
  ComplyResult,
  ClassifierResult,
  Violation,
  ViolationView,
  Verdict,
  RiskContext,
  PolicyPack,
  PolicyRule,
  RegistryCacheOptions,
  NormalizationStep,
  NormalizationTransform,
  DecodedExtraction,
} from './types';

export { normalize } from './normalize';

export { classifyWithRegex } from './classifier/regex';
export { classifyDualLayer } from './classifier/dual-layer';
export { GuardClient } from './classifier/guard-client';
export {
  classifyWithNanoMindDaemon,
  isNanoMindDaemonAvailable,
  mapInferResponseToClassifierResult,
  DEFAULT_NANOMIND_DAEMON_URL,
  DEFAULT_NANOMIND_TIMEOUT_MS,
  NANOMIND_INFER_ENDPOINT,
  NANOMIND_DEFAULT_INTENT,
} from './classifier/guard-client/nanomind-adapter';
export type { NanoMindAdapterOptions } from './classifier/guard-client/nanomind-adapter';
export type {
  NanoMindAttackClass,
  NanoMindInferRequest,
  NanoMindInferResponse,
  NanoMindErrorResponse,
} from './classifier/guard-client/types';
export { SessionVault } from './vault';
export { loadPolicyPack, validatePolicyConfig } from './policy';
export { assembleRiskContext } from './risk';
export { RegistryIntelligenceCache } from './registry';
export { ArpClient, verifyClassification, CLASSIFICATION_MIN_TIER, ABSOLUTE_DENY_CLASSES } from './arp';
export type {
  NanoMindGuardResult,
  NanoMindGuardVerifyOptions,
  NanoMindGuardVerifyResult,
  NanoMindGuardVerifyErrorCode,
  CapabilityManifest,
  CapabilityTier,
  EncodedHybridPublicKey,
  EncodedHybridSignature,
} from './arp';
export { scanPatterns, luhnCheck } from './classifier/regex/patterns';
export type { PatternMatch, PatternType } from './classifier/regex/patterns';

import { classifyDualLayer } from './classifier/dual-layer';
import { RegistryIntelligenceCache } from './registry';
import { loadPolicyPack } from './policy';
import type { DualLayerOptions } from './classifier/dual-layer';
import type { ComplyOptions, ComplyResult, RegistryCacheOptions } from './types';

export type { DualLayerOptions } from './classifier/dual-layer';

/**
 * Run compliance classification on content.
 *
 * This is the primary entry point. It runs the dual-layer classifier
 * (regex + Guard when available) and returns a verdict.
 *
 * When guardResult and guardVerifyOptions are provided via dualLayerOptions,
 * the Guard classification is signature-verified (Ed25519+ML-DSA-44) before
 * being trusted. Invalid signatures trigger parse-to-deny (CR-001).
 *
 * When sourcePackage and registryCache are set on options, Registry L2 logic
 * runs after classification (fleet anomaly threshold + supply-chain hard block).
 * The cache must be warmed before calling comply() - use ClassificationSession
 * or warmRegistryCache() to ensure this (AC-005: no network I/O in the hot path).
 *
 * @param options - Content to classify and optional policy/risk context
 * @param dualLayerOptions - Guard classification result and verification config
 * @returns Classification result with verdict and violations
 */
export async function comply(
  options: ComplyOptions,
  dualLayerOptions?: DualLayerOptions,
): Promise<ComplyResult> {
  // Reject non-string content explicitly so consumers can't silently
  // bypass classification by passing a number, object, array, or missing
  // key (`comply({})`). Empty string is allowed and short-circuits with
  // a CLEAN result + populated audit fields.
  if (options === null || typeof options !== 'object') {
    throw new TypeError('comply: options must be an object');
  }
  if (options.content !== undefined && typeof options.content !== 'string') {
    throw new TypeError(
      `comply: options.content must be a string (got ${typeof options.content})`,
    );
  }
  if (!options.content) {
    // Empty / missing content. Populate the audit fields so consumers can
    // rely on `originalContent` / `normalizedContent` / `normalizations`
    // being present in the result type (per types.ts ComplyResult contract).
    return {
      verdict: 'CLEAN',
      violations: [],
      classifierResults: {
        regex: { classifier: 'regex', verdict: 'CLEAN', violations: [] },
      },
      originalContent: options.content ?? '',
      normalizedContent: options.content ?? '',
      normalizations: [],
    };
  }

  const mergedOptions: DualLayerOptions = {
    ...dualLayerOptions,
    ...(options.sourcePackage !== undefined && { sourcePackage: options.sourcePackage }),
    ...(options.registryCache !== undefined && { registryCache: options.registryCache }),
    ...(options.policyPack !== undefined && { policyPack: loadPolicyPack(options.policyPack) }),
    ...(options.riskContext !== undefined && { riskContext: options.riskContext }),
  };

  return classifyDualLayer(options.content, mergedOptions);
}

/**
 * Create and warm a RegistryIntelligenceCache.
 *
 * Use this when you manage the cache lifecycle yourself (e.g., one warm-start
 * per request handler). For long-lived processes with multiple comply() calls,
 * prefer ClassificationSession which owns the full lifecycle.
 *
 * @example
 * const cache = await warmRegistryCache({ baseUrl: 'https://api.oa2a.org' });
 * const result = await comply({ content, sourcePackage: 'my-agent', registryCache: cache });
 */
export async function warmRegistryCache(
  options?: RegistryCacheOptions,
): Promise<RegistryIntelligenceCache> {
  const cache = new RegistryIntelligenceCache(options);
  await cache.warm();
  return cache;
}

/**
 * Session-scoped compliance classifier that owns the registry cache lifecycle.
 *
 * Warms the cache once on construction and exposes comply() for repeated calls
 * against the same warmed cache. Use refreshCache() to trigger a background
 * refresh when the TTL has expired.
 *
 * Prefer this over warmRegistryCache() when the same cache instance services
 * multiple comply() calls (e.g., an agent session or a request batch).
 *
 * @example
 * const session = await ClassificationSession.create({ baseUrl: 'https://api.oa2a.org' });
 * const result = await session.comply({ content, sourcePackage: 'my-agent' });
 * session.refreshCache(); // non-blocking; call when convenient
 */
export class ClassificationSession {
  private readonly cache: RegistryIntelligenceCache;

  private constructor(cache: RegistryIntelligenceCache) {
    this.cache = cache;
  }

  /**
   * Create a session with a warmed registry cache.
   * Resolves after warm() completes (both fleet and supply-chain endpoints fetched).
   */
  static async create(options?: RegistryCacheOptions): Promise<ClassificationSession> {
    const cache = new RegistryIntelligenceCache(options);
    await cache.warm();
    return new ClassificationSession(cache);
  }

  /**
   * Run compliance classification, applying L2 registry logic when sourcePackage
   * is provided. Uses the session's warmed cache - no network I/O in the hot path.
   */
  async comply(
    options: ComplyOptions,
    dualLayerOptions?: DualLayerOptions,
  ): Promise<ComplyResult> {
    const optionsWithCache: ComplyOptions = {
      ...options,
      registryCache: options.registryCache ?? this.cache,
    };
    return comply(optionsWithCache, dualLayerOptions);
  }

  /**
   * Trigger a background refresh of the registry cache if stale.
   * Non-blocking - returns immediately and does not affect in-flight classifies.
   */
  refreshCache(): void {
    this.cache.refreshIfStale();
  }
}
