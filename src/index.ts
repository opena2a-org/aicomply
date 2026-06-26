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
 * @param options - Either a bare string to classify, or an options object with
 *   `content` plus optional policy/risk/registry context. `comply('text')` is
 *   shorthand for `comply({ content: 'text' })`.
 * @param dualLayerOptions - Guard classification result and verification config
 * @returns Classification result with verdict and violations
 */
export async function comply(
  options: ComplyOptions | string,
  dualLayerOptions?: DualLayerOptions,
): Promise<ComplyResult> {
  // Convenience overload: a bare string is treated as { content: <string> } so
  // `comply('text')` works without wrapping. Anything that is neither a string
  // nor an options object is a caller mistake; name the expected shape rather
  // than the unhelpful "options must be an object".
  const opts: ComplyOptions =
    typeof options === 'string' ? { content: options } : (options as ComplyOptions);
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) {
    const got = opts === null ? 'null' : Array.isArray(opts) ? 'array' : typeof opts;
    throw new TypeError(
      `comply: expected a string or an options object like comply({ content: '...' }), got ${got}`,
    );
  }
  // Reject non-string content explicitly so consumers can't silently bypass
  // classification by passing a number, object, or array as content. Empty
  // string and missing content are allowed and short-circuit with a CLEAN
  // result + populated audit fields.
  if (opts.content !== undefined && typeof opts.content !== 'string') {
    throw new TypeError(
      `comply: options.content must be a string (got ${typeof opts.content})`,
    );
  }
  if (!opts.content) {
    // Empty / missing content. Populate the audit fields so consumers can
    // rely on `originalContent` / `normalizedContent` / `normalizations`
    // being present in the result type (per types.ts ComplyResult contract).
    return {
      verdict: 'CLEAN',
      violations: [],
      classifierResults: {
        regex: { classifier: 'regex', verdict: 'CLEAN', violations: [] },
      },
      originalContent: opts.content ?? '',
      normalizedContent: opts.content ?? '',
      normalizations: [],
    };
  }

  const mergedOptions: DualLayerOptions = {
    ...dualLayerOptions,
    ...(opts.sourcePackage !== undefined && { sourcePackage: opts.sourcePackage }),
    ...(opts.registryCache !== undefined && { registryCache: opts.registryCache }),
    ...(opts.policyPack !== undefined && { policyPack: loadPolicyPack(opts.policyPack) }),
    ...(opts.riskContext !== undefined && { riskContext: opts.riskContext }),
  };

  return classifyDualLayer(opts.content, mergedOptions);
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
