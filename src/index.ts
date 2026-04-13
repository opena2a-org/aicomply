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
  Verdict,
  RiskContext,
  PolicyPack,
  PolicyRule,
} from './types';

export { classifyWithRegex } from './classifier/regex';
export { classifyDualLayer } from './classifier/dual-layer';
export { GuardClient } from './classifier/guard-client';
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
import type { DualLayerOptions } from './classifier/dual-layer';
import type { ComplyOptions, ComplyResult } from './types';

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
 * @param options - Content to classify and optional policy/risk context
 * @param dualLayerOptions - Guard classification result and verification config
 * @returns Classification result with verdict and violations
 */
export async function comply(
  options: ComplyOptions,
  dualLayerOptions?: DualLayerOptions,
): Promise<ComplyResult> {
  if (!options?.content) {
    return {
      verdict: 'CLEAN',
      violations: [],
      classifierResults: {
        regex: { classifier: 'regex', verdict: 'CLEAN', violations: [] },
      },
    };
  }

  return classifyDualLayer(options.content, dualLayerOptions);
}
