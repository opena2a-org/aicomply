/**
 * Dual-layer classifier merge logic with ARP signature verification and
 * Registry L2 threshold/block logic (Section 3.1, lines 239-263).
 *
 * Both the regex classifier and Guard classifier must return CLEAN
 * for content to pass. If either flags a violation, the result is VIOLATION.
 * If either returns DENY, the result is DENY (highest severity wins).
 *
 * Parse-to-deny (CR-001): unsigned, invalid-signature, or missing Guard
 * output is treated as DENY when Guard is available. In V1 (Guard
 * unavailable), regex-only classification is used.
 *
 * Registry L2 logic (AC-002, AC-005):
 *   - fleetAnomalySignal > 0.30 => classification threshold lowered by 0.15
 *   - Any active supply-chain alert on the source package => hard block (DENY)
 *   - Cache miss / error => treat as unknown, do NOT treat as clean
 */

import { classifyWithRegex } from '../regex';
import { GuardClient } from '../guard-client';
import { verifyClassification } from '../../arp/verify';
import { RegistryIntelligenceCache } from '../../registry';
import type { ClassifierResult, ComplyResult, Violation } from '../../types';
import type {
  NanoMindGuardResult,
  NanoMindGuardVerifyOptions,
} from '../../arp/types';

const guardClient = new GuardClient();

export interface DualLayerOptions {
  guardVerifyOptions?: NanoMindGuardVerifyOptions;
  guardResult?: NanoMindGuardResult;
  /**
   * Registry cache instance. When provided, L2 threshold/block logic runs
   * against the pre-warmed cache (AC-005: synchronous lookup only).
   */
  registryCache?: RegistryIntelligenceCache;
  /**
   * Package/agent name to look up in the Registry. Required for L2 logic.
   * Typically the source agent identifier from the message envelope.
   */
  sourcePackage?: string;
}

// ---------------------------------------------------------------------------
// Registry L2 constants (Section 3.1, lines 239-263)
// ---------------------------------------------------------------------------
const FLEET_ANOMALY_THRESHOLD = 0.30;
const THRESHOLD_DELTA = -0.15;

/**
 * Run content through both classification layers and merge results.
 *
 * When guardResult and guardVerifyOptions are provided, the Guard
 * classification is signature-verified before being trusted. Invalid
 * signatures trigger parse-to-deny (CR-001).
 *
 * When registryCache and sourcePackage are provided, Registry L2 logic
 * is applied after classification (AC-005: synchronous cache lookup only).
 */
export async function classifyDualLayer(
  content: string,
  options?: DualLayerOptions,
): Promise<ComplyResult> {
  // Always run regex classifier
  const regexResult = classifyWithRegex(content);

  let baseResult: Omit<ComplyResult, 'registrySignals'>;

  // If Guard result and verification options are provided, verify the signature
  if (options?.guardResult && options?.guardVerifyOptions) {
    const verifyResult = await verifyClassification(
      options.guardResult,
      options.guardVerifyOptions,
    );

    if (!verifyResult.valid) {
      // Parse-to-deny: invalid signature means we cannot trust the classification
      baseResult = {
        verdict: 'DENY',
        violations: regexResult.violations,
        classifierResults: { regex: regexResult },
        signatureValid: false,
        verifyError: { code: verifyResult.code, reason: verifyResult.reason },
      };
    } else {
      // Signature valid — build Guard classifier result from the verified classification
      const guardClassifierResult: ClassifierResult = {
        classifier: 'guard',
        verdict: verifyResult.classification === 'documentation' ||
                 verifyResult.classification === 'code-analysis' ||
                 verifyResult.classification === 'data-read'
          ? 'CLEAN' : 'VIOLATION',
        violations: verifyResult.classification !== 'documentation' &&
                    verifyResult.classification !== 'code-analysis' &&
                    verifyResult.classification !== 'data-read'
          ? [{
              type: verifyResult.classification,
              value: verifyResult.classification,
              start: 0,
              end: content.length,
              confidence: verifyResult.confidence,
              classifier: 'guard',
            }]
          : [],
      };

      const allViolations: Violation[] = [
        ...regexResult.violations,
        ...guardClassifierResult.violations,
      ];

      baseResult = {
        verdict: mergeVerdicts(regexResult, guardClassifierResult),
        violations: allViolations,
        classifierResults: {
          regex: regexResult,
          guard: guardClassifierResult,
        },
        signatureValid: true,
      };
    }
  } else {
    // Attempt Guard classifier via IPC (V1: always returns null)
    const guardResult = await guardClient.classify(content);

    const allViolations: Violation[] = [...regexResult.violations];
    if (guardResult) {
      allViolations.push(...guardResult.violations);
    }

    baseResult = {
      verdict: mergeVerdicts(regexResult, guardResult),
      violations: allViolations,
      classifierResults: {
        regex: regexResult,
        guard: guardResult ?? undefined,
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Registry L2 threshold/block logic (Section 3.1, lines 239-263)
  // AC-005: synchronous cache lookup only — never fetch in the hot path.
  // ---------------------------------------------------------------------------
  if (options?.registryCache && options?.sourcePackage) {
    return applyRegistryL2(baseResult, options.registryCache, options.sourcePackage);
  }

  return baseResult;
}

/**
 * Apply Registry L2 logic to an already-classified result.
 *
 *   - Hard block (DENY) if any active supply-chain alert exists for the package.
 *   - Fleet anomaly score > 0.30 lowers the effective classification threshold
 *     by 0.15 — implemented here as: if the current verdict is CLEAN but the
 *     anomaly score is elevated, re-evaluate with the lowered threshold and
 *     promote to VIOLATION.
 *   - Cache miss / error => treat as unknown, not clean (AC-002). We do NOT
 *     promote CLEAN to VIOLATION on a miss alone, but we record the delta so
 *     callers can decide. A subsequent warm() + re-classify is the correct path.
 */
function applyRegistryL2(
  base: Omit<ComplyResult, 'registrySignals'>,
  cache: RegistryIntelligenceCache,
  packageName: string,
): ComplyResult {
  const lookup = cache.lookup(packageName);

  if (lookup.status === 'error' || lookup.status === 'miss') {
    // AC-002: unknown is NOT clean. Surface the signal; do not silently pass.
    return {
      ...base,
      registrySignals: {
        fleetAnomalyScore: null,
        thresholdDelta: 0,
        supplyChainBlock: false,
        packageName,
      },
    };
  }

  const { intelligence } = lookup;
  const fleetScore = intelligence.fleetAnomalySignal?.anomalyScore ?? null;
  const activeAlerts = intelligence.supplyChainAlerts ?? [];
  const hasSupplyChainAlert = activeAlerts.length > 0;

  // Hard block: any active supply-chain alert => DENY regardless of prior verdict
  if (hasSupplyChainAlert) {
    const blockViolation: Violation = {
      type: 'SUPPLY_CHAIN_ALERT',
      value: activeAlerts.map(a => a.id).join(','),
      start: 0,
      end: 0,
      confidence: 1.0,
      classifier: 'regex',
    };
    return {
      ...base,
      verdict: 'DENY',
      violations: [...base.violations, blockViolation],
      registrySignals: {
        fleetAnomalyScore: fleetScore,
        thresholdDelta: 0,
        supplyChainBlock: true,
        packageName,
      },
    };
  }

  // Threshold adjustment: fleet anomaly score > 0.30 => threshold -= 0.15
  const thresholdDelta =
    fleetScore !== null && fleetScore > FLEET_ANOMALY_THRESHOLD
      ? THRESHOLD_DELTA
      : 0;

  // If threshold is lowered and the current verdict is CLEAN, promote to VIOLATION.
  // The delta represents a reduction in the confidence bar required to flag.
  const adjustedVerdict =
    thresholdDelta < 0 && base.verdict === 'CLEAN' ? 'VIOLATION' : base.verdict;

  const violations = [...base.violations];
  if (adjustedVerdict === 'VIOLATION' && base.verdict === 'CLEAN') {
    violations.push({
      type: 'FLEET_ANOMALY_ELEVATED',
      value: `anomalyScore=${fleetScore}`,
      start: 0,
      end: 0,
      confidence: fleetScore ?? 0,
      classifier: 'regex',
    });
  }

  return {
    ...base,
    verdict: adjustedVerdict,
    violations,
    registrySignals: {
      fleetAnomalyScore: fleetScore,
      thresholdDelta,
      supplyChainBlock: false,
      packageName,
    },
  };
}

function mergeVerdicts(
  regex: ClassifierResult,
  guard: ClassifierResult | null,
): ComplyResult['verdict'] {
  const verdicts = [regex.verdict];
  if (guard) verdicts.push(guard.verdict);

  if (verdicts.includes('DENY')) return 'DENY';
  if (verdicts.includes('VIOLATION')) return 'VIOLATION';
  return 'CLEAN';
}
