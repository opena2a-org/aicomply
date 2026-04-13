/**
 * Dual-layer classifier merge logic with ARP signature verification.
 *
 * Both the regex classifier and Guard classifier must return CLEAN
 * for content to pass. If either flags a violation, the result is VIOLATION.
 * If either returns DENY, the result is DENY (highest severity wins).
 *
 * Parse-to-deny (CR-001): unsigned, invalid-signature, or missing Guard
 * output is treated as DENY when Guard is available. In V1 (Guard
 * unavailable), regex-only classification is used.
 */

import { classifyWithRegex } from '../regex';
import { GuardClient } from '../guard-client';
import { verifyClassification } from '../../arp/verify';
import type { ClassifierResult, ComplyResult, Violation } from '../../types';
import type {
  NanoMindGuardResult,
  NanoMindGuardVerifyOptions,
} from '../../arp/types';

const guardClient = new GuardClient();

export interface DualLayerOptions {
  guardVerifyOptions?: NanoMindGuardVerifyOptions;
  guardResult?: NanoMindGuardResult;
}

/**
 * Run content through both classification layers and merge results.
 *
 * When guardResult and guardVerifyOptions are provided, the Guard
 * classification is signature-verified before being trusted. Invalid
 * signatures trigger parse-to-deny (CR-001).
 */
export async function classifyDualLayer(
  content: string,
  options?: DualLayerOptions,
): Promise<ComplyResult> {
  // Always run regex classifier
  const regexResult = classifyWithRegex(content);

  // If Guard result and verification options are provided, verify the signature
  if (options?.guardResult && options?.guardVerifyOptions) {
    const verifyResult = await verifyClassification(
      options.guardResult,
      options.guardVerifyOptions,
    );

    if (!verifyResult.valid) {
      // Parse-to-deny: invalid signature means we cannot trust the classification
      return {
        verdict: 'DENY',
        violations: regexResult.violations,
        classifierResults: { regex: regexResult },
        signatureValid: false,
        verifyError: { code: verifyResult.code, reason: verifyResult.reason },
      };
    }

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

    const verdict = mergeVerdicts(regexResult, guardClassifierResult);

    return {
      verdict,
      violations: allViolations,
      classifierResults: {
        regex: regexResult,
        guard: guardClassifierResult,
      },
      signatureValid: true,
    };
  }

  // Attempt Guard classifier via IPC (V1: always returns null)
  const guardResult = await guardClient.classify(content);

  const allViolations: Violation[] = [...regexResult.violations];
  if (guardResult) {
    allViolations.push(...guardResult.violations);
  }

  const verdict = mergeVerdicts(regexResult, guardResult);

  return {
    verdict,
    violations: allViolations,
    classifierResults: {
      regex: regexResult,
      guard: guardResult ?? undefined,
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
