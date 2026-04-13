/**
 * Dual-layer classifier merge logic.
 *
 * Both the regex classifier and Guard classifier must return CLEAN
 * for content to pass. If either flags a violation, the result is VIOLATION.
 * If either returns DENY, the result is DENY (highest severity wins).
 */

import { classifyWithRegex } from '../regex';
import { GuardClient } from '../guard-client';
import type { ClassifierResult, ComplyResult, Violation } from '../../types';

const guardClient = new GuardClient();

/**
 * Run content through both classification layers and merge results.
 */
export async function classifyDualLayer(content: string): Promise<ComplyResult> {
  // Always run regex classifier
  const regexResult = classifyWithRegex(content);

  // Attempt Guard classifier (returns null if unavailable in V1)
  const guardResult = await guardClient.classify(content);

  // Merge violations from both classifiers
  const allViolations: Violation[] = [...regexResult.violations];
  if (guardResult) {
    allViolations.push(...guardResult.violations);
  }

  // Determine final verdict: DENY > VIOLATION > CLEAN
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

/**
 * Merge verdicts from both classifiers.
 * DENY beats VIOLATION beats CLEAN.
 */
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
