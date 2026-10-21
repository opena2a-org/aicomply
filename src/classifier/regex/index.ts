/**
 * Deterministic regex-based content classifier.
 *
 * Scans content for sensitive data patterns (PII, credentials,
 * controlled markings) using validated regular expressions.
 *
 * In v1.0 the classifier accepts an optional view descriptor so the
 * dual-layer can scan multiple content views (normalized stream, compact
 * whitespace-stripped form, Base64/URL-decoded extractions) and tag each
 * finding with its source view and best-effort original-content range.
 */

import { scanPatterns, type PatternMatch } from './patterns';
import type { ClassifierResult, Violation, ViolationView } from '../../types';

export interface ScanViewOptions {
  /** Which content view this scan represents. Defaults to 'normalized'. */
  view?: ViolationView;
  /**
   * Map from positions in the scanned content to positions in the
   * original (pre-normalization) content. When omitted, original* fields
   * on violations equal start/end (i.e. content IS the original).
   */
  offsetMap?: ArrayLike<number>;
  /**
   * For decoded extractions, the enclosing token's range in the original
   * content. Findings inside a decoded segment are anchored to this
   * range regardless of where they sit inside `decoded`.
   */
  originalAnchor?: { start: number; end: number };
}

export function classifyWithRegex(
  content: string,
  options?: ScanViewOptions,
): ClassifierResult {
  const matches = scanPatterns(content);
  const view: ViolationView = options?.view ?? 'normalized';

  const violations: Violation[] = matches.map((m: PatternMatch) => {
    const violation: Violation = {
      type: m.type,
      value: redact(m.value),
      start: m.start,
      end: m.end,
      confidence: m.confidence,
      classifier: 'regex' as const,
      view,
    };

    if (options?.originalAnchor !== undefined) {
      violation.originalStart = options.originalAnchor.start;
      violation.originalEnd = options.originalAnchor.end;
    } else if (options?.offsetMap !== undefined) {
      const startIdx = options.offsetMap[m.start];
      const lastInIndex = m.end - 1;
      const endIdx = options.offsetMap[lastInIndex];
      if (startIdx !== undefined) violation.originalStart = startIdx;
      if (endIdx !== undefined) violation.originalEnd = endIdx + 1;
    } else {
      violation.originalStart = m.start;
      violation.originalEnd = m.end;
    }

    return violation;
  });

  return {
    classifier: 'regex',
    verdict: violations.length === 0 ? 'CLEAN' : 'VIOLATION',
    violations,
  };
}

/**
 * Redact matched value for safe logging. No prefix is ever revealed, and
 * the revealed suffix depends on the value's length: 8 characters or fewer
 * reveal nothing and are fully starred, length-preserving ('*' per
 * character); 9 to 12 characters give '...' plus the last 2; 13 or more
 * give '...' plus the last 4. So `123-45-6789` gives `...89`, and a
 * 7-character passport or record number shows none of its characters.
 */
function redact(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  if (value.length <= 12) return '...' + value.slice(-2);
  return '...' + value.slice(-4);
}
