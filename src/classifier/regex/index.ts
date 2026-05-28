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
  offsetMap?: number[];
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
 * Redact matched value for safe logging — show first 4 and last 2 chars
 * when the value is long enough that the prefix/suffix don't reveal the
 * full secret. Threshold of 6 chars (down from 8) ensures shorter MRNs
 * (typically 6-12 chars) get the same partial-redaction treatment as
 * longer credentials, so downstream audit dashboards see a consistent
 * shape across detection classes. Values of 6 chars or fewer (rare in
 * the regex set) fall back to a length-preserving full-mask so the
 * shape is still visible without leaking the bytes.
 */
function redact(value: string): string {
  if (value.length <= 6) return '*'.repeat(value.length);
  return value.slice(0, 4) + '...' + value.slice(-2);
}
