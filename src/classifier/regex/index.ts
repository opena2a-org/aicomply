/**
 * Deterministic regex-based content classifier.
 *
 * Scans content for sensitive data patterns (PII, credentials,
 * controlled markings) using validated regular expressions.
 */

import { scanPatterns, type PatternMatch } from './patterns';
import type { ClassifierResult, Violation } from '../../types';

export function classifyWithRegex(content: string): ClassifierResult {
  const matches = scanPatterns(content);

  const violations: Violation[] = matches.map((m: PatternMatch) => ({
    type: m.type,
    value: redact(m.value),
    start: m.start,
    end: m.end,
    confidence: m.confidence,
    classifier: 'regex' as const,
  }));

  return {
    classifier: 'regex',
    verdict: violations.length === 0 ? 'CLEAN' : 'VIOLATION',
    violations,
  };
}

/**
 * Redact matched value for safe logging -- show first 4 and last 2 chars.
 */
function redact(value: string): string {
  if (value.length <= 8) return '***REDACTED***';
  return value.slice(0, 4) + '...' + value.slice(-2);
}
