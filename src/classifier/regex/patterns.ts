/**
 * Deterministic regex scan for sensitive data classification.
 *
 * The patterns themselves are data in `pack/patterns.json`, compiled once by
 * `./pack`. Each entry carries a detection regex and an optional named
 * validator for post-match verification (e.g., Luhn check for PANs, see
 * `./validators`). This module only runs them.
 */

import { PACK, type PatternDefinition, type PatternType } from './pack';

export { luhnCheck } from './validators';
export type { PatternDefinition, PatternType };

export interface PatternMatch {
  type: PatternType;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

/** Compiled patterns, in pack order. Pack order is scan and tie-break order. */
export const PATTERNS: PatternDefinition[] = PACK.patterns;

/**
 * True when the value is a reference to a credential rather than the
 * credential itself.
 *
 * `process.env.OPENAI_API_KEY` is the *remediated* shape -- it is exactly what
 * `opena2a protect` rewrites a hardcoded key into. Reporting it as a finding
 * makes two commands in the same CLI contradict each other and breaks CI on
 * correctly-fixed code (opena2a#254).
 *
 * The forms are the pack's `referenceForms`, each anchored `^...$` against the
 * captured value, so this suppresses a value that IS a reference and never one
 * that merely contains a reference-shaped substring (`process.envXABC...` stays
 * a finding). Exported so the dual-layer and any future non-regex consumer can
 * apply one definition instead of restating it.
 */
export function isEnvVarReference(value: string): boolean {
  const trimmed = value.trim();
  return PACK.referenceForms.some((form) => form.test(trimmed));
}

/**
 * Scan content against all patterns and return validated matches.
 */
export function scanPatterns(content: string): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const pattern of PATTERNS) {
    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(content)) !== null) {
      const fullMatch = match[0];
      const capturedValue = match[1] || fullMatch;

      // An env-var reference names a secret without carrying one. Skipping it
      // here (not per-pattern) keeps the definition in one place; the anchored
      // forms mean a literal sitting next to a reference still reports. The
      // same reference is capturable by any keyword rule -- the generic
      // api_key rule and the Bearer rule both matched it before this landed.
      if (isEnvVarReference(capturedValue)) {
        continue;
      }

      // Run validator if present
      if (pattern.validate && !pattern.validate(capturedValue)) {
        continue;
      }

      matches.push({
        type: pattern.type,
        value: capturedValue,
        start: match.index,
        end: match.index + fullMatch.length,
        confidence: pattern.confidence,
      });
    }
  }

  // Deduplicate overlapping matches: higher confidence wins
  matches.sort((a, b) => b.confidence - a.confidence);
  const deduped: PatternMatch[] = [];
  for (const m of matches) {
    const overlaps = deduped.some(
      (d) => m.start < d.end && m.end > d.start && m.value === d.value
    );
    if (!overlaps) {
      deduped.push(m);
    }
  }

  return deduped;
}
