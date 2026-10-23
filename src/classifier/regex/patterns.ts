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

/** The matches of one scan of the content, and the patterns it could not run. */
export interface PatternScan {
  /** The validated matches, as scanPatterns() returns them when every pattern ran. */
  matches: PatternMatch[];
  /**
   * Ids of the patterns the regex engine threw on for this content, in pack
   * order. The matches such a pattern found before the error are kept.
   */
  unevaluatedPatterns: string[];
}

/** Add the validated matches of `pattern` in `content` to `matches`. */
function collectMatches(pattern: PatternDefinition, content: string, matches: PatternMatch[]): void {
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

/** Every pattern's matches, and each pattern that threw with what it threw. */
function runPatterns(content: string): {
  matches: PatternMatch[];
  failures: Array<{ id: string; error: unknown }>;
} {
  const matches: PatternMatch[] = [];
  const failures: Array<{ id: string; error: unknown }> = [];

  for (const pattern of PATTERNS) {
    // An error the engine throws for one pattern, such as a RangeError when
    // it runs out of backtracking stack, ends that pattern's search only: the
    // next pattern still runs, and the matches of the others stand.
    try {
      collectMatches(pattern, content, matches);
    } catch (error) {
      failures.push({ id: pattern.id, error });
    } finally {
      pattern.regex.lastIndex = 0;
    }
  }

  // Deduplicate overlapping matches: higher confidence wins
  matches.sort((a, b) => b.confidence - a.confidence);
  return { matches: dropOverlappingRepeats(matches), failures };
}

/**
 * Scan content against all patterns and return the validated matches with
 * the ids of the patterns the regex engine could not run on it.
 */
export function scanEachPattern(content: string): PatternScan {
  const { matches, failures } = runPatterns(content);
  return { matches, unevaluatedPatterns: failures.map((f) => f.id) };
}

/**
 * Scan content against all patterns and return validated matches.
 *
 * When the regex engine could not run a pattern on the content, this throws
 * once every pattern has run, naming each such pattern, rather than return
 * the matches of the others as if the scan were whole. scanEachPattern()
 * returns those matches and the ids of the patterns that did not run.
 */
export function scanPatterns(content: string): PatternMatch[] {
  const { matches, failures } = runPatterns(content);
  if (failures.length > 0) {
    const first = failures[0].error;
    const reason = first instanceof Error ? `${first.name}: ${first.message}` : String(first);
    const one = failures.length === 1;
    throw new Error(
      `aicomply: pattern${one ? '' : 's'} ${failures.map((f) => f.id).join(', ')} ` +
        `${one ? 'was' : 'were'} not evaluated on this content (${reason}); scanEachPattern() ` +
        'returns the matches of the other patterns and the ids of those not evaluated',
    );
  }
  return matches;
}

/**
 * `matches` in their order, without each match whose range overlaps the range
 * of an earlier kept match with the same value. scanPatterns() passes its
 * matches highest confidence first, pack order breaking a tie, so of two
 * matches of one value at overlapping ranges the first in that order is kept.
 *
 * The kept matches of one value do not overlap one another, so ordered by
 * start, then end, each ends at or before the start of the next. Of those that
 * start before a match ends, the last in that order ends last, and the match
 * overlaps one of them only if it overlaps that one. Each match is compared
 * with that one kept match, found by binary search and a Fenwick tree, not
 * with every kept match: that took time that grew with the square of the
 * number of findings.
 */
export function dropOverlappingRepeats(matches: PatternMatch[]): PatternMatch[] {
  // The indices of the matches of each value, in match order.
  const byValue = new Map<string, number[]>();
  for (let i = 0; i < matches.length; i += 1) {
    const indices = byValue.get(matches[i].value);
    if (indices === undefined) byValue.set(matches[i].value, [i]);
    else indices.push(i);
  }

  const kept = new Uint8Array(matches.length);
  // The place of a match among the matches of its value ordered by start, then end.
  const place = new Int32Array(matches.length);
  for (const indices of byValue.values()) {
    if (indices.length === 1) {
      kept[indices[0]] = 1;
      continue;
    }
    const ordered = indices
      .slice()
      .sort((a, b) => matches[a].start - matches[b].start || matches[a].end - matches[b].end);
    ordered.forEach((index, p) => {
      place[index] = p;
    });
    // Fenwick tree over places: lastKept[k] is the last place of a kept match
    // among places k - (k & -k) to k - 1, or -1 when none of them is kept.
    const lastKept = new Int32Array(ordered.length + 1).fill(-1);
    for (const index of indices) {
      const { start, end } = matches[index];
      // The matches at places 0 to startsBefore - 1 start before this one ends.
      let startsBefore = 0;
      let hi = ordered.length;
      while (startsBefore < hi) {
        const mid = (startsBefore + hi) >>> 1;
        if (matches[ordered[mid]].start < end) startsBefore = mid + 1;
        else hi = mid;
      }
      let last = -1;
      for (let k = startsBefore; k > 0; k -= k & -k) {
        if (lastKept[k] > last) last = lastKept[k];
      }
      if (last !== -1 && matches[ordered[last]].end > start) continue;
      kept[index] = 1;
      const p = place[index];
      for (let k = p + 1; k <= ordered.length; k += k & -k) {
        if (lastKept[k] < p) lastKept[k] = p;
      }
    }
  }
  return matches.filter((_, i) => kept[i] === 1);
}
