/**
 * Generate a "compact" view of content with whitespace removed from
 * inside what would otherwise be a single token of digits/separators.
 *
 * Whitespace injection ("1 2 3 - 4 5 - 6 7 8 9") is a common evasion.
 * Naively stripping ALL whitespace breaks legitimate prose because
 * patterns like SSN rely on word boundaries ("My SSN" → "MySSN"
 * eliminates `\b` before the digits). Instead we strip whitespace
 * only when BOTH neighbors are in the set {digit, '-', '_', '/', '.',
 * ':'} - characters that appear inside SSNs, PANs, IBANs, MRNs, NPIs,
 * passport numbers. The boundary characters around such a run remain
 * intact, so the regex's word boundaries still fire.
 *
 * Strips runs of:
 *   - ASCII whitespace (space, tab, CR, LF, VT, FF)
 *   - Non-zero-width Unicode whitespace (U+00A0 NBSP, U+1680, U+2000–
 *     U+200A, U+2028, U+2029, U+202F, U+205F, U+3000)
 *
 * Does NOT strip zero-width characters (those are handled by
 * `stripZeroWidth` in the main normalization chain).
 *
 * Credential whitespace-injection ("ghp_AB CDEF...") is out of scope
 * for the digit-compact view; credentials follow a different shape and
 * are addressed by the Base64/URL decode paths and the canonical
 * normalized stream.
 */

import { OffsetMapBuilder, offsetMapToArray, type OffsetMap } from './offset-map';

const ASCII_WHITESPACE: ReadonlySet<number> = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20,
]);

const UNICODE_WHITESPACE: ReadonlySet<number> = new Set([
  0x00a0,
  0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
  0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f,
  0x3000,
]);

export interface CompactFormResult {
  /** Whitespace-removed view of the input. */
  compact: string;
  /** offsetMap[i] = index in INPUT where compact[i] originated. */
  offsetMap: number[];
  /** Number of code units stripped. */
  removedCount: number;
}

function isWhitespace(cp: number): boolean {
  return ASCII_WHITESPACE.has(cp) || UNICODE_WHITESPACE.has(cp);
}

/** Characters that can sit on either side of a stripped whitespace run. */
function isTokenChar(cp: number): boolean {
  // digits 0-9
  if (cp >= 0x30 && cp <= 0x39) return true;
  // separators commonly found inside SSN/PAN/IBAN/MRN/NPI/passport numbers
  return cp === 0x2d || cp === 0x5f || cp === 0x2f || cp === 0x2e || cp === 0x3a;
}

/** A CompactFormResult with the offset map as an OffsetMap. */
export interface CompactStage {
  compact: string;
  offsets: OffsetMap;
  removedCount: number;
}

export function buildCompactForm(input: string): CompactFormResult {
  const { compact, offsets, removedCount } = compactStage(input);
  return { compact, offsetMap: offsetMapToArray(offsets, compact.length), removedCount };
}

/**
 * buildCompactForm() with the map as an OffsetMap. Every whitespace and token
 * character is one code unit outside the surrogate range, so the input is read
 * a code unit at a time, and each run between two stripped whitespace runs
 * goes to the output as one slice of the input.
 */
export function compactStage(input: string): CompactStage {
  const parts: string[] = [];
  const offsets = new OffsetMapBuilder(input.length);
  let removed = 0;
  // input[copied, i) is a run that goes to the output as it is.
  let copied = 0;
  let i = 0;
  while (i < input.length) {
    if (!isWhitespace(input.charCodeAt(i))) {
      i += 1;
      continue;
    }
    // Whitespace run input[i, end). The character before it is not
    // whitespace, so it is the last one emitted.
    let end = i + 1;
    while (end < input.length && isWhitespace(input.charCodeAt(end))) end += 1;
    const stripRun = i > 0 && end < input.length
      && isTokenChar(input.charCodeAt(i - 1)) && isTokenChar(input.charCodeAt(end));
    if (stripRun) {
      parts.push(input.slice(copied, i));
      offsets.copy(copied, i - copied);
      removed += end - i;
      copied = end;
    }
    i = end;
  }
  offsets.copy(copied, input.length - copied);
  if (removed === 0) return { compact: input, offsets: offsets.finish(), removedCount: 0 };
  parts.push(input.slice(copied));
  return { compact: parts.join(''), offsets: offsets.finish(), removedCount: removed };
}
