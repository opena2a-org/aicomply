/**
 * Generate a "compact" view of content with whitespace removed from
 * inside what would otherwise be a single token of digits/separators.
 *
 * Whitespace injection ("1 2 3 - 4 5 - 6 7 8 9") is a common evasion.
 * Naively stripping ALL whitespace breaks legitimate prose because
 * patterns like SSN rely on word boundaries ("My SSN" → "MySSN"
 * eliminates `\b` before the digits). Instead we strip whitespace
 * only when BOTH neighbors are in the set {digit, '-', '_', '/', '.',
 * ':'} — characters that appear inside SSNs, PANs, IBANs, MRNs, NPIs,
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

export function buildCompactForm(input: string): CompactFormResult {
  // Pre-decode the input into a positions array so we can look both
  // backwards (at the previous emitted code point) and forwards (at the
  // next non-whitespace code point) when deciding whether to strip a
  // whitespace run.
  const codePoints: { text: string; offset: number; cp: number }[] = [];
  let cursor = 0;
  for (const ch of input) {
    const cp = ch.codePointAt(0) ?? 0;
    codePoints.push({ text: ch, offset: cursor, cp });
    cursor += ch.length;
  }

  const outputParts: string[] = [];
  const offsetMap: number[] = [];
  let removed = 0;
  let lastEmittedCp: number | null = null;

  for (let i = 0; i < codePoints.length; i += 1) {
    const here = codePoints[i]!;
    if (!isWhitespace(here.cp)) {
      outputParts.push(here.text);
      for (let k = 0; k < here.text.length; k += 1) offsetMap.push(here.offset + k);
      lastEmittedCp = here.cp;
      continue;
    }
    // Whitespace run: find the next non-whitespace code point.
    let j = i + 1;
    while (j < codePoints.length && isWhitespace(codePoints[j]!.cp)) j += 1;
    const nextCp = j < codePoints.length ? codePoints[j]!.cp : null;

    const stripRun = lastEmittedCp !== null && nextCp !== null
      && isTokenChar(lastEmittedCp) && isTokenChar(nextCp);

    if (stripRun) {
      // Skip all whitespace in this run.
      for (let k = i; k < j; k += 1) removed += codePoints[k]!.text.length;
      i = j - 1; // for-loop's i += 1 advances to j
    } else {
      // Keep the whitespace run verbatim.
      for (let k = i; k < j; k += 1) {
        const ws = codePoints[k]!;
        outputParts.push(ws.text);
        for (let m = 0; m < ws.text.length; m += 1) offsetMap.push(ws.offset + m);
      }
      lastEmittedCp = codePoints[j - 1]?.cp ?? lastEmittedCp;
      i = j - 1;
    }
  }

  return {
    compact: outputParts.join(''),
    offsetMap,
    removedCount: removed,
  };
}
