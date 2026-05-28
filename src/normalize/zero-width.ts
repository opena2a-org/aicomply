/**
 * Strip zero-width and bidi-control characters that are commonly used to
 * defeat naive regex matching (e.g. inserting U+200B between digits of an
 * SSN). These characters carry no semantic content for our detection
 * patterns — stripping them is lossless for our purposes.
 *
 * In-scope:
 *   - U+200B ZERO WIDTH SPACE
 *   - U+200C ZERO WIDTH NON-JOINER
 *   - U+200D ZERO WIDTH JOINER
 *   - U+200E LEFT-TO-RIGHT MARK
 *   - U+200F RIGHT-TO-LEFT MARK
 *   - U+202A–U+202E bidi embedding / override controls
 *   - U+2060 WORD JOINER
 *   - U+2066–U+2069 isolate controls
 *   - U+FEFF BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
 *
 * NOT stripped:
 *   - U+00AD SOFT HYPHEN — visible in some renderers, deferred to v1.1.
 *   - Combining marks (U+0300–U+036F) — would break legitimate accented prose.
 */

const STRIP_CODE_POINTS: ReadonlySet<number> = new Set([
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2060,
  0x2066, 0x2067, 0x2068, 0x2069,
  0xfeff,
]);

export interface ZeroWidthStripResult {
  output: string;
  /** offsetMap[i] = index in input where output[i] originated. */
  offsetMap: number[];
  /** Number of code units removed. */
  removedCount: number;
}

export function stripZeroWidth(input: string): ZeroWidthStripResult {
  const outputParts: string[] = [];
  const offsetMap: number[] = [];
  let removed = 0;

  let cursor = 0;
  for (const codePoint of input) {
    const sourceLen = codePoint.length;
    const cpValue = codePoint.codePointAt(0);
    if (cpValue !== undefined && STRIP_CODE_POINTS.has(cpValue)) {
      removed += sourceLen;
      cursor += sourceLen;
      continue;
    }
    outputParts.push(codePoint);
    for (let i = 0; i < codePoint.length; i += 1) {
      offsetMap.push(cursor + i);
    }
    cursor += sourceLen;
  }

  return {
    output: outputParts.join(''),
    offsetMap,
    removedCount: removed,
  };
}
