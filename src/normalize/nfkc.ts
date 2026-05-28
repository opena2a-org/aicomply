/**
 * Unicode NFKC (Compatibility Composition) normalization with offset
 * tracking back to the original input.
 *
 * NFKC folds compatibility variants to their canonical form:
 *   - Fullwidth digits (U+FF10–FF19) → ASCII 0–9
 *   - Mathematical alphanumerics → ASCII
 *   - Ligatures (ﬃ → ffi)
 *   - Many superscripts and subscripts → base form
 *
 * This defeats the common "use a fullwidth digit to evade an SSN regex"
 * attack while preserving readable prose. NFKC is conservative: it does
 * NOT fold visually-similar-but-semantically-different glyphs (e.g.
 * Cyrillic 'а' U+0430 stays U+0430, since it is a different letter).
 * Those are out of v1.0 scope.
 */

export interface NFKCResult {
  output: string;
  /** offsetMap[i] = index in input where output[i] originated. */
  offsetMap: number[];
  /** Count of input code points whose NFKC form differed from themselves. */
  changedCount: number;
}

/**
 * NFKC-normalize input while tracking offset mapping per output code unit.
 *
 * We walk the input code-point by code-point, normalize each in isolation
 * (NFKC is well-defined on single code points), and emit the result with
 * each output code unit pointing back at the source code point's starting
 * UTF-16 offset. This is a conservative approximation: NFKC can in
 * principle combine across code-point boundaries, but for the
 * compatibility cases we care about (fullwidth, math-alphanumeric,
 * ligatures), per-code-point normalization is sound.
 */
export function normalizeNFKC(input: string): NFKCResult {
  const outputParts: string[] = [];
  const offsetMap: number[] = [];
  let changedCount = 0;

  let cursor = 0;
  for (const codePoint of input) {
    const sourceLen = codePoint.length;
    const normalized = codePoint.normalize('NFKC');

    if (normalized !== codePoint) changedCount += 1;

    outputParts.push(normalized);
    for (let i = 0; i < normalized.length; i += 1) {
      offsetMap.push(cursor);
    }
    cursor += sourceLen;
  }

  return {
    output: outputParts.join(''),
    offsetMap,
    changedCount,
  };
}
