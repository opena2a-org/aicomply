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

import { OffsetMapBuilder, offsetMapToArray, type OffsetMap } from './offset-map';
import { TextBuilder } from './text-builder';

export interface NFKCResult {
  output: string;
  /** offsetMap[i] = index in input where output[i] originated. */
  offsetMap: number[];
  /** Count of input code points whose NFKC form differed from themselves. */
  changedCount: number;
}

/** An NFKCResult with the offset map as an OffsetMap. */
export interface NFKCStage {
  output: string;
  offsets: OffsetMap;
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
  const { output, offsets, changedCount } = nfkcStage(input);
  return { output, offsetMap: offsetMapToArray(offsets, output.length), changedCount };
}

/**
 * normalizeNFKC() with the map as an OffsetMap. An ASCII character is its own
 * NFKC form, so only code points at or above U+0080 are normalized, and a run
 * of code points that are their own NFKC form goes to the output as one slice
 * of the input.
 */
export function nfkcStage(input: string): NFKCStage {
  const output = new TextBuilder();
  const offsets = new OffsetMapBuilder(input.length);
  let changedCount = 0;
  // input[copied, i) is a run that goes to the output as it is, and
  // input[mapped, i) the end of that run whose code units each point at their
  // own index.
  let copied = 0;
  let mapped = 0;
  let i = 0;
  while (i < input.length) {
    if (input.charCodeAt(i) < 0x80) {
      i += 1;
      continue;
    }
    const length = (input.codePointAt(i) as number) > 0xffff ? 2 : 1;
    const codePoint = input.slice(i, i + length);
    const normalized = codePoint.normalize('NFKC');
    // Each output code unit of a code point that NFKC changes, or that is
    // held in two code units, points at its first code unit.
    if (normalized === codePoint) {
      if (length === 2) {
        offsets.copy(mapped, i - mapped);
        offsets.repeat(i, 2);
        mapped = i + 2;
      }
      i += length;
      continue;
    }
    output.append(input.slice(copied, i));
    offsets.copy(mapped, i - mapped);
    changedCount += 1;
    output.append(normalized);
    offsets.repeat(i, normalized.length);
    i += length;
    copied = i;
    mapped = i;
  }
  offsets.copy(mapped, input.length - mapped);
  if (copied === 0) return { output: input, offsets: offsets.finish(), changedCount };
  output.append(input.slice(copied));
  return { output: output.finish(), offsets: offsets.finish(), changedCount };
}
