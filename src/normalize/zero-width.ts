/**
 * Strip zero-width and bidi-control characters that are commonly used to
 * defeat naive regex matching (e.g. inserting U+200B between digits of an
 * SSN). These characters carry no semantic content for our detection
 * patterns - stripping them is lossless for our purposes.
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
 *   - U+00AD SOFT HYPHEN - visible in some renderers.
 *   - Combining marks (U+0300–U+036F) - would break legitimate accented prose.
 */

import { OffsetMapBuilder, offsetMapToArray, type OffsetMap } from './offset-map';

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

/** A ZeroWidthStripResult with the offset map as an OffsetMap. */
export interface ZeroWidthStage {
  output: string;
  offsets: OffsetMap;
  removedCount: number;
}

export function stripZeroWidth(input: string): ZeroWidthStripResult {
  const { output, offsets, removedCount } = zeroWidthStage(input);
  return { output, offsetMap: offsetMapToArray(offsets, output.length), removedCount };
}

/**
 * stripZeroWidth() with the map as an OffsetMap. Each stripped character is
 * one code unit at or above U+200B and outside the surrogate range, so the
 * input is read a code unit at a time, and each run between two stripped
 * characters goes to the output as one slice of the input.
 */
export function zeroWidthStage(input: string): ZeroWidthStage {
  const parts: string[] = [];
  const offsets = new OffsetMapBuilder(input.length);
  let removed = 0;
  // input[copied, i) is a run that goes to the output as it is.
  let copied = 0;
  for (let i = 0; i < input.length; i += 1) {
    const unit = input.charCodeAt(i);
    if (unit < 0x200b || !STRIP_CODE_POINTS.has(unit)) continue;
    parts.push(input.slice(copied, i));
    offsets.copy(copied, i - copied);
    removed += 1;
    copied = i + 1;
  }
  offsets.copy(copied, input.length - copied);
  if (removed === 0) return { output: input, offsets: offsets.finish(), removedCount: 0 };
  parts.push(input.slice(copied));
  return { output: parts.join(''), offsets: offsets.finish(), removedCount: removed };
}
