/**
 * Pre-regex normalization pipeline.
 *
 * Runs NFKC + zero-width stripping on the input to produce a canonical
 * `normalizedContent`, generates a compact (whitespace-removed) view as
 * an additional `DecodedExtraction`, and extracts any bounded
 * Base64/URL-encoded payloads as further extractions. The dual-layer
 * classifier scans all of these views.
 *
 * Threat-model scope and bounds: see `types.ts` and `encoded.ts` headers.
 */

import { normalizeNFKC } from './nfkc';
import { stripZeroWidth } from './zero-width';
import { buildCompactForm } from './whitespace';
import { extractEncoded } from './encoded';
import type {
  NormalizationResult,
  NormalizationStep,
  DecodedExtraction,
} from './types';

/**
 * Compose two offset maps: `outer` maps stage-N output positions to
 * stage-N-1 output positions; `inner` maps stage-N-1 output positions
 * to original input positions. Result maps stage-N output positions
 * directly back to the original input.
 */
function composeOffsetMaps(outer: number[], inner: number[]): number[] {
  return outer.map((mid) => (mid < inner.length ? inner[mid] : (inner[inner.length - 1] ?? 0)));
}

function buildIdentityMap(length: number): number[] {
  const m = new Array<number>(length);
  for (let i = 0; i < length; i += 1) m[i] = i;
  return m;
}

export function normalize(content: string): NormalizationResult {
  const steps: NormalizationStep[] = [];

  // Stage 1: NFKC normalization (compatibility decomposition + composition).
  const nfkc = normalizeNFKC(content);
  if (nfkc.changedCount > 0) {
    steps.push({ transform: 'nfkc', count: nfkc.changedCount });
  }

  // Stage 2: zero-width / bidi-control stripping.
  const zw = stripZeroWidth(nfkc.output);
  if (zw.removedCount > 0) {
    steps.push({ transform: 'strip-zero-width', count: zw.removedCount });
  }

  // Compose: zw maps into nfkc.output positions; nfkc maps into original.
  const normalizedToOriginalMap =
    nfkc.changedCount === 0 && zw.removedCount === 0
      ? buildIdentityMap(content.length)
      : composeOffsetMaps(zw.offsetMap, nfkc.offsetMap);

  const normalizedContent = zw.output;
  const decodedExtractions: DecodedExtraction[] = [];

  // Compact form: whitespace-removed view of the normalized stream.
  // Carried as a DecodedExtraction so the dual-layer treats it uniformly
  // alongside Base64/URL decodings.
  const compact = buildCompactForm(normalizedContent);
  if (compact.removedCount > 0 && compact.compact.length > 0) {
    steps.push({ transform: 'compact-whitespace', count: compact.removedCount });
    // Map compact positions back to original via the normalized offset map.
    const compactOriginalStart = normalizedToOriginalMap[compact.offsetMap[0] ?? 0] ?? 0;
    const lastCompactIdx = compact.offsetMap[compact.offsetMap.length - 1] ?? 0;
    const compactOriginalEnd = (normalizedToOriginalMap[lastCompactIdx] ?? content.length - 1) + 1;
    decodedExtractions.push({
      decoded: compact.compact,
      originalStart: compactOriginalStart,
      originalEnd: Math.min(compactOriginalEnd, content.length),
      // Compact-form is not technically an encoded form, but reusing the
      // DecodedExtraction shape keeps the dual-layer's scan loop uniform.
      // We mark it as 'url' for the source tag since it's not Base64;
      // callers distinguish via NormalizationStep entries on the result.
      source: 'url',
      depth: 1,
    });
  }

  // Base64 / URL decoded payloads from the original input.
  const encoded = extractEncoded(content);
  for (const ext of encoded) {
    decodedExtractions.push(ext);
    if (ext.source === 'base64') {
      const existing = steps.find((s) => s.transform === 'decode-base64');
      if (existing) existing.count += 1;
      else steps.push({ transform: 'decode-base64', count: 1 });
    } else {
      const existing = steps.find((s) => s.transform === 'decode-url');
      if (existing) existing.count += 1;
      else steps.push({ transform: 'decode-url', count: 1 });
    }
  }

  return {
    originalContent: content,
    normalizedContent,
    offsetMap: normalizedToOriginalMap,
    steps,
    decodedExtractions,
  };
}

export type { NormalizationResult, NormalizationStep, DecodedExtraction } from './types';
