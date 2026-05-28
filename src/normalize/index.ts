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
  // The compact view carries a precise per-character offsetMap back to
  // the original content (composed: compact → normalized → original) so
  // findings inside it project to the exact source range, not the whole
  // extraction. This is necessary for dedup against the normalized scan.
  const compact = buildCompactForm(normalizedContent);
  if (compact.removedCount > 0 && compact.compact.length > 0) {
    steps.push({ transform: 'compact-whitespace', count: compact.removedCount });
    const compactToOriginalMap = compact.offsetMap.map(
      (normIdx) => normalizedToOriginalMap[normIdx] ?? normIdx,
    );
    const compactOriginalStart = compactToOriginalMap[0] ?? 0;
    const compactOriginalEnd = (compactToOriginalMap[compactToOriginalMap.length - 1] ?? content.length - 1) + 1;
    decodedExtractions.push({
      decoded: compact.compact,
      originalStart: compactOriginalStart,
      originalEnd: Math.min(compactOriginalEnd, content.length),
      source: 'compact',
      depth: 1,
      offsetMap: compactToOriginalMap,
    });
  }

  // Base64 / URL decoded payloads from the original input. These views
  // have no meaningful per-character mapping into the original (the
  // decoded chars don't correspond to sub-positions of the encoded
  // blob), so they ship without an offsetMap — findings get anchored
  // to the whole encoded token via originalStart/End.
  const encoded = extractEncoded(content);
  let base64Count = 0;
  let urlCount = 0;
  for (const ext of encoded) {
    decodedExtractions.push(ext);
    if (ext.source === 'decoded-base64') base64Count += 1;
    else urlCount += 1;
  }
  if (base64Count > 0) steps.push({ transform: 'decode-base64', count: base64Count });
  if (urlCount > 0) steps.push({ transform: 'decode-url', count: urlCount });

  return {
    originalContent: content,
    normalizedContent,
    offsetMap: normalizedToOriginalMap,
    steps,
    decodedExtractions,
  };
}

export type { NormalizationResult, NormalizationStep, DecodedExtraction } from './types';
