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

import { nfkcStage } from './nfkc';
import { zeroWidthStage } from './zero-width';
import { compactStage } from './whitespace';
import { extractEncoded } from './encoded';
import { composeOffsetMaps, offsetMapOrIdentity, offsetMapToArray } from './offset-map';
import type {
  NormalizationResult,
  NormalizationStep,
  ScanExtraction,
  ScanNormalization,
} from './types';

export function normalize(content: string): NormalizationResult {
  const scan = normalizeForScan(content);
  return {
    originalContent: scan.originalContent,
    normalizedContent: scan.normalizedContent,
    offsetMap: offsetMapToArray(scan.offsetMap, scan.normalizedContent.length),
    steps: scan.steps,
    decodedExtractions: scan.decodedExtractions.map(({ offsetMap, ...ext }) =>
      offsetMap === undefined ? ext : { ...ext, offsetMap: Array.from(offsetMap) },
    ),
  };
}

/**
 * The views normalize() returns, as the classifier scans them: each offset map
 * is a Uint32Array, and `offsetMap` is undefined when each position of
 * normalizedContent is the same position of the content. A stage allocates its
 * map only once a code unit of its output comes from another index of its
 * input (see ./offset-map).
 */
export function normalizeForScan(content: string): ScanNormalization {
  const steps: NormalizationStep[] = [];

  // Stage 1: NFKC normalization (compatibility decomposition + composition).
  const nfkc = nfkcStage(content);
  if (nfkc.changedCount > 0) {
    steps.push({ transform: 'nfkc', count: nfkc.changedCount });
  }

  // Stage 2: zero-width / bidi-control stripping.
  const zw = zeroWidthStage(nfkc.output);
  if (zw.removedCount > 0) {
    steps.push({ transform: 'strip-zero-width', count: zw.removedCount });
  }

  // Compose: zw maps into nfkc.output positions; nfkc maps into original.
  // When neither stage changed the content, the map is the identity.
  const normalizedToOriginalMap =
    nfkc.changedCount === 0 && zw.removedCount === 0
      ? undefined
      : composeOffsetMaps(zw.offsets, nfkc.offsets, zw.output.length);

  const normalizedContent = zw.output;
  const decodedExtractions: ScanExtraction[] = [];

  // Compact form: whitespace-removed view of the normalized stream.
  // The compact view carries a precise per-character offsetMap back to
  // the original content (composed: compact → normalized → original) so
  // findings inside it project to the exact source range, not the whole
  // extraction. This is necessary for dedup against the normalized scan.
  const compact = compactStage(normalizedContent);
  if (compact.removedCount > 0 && compact.compact.length > 0) {
    steps.push({ transform: 'compact-whitespace', count: compact.removedCount });
    const compactToOriginalMap = offsetMapOrIdentity(
      composeOffsetMaps(compact.offsets, normalizedToOriginalMap, compact.compact.length),
      compact.compact.length,
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
  // blob), so they ship without an offsetMap - findings get anchored
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
