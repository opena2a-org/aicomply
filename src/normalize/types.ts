/**
 * Types for the pre-regex normalization layer (v1.0).
 *
 * Normalization is additive and non-destructive: the original content is
 * always preserved on the result alongside the canonical form. Findings
 * carry both their position in the normalized stream and a best-effort
 * slice of the original bytes they map back to.
 *
 * Threat-model scope (CHIEF-CSR 2026-05-28): in-scope mutations are
 * Unicode homoglyphs (NFKC), zero-width / bidi controls, intra-token
 * whitespace injection, and bounded Base64 / URL-encoded forms.
 * Out-of-scope: steganography, language translation, adversarial LLM
 * rephrasing - those require the Guard semantic layer.
 */

export type NormalizationTransform =
  | 'nfkc'
  | 'strip-zero-width'
  | 'compact-whitespace'
  | 'decode-base64'
  | 'decode-url';

export interface NormalizationStep {
  transform: NormalizationTransform;
  /** How many characters were affected (transformed, stripped, or decoded). */
  count: number;
}

/**
 * An additional view of the content scanned alongside the canonical
 * normalized stream. Each view carries its own anchoring back to the
 * original content so findings attribute correctly.
 *
 * The `source` tag matches `ViolationView` 1:1 (minus `'normalized'`),
 * so the dual-layer can use it as the view tag directly without
 * heuristic re-derivation.
 */
export interface DecodedExtraction {
  /** The view's text (ASCII-printable; non-printable decodes are rejected upstream). */
  decoded: string;
  /** Where the view's source range starts in the ORIGINAL content. */
  originalStart: number;
  /** Where the view's source range ends in the ORIGINAL content (exclusive). */
  originalEnd: number;
  /**
   * Which view this is. `'compact'` = whitespace-stripped form of the
   * normalized stream. `'decoded-base64'` / `'decoded-url'` = decoded
   * payload from an encoded blob in the original.
   */
  source: 'compact' | 'decoded-base64' | 'decoded-url';
  /**
   * Recursion depth for decoded views (1 = decoded directly from
   * original; 2 = decoded from a depth-1 result). Always 1 for
   * `'compact'`.
   */
  depth: number;
  /**
   * Per-character map from `decoded[i]` back to the corresponding
   * position in the ORIGINAL content. Present for `'compact'` (where
   * we know the projection precisely); absent for `'decoded-base64'`
   * / `'decoded-url'` (where the decoded payload's chars don't have
   * a meaningful sub-position inside the encoded blob - findings are
   * anchored to the whole encoded token via originalStart/End).
   */
  offsetMap?: number[];
}

export interface NormalizationResult {
  /** The original input, byte-identical to what the caller passed. */
  originalContent: string;
  /**
   * Canonicalized form of the original content after NFKC, zero-width
   * stripping, and intra-token whitespace compaction.
   * If no transforms apply, this equals originalContent.
   */
  normalizedContent: string;
  /**
   * Position map: `offsetMap[i]` is the index in originalContent that
   * normalizedContent[i] derived from. Length equals normalizedContent.length.
   * If a normalized character was synthesized from multiple original
   * characters (NFKC compatibility decomposition), the map points at the
   * first source position.
   */
  offsetMap: number[];
  /** Ordered list of transforms applied with their hit counts. */
  steps: NormalizationStep[];
  /**
   * Additional decoded segments to scan. Each carries its own
   * originalStart/originalEnd anchoring back to the original content.
   */
  decodedExtractions: DecodedExtraction[];
}
