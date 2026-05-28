/**
 * Bounded recursive extraction of Base64- and URL-encoded segments.
 *
 * Threat model (CHIEF-CSR 2026-05-28): attackers Base64-encode credentials or
 * URL-encode them as a trivial evasion ("api_key=YWJjZGVm..." or
 * "%73%73%6e%3d..."). We extract candidates, decode them, and emit a
 * `DecodedExtraction` per successful decode for the dual-layer classifier
 * to scan in addition to the main canonical stream.
 *
 * Bounds (decision D-NORM-1, 2026-05-28):
 *   - Max recursion depth: 2 (a Base64 string containing a Base64 string is
 *     extracted, but a third level is not). Defeats trivial wrapping, refuses
 *     to chase arbitrary deep encodings.
 *   - Min candidate length: 24 chars. Below this the false-positive rate on
 *     prose (which contains short Base64-shaped substrings constantly) is
 *     unacceptable.
 *   - Charset gate: Base64 candidates must match /^[A-Za-z0-9+/=]+$/ with
 *     valid padding. URL candidates must contain at least 2 percent-escapes.
 *   - Output gate: decoded result must be ASCII-printable (>= 90% of bytes
 *     in 0x20-0x7E or whitespace). Binary decodes are rejected.
 */

import type { DecodedExtraction } from './types';

const MIN_CANDIDATE_LENGTH = 24;
const MAX_DEPTH = 2;
const PRINTABLE_MIN_RATIO = 0.9;

// Base64 character set, valid padding, length multiple of 4.
const BASE64_PATTERN = /[A-Za-z0-9+/]{20,}={0,2}/g;

// URL-encoded candidate: a contiguous run of URL-safe chars that includes
// at least one percent-escape. We further gate to ≥ 2 escapes after match.
const URL_PATTERN = /[A-Za-z0-9_\-.~!*'();:@&=+$,/?#\[\]%]+/g;
const PERCENT_ESCAPE_RE = /%[0-9A-Fa-f]{2}/g;

function countPercentEscapes(s: string): number {
  const m = s.match(PERCENT_ESCAPE_RE);
  return m ? m.length : 0;
}

function isAsciiPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) {
      printable += 1;
    }
  }
  return printable / s.length >= PRINTABLE_MIN_RATIO;
}

function tryBase64Decode(candidate: string): string | null {
  if (candidate.length < MIN_CANDIDATE_LENGTH) return null;
  if (candidate.length % 4 !== 0) return null;
  try {
    const decoded = Buffer.from(candidate, 'base64').toString('utf8');
    if (!isAsciiPrintable(decoded)) return null;
    // Re-encoding round-trip protects against decoder leniency (Buffer.from
    // tolerates invalid chars). If the decoded form doesn't round-trip
    // exactly, the candidate wasn't really Base64.
    const roundTrip = Buffer.from(decoded, 'utf8').toString('base64');
    if (roundTrip.replace(/=+$/, '') !== candidate.replace(/=+$/, '')) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryUrlDecode(candidate: string): string | null {
  try {
    const decoded = decodeURIComponent(candidate);
    if (decoded === candidate) return null;
    if (!isAsciiPrintable(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

interface CandidateMatch {
  text: string;
  start: number;
  end: number;
  source: 'base64' | 'url';
}

function findCandidates(input: string): CandidateMatch[] {
  const out: CandidateMatch[] = [];
  let m: RegExpExecArray | null;

  BASE64_PATTERN.lastIndex = 0;
  while ((m = BASE64_PATTERN.exec(input)) !== null) {
    if (m[0].length >= MIN_CANDIDATE_LENGTH) {
      out.push({ text: m[0], start: m.index, end: m.index + m[0].length, source: 'base64' });
    }
  }

  URL_PATTERN.lastIndex = 0;
  while ((m = URL_PATTERN.exec(input)) !== null) {
    if (m[0].length < MIN_CANDIDATE_LENGTH) continue;
    if (countPercentEscapes(m[0]) < 2) continue;
    out.push({ text: m[0], start: m.index, end: m.index + m[0].length, source: 'url' });
  }

  return out;
}

/**
 * Walk the input for encoded candidates up to MAX_DEPTH. Each successful
 * decode produces a DecodedExtraction anchored to the candidate's range
 * in the ORIGINAL input. Depth-2 decodes inherit the depth-1 candidate's
 * original anchor (best-effort: we cannot precisely locate sub-spans
 * inside the decoded text within the original encoded blob).
 */
export function extractEncoded(input: string): DecodedExtraction[] {
  const out: DecodedExtraction[] = [];

  const seed = findCandidates(input);
  for (const c of seed) {
    const decoded = c.source === 'base64' ? tryBase64Decode(c.text) : tryUrlDecode(c.text);
    if (decoded === null) continue;
    out.push({
      decoded,
      originalStart: c.start,
      originalEnd: c.end,
      source: c.source,
      depth: 1,
    });

    if (MAX_DEPTH < 2) continue;
    // Depth-2: re-scan inside the decoded payload.
    const inner = findCandidates(decoded);
    for (const ic of inner) {
      const innerDecoded =
        ic.source === 'base64' ? tryBase64Decode(ic.text) : tryUrlDecode(ic.text);
      if (innerDecoded === null) continue;
      out.push({
        decoded: innerDecoded,
        originalStart: c.start,
        originalEnd: c.end,
        source: ic.source,
        depth: 2,
      });
    }
  }

  return out;
}
