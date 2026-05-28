/**
 * Spec-driven tests for the adversarial-mutation normalization layer
 * (v1.0, CHIEF-CSR decision 2026-05-28).
 *
 * Each assertion maps to one of:
 *   - NFKC compatibility folding for homoglyph defenses
 *   - Zero-width / bidi-control stripping
 *   - Compact-form (whitespace-removed) view for whitespace-injection defense
 *   - Bounded Base64 / URL-decoded extractions (depth ≤ 2, length ≥ 24 chars,
 *     ASCII-printable round-trip gate)
 *   - Offset-map preservation back to the original content
 *   - No-op behavior on clean ASCII input
 */

import { normalize } from '../index';
import { normalizeNFKC } from '../nfkc';
import { stripZeroWidth } from '../zero-width';
import { buildCompactForm } from '../whitespace';
import { extractEncoded } from '../encoded';

describe('NFKC normalization (homoglyph defense)', () => {
  it('folds fullwidth digits to ASCII digits', () => {
    // U+FF11 FULLWIDTH DIGIT ONE → "1"
    const r = normalizeNFKC('１２３-４５-６７８９');
    expect(r.output).toBe('123-45-6789');
    expect(r.changedCount).toBe(9);
  });

  it('folds fullwidth ASCII letters to ASCII', () => {
    const r = normalizeNFKC('ＡＢＣ'); // ABC fullwidth
    expect(r.output).toBe('ABC');
  });

  it('preserves regular ASCII unchanged (no NFKC step recorded)', () => {
    const r = normalizeNFKC('My SSN is 123-45-6789.');
    expect(r.output).toBe('My SSN is 123-45-6789.');
    expect(r.changedCount).toBe(0);
  });

  it('offset map for fullwidth output points at the (single) source codepoint per ASCII char', () => {
    // Each fullwidth digit is one UTF-16 code unit at index 0,1,2...
    const r = normalizeNFKC('１２３');
    expect(r.output).toBe('123');
    expect(r.offsetMap).toEqual([0, 1, 2]);
  });
});

describe('Zero-width / bidi-control stripping', () => {
  it('strips U+200B ZERO WIDTH SPACE injected between digits of an SSN', () => {
    const injected = '1​2​3​-​4​5​-​6​7​8​9';
    const r = stripZeroWidth(injected);
    expect(r.output).toBe('123-45-6789');
    expect(r.removedCount).toBe(10);
  });

  it('strips U+202E RIGHT-TO-LEFT OVERRIDE without breaking the rest of the input', () => {
    const r = stripZeroWidth('aws_key=‮ABC');
    expect(r.output).toBe('aws_key=ABC');
    expect(r.removedCount).toBe(1);
  });

  it('strips U+FEFF BOM', () => {
    const r = stripZeroWidth('﻿123-45-6789');
    expect(r.output).toBe('123-45-6789');
    expect(r.removedCount).toBe(1);
  });

  it('preserves combining marks (out-of-scope for v1.0)', () => {
    const r = stripZeroWidth('café');
    expect(r.output).toBe('café');
    expect(r.removedCount).toBe(0);
  });

  it('offset map maps stripped output back to original positions', () => {
    const r = stripZeroWidth('a​b');
    expect(r.output).toBe('ab');
    // 'a' came from position 0, 'b' came from position 2 (U+200B was at 1).
    expect(r.offsetMap).toEqual([0, 2]);
  });
});

describe('Compact-form view (whitespace-injection defense)', () => {
  it('removes ASCII whitespace from a spaced-out SSN', () => {
    const r = buildCompactForm('1 2 3 - 4 5 - 6 7 8 9');
    expect(r.compact).toBe('123-45-6789');
    expect(r.removedCount).toBe(10);
  });

  it('removes tabs and newlines', () => {
    const r = buildCompactForm('1\t2\t3-\n4 5-6789');
    expect(r.compact).toBe('123-45-6789');
  });

  it('removes non-zero-width Unicode whitespace (U+00A0 NBSP)', () => {
    const r = buildCompactForm('1 2 3-45-6789');
    expect(r.compact).toBe('123-45-6789');
  });

  it('offset map for compact form points at source positions in input (digit run)', () => {
    const r = buildCompactForm('1 2 3');
    expect(r.compact).toBe('123');
    expect(r.offsetMap).toEqual([0, 2, 4]);
  });

  it('preserves whitespace between letters — does NOT collapse prose word boundaries', () => {
    const r = buildCompactForm('My SSN is 1 2 3');
    // "My SSN is" prose stays whitespaced; "1 2 3" digit run collapses
    // because both neighbors of each space are token chars.
    expect(r.compact).toBe('My SSN is 123');
  });
});

describe('Base64 / URL decode extraction', () => {
  it('decodes a length-gated Base64-wrapped credential pattern', () => {
    // "api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" base64-encoded
    const payload = 'api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const b64 = Buffer.from(payload).toString('base64');
    const exts = extractEncoded(`look: ${b64} end`);
    expect(exts).toHaveLength(1);
    expect(exts[0]?.decoded).toBe(payload);
    expect(exts[0]?.source).toBe('decoded-base64');
    expect(exts[0]?.depth).toBe(1);
  });

  it('rejects short Base64-shaped substrings below MIN_CANDIDATE_LENGTH', () => {
    const exts = extractEncoded('short token: dGVzdA==');
    expect(exts).toHaveLength(0);
  });

  it('rejects Base64 candidates that decode to non-printable bytes', () => {
    // 32 random bytes as Base64 → binary decode, should be rejected.
    const binary = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
    const b64 = binary.toString('base64');
    const exts = extractEncoded(`x: ${b64}`);
    expect(exts).toHaveLength(0);
  });

  it('recurses to depth 2: Base64 of a Base64-wrapped credential', () => {
    const inner = 'api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const layer1 = Buffer.from(inner).toString('base64');
    const layer2 = Buffer.from(layer1).toString('base64');
    const exts = extractEncoded(`wrapped: ${layer2}`);
    expect(exts.length).toBeGreaterThanOrEqual(2);
    const d1 = exts.find((e) => e.depth === 1);
    const d2 = exts.find((e) => e.depth === 2);
    expect(d1?.decoded).toBe(layer1);
    expect(d2?.decoded).toBe(inner);
  });

  it('decodes URL-encoded content with at least two percent-escapes', () => {
    // Payload chosen so encodeURIComponent produces ≥ 2 escapes
    // ('=' and ' ' both encode, giving %3D and %20).
    const inner = 'secret = ghp_THISisaGHPATtokenABCDEFGHIJKLMNOPQRSTU';
    const enc = encodeURIComponent(inner);
    const exts = extractEncoded(`q: ${enc}`);
    const urlExt = exts.find((e) => e.source === 'decoded-url');
    expect(urlExt?.decoded).toBe(inner);
  });

  it('rejects URL candidates with fewer than 2 percent-escapes', () => {
    // "a%20bcdefghijklmnopqrstuvwxyz" has only 1 escape.
    const exts = extractEncoded('a%20bcdefghijklmnopqrstuvwxyz');
    const urlExt = exts.find((e) => e.source === 'decoded-url');
    expect(urlExt).toBeUndefined();
  });

  it('anchors decoded extraction range to the encoded token in the original', () => {
    const inner = 'api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const b64 = Buffer.from(inner).toString('base64');
    const prefix = 'here is data: ';
    const input = prefix + b64 + ' end';
    const exts = extractEncoded(input);
    expect(exts[0]?.originalStart).toBe(prefix.length);
    expect(exts[0]?.originalEnd).toBe(prefix.length + b64.length);
  });
});

describe('normalize() pipeline end-to-end', () => {
  it('no-op on whitespace-free ASCII: normalizedContent === input, no steps recorded', () => {
    // No whitespace, no Unicode → no normalization steps at all.
    const r = normalize('SSN:123-45-6789');
    expect(r.originalContent).toBe('SSN:123-45-6789');
    expect(r.normalizedContent).toBe('SSN:123-45-6789');
    expect(r.steps).toEqual([]);
    expect(r.decodedExtractions).toEqual([]);
  });

  it('compact-whitespace step is recorded only when intra-token whitespace was actually stripped', () => {
    // No intra-digit-run whitespace → no step.
    const clean = normalize('My SSN is 123-45-6789.');
    expect(clean.steps.find((s) => s.transform === 'compact-whitespace')).toBeUndefined();

    // Intra-digit-run whitespace → step recorded, compact extraction
    // available for the dual-layer to scan.
    const spaced = normalize('My SSN is 1 2 3 - 4 5 - 6 7 8 9.');
    expect(spaced.steps.find((s) => s.transform === 'compact-whitespace')).toBeDefined();
    expect(spaced.steps.find((s) => s.transform === 'nfkc')).toBeUndefined();
  });

  it('NFKC + zero-width strip compose: fullwidth digits with U+200B between them', () => {
    const r = normalize('１​２​３');
    expect(r.normalizedContent).toBe('123');
    expect(r.steps.map((s) => s.transform)).toContain('nfkc');
    expect(r.steps.map((s) => s.transform)).toContain('strip-zero-width');
  });

  it('records a compact-whitespace step when input contains whitespace', () => {
    const r = normalize('1 2 3 - 4 5 - 6 7 8 9');
    expect(r.steps.find((s) => s.transform === 'compact-whitespace')).toBeDefined();
    expect(r.decodedExtractions.some((e) => e.decoded === '123-45-6789')).toBe(true);
  });

  it('originalContent is byte-identical to the input', () => {
    const tricky = '​１２３ \t mixed';
    const r = normalize(tricky);
    expect(r.originalContent).toBe(tricky);
  });

  it('exposes decoded extractions for Base64-wrapped credentials', () => {
    const inner = 'api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const b64 = Buffer.from(inner).toString('base64');
    const r = normalize(`payload: ${b64}`);
    expect(r.decodedExtractions.some((e) => e.decoded === inner && e.source === 'decoded-base64')).toBe(true);
    expect(r.steps.find((s) => s.transform === 'decode-base64')).toBeDefined();
  });

  it('offsetMap length equals normalizedContent length', () => {
    const r = normalize('１​２​３');
    expect(r.offsetMap.length).toBe(r.normalizedContent.length);
  });
});

describe('Threat-model bounds (CHIEF-CSR scope decisions)', () => {
  it('does NOT fold Cyrillic look-alikes (different letter, out of scope)', () => {
    // U+0430 Cyrillic 'а' is NOT NFKC-equivalent to U+0061 ASCII 'a'.
    const r = normalize('pаssword=hunter2');
    expect(r.normalizedContent).toBe('pаssword=hunter2');
    const nfkcStep = r.steps.find((s) => s.transform === 'nfkc');
    expect(nfkcStep).toBeUndefined();
  });

  it('does NOT strip soft hyphen (U+00AD, out of scope for v1.0)', () => {
    const r = normalize('s­sn­:­ 123-45-6789');
    expect(r.normalizedContent.includes('­')).toBe(true);
  });

  it('caps Base64 recursion at depth 2 (depth-3 wrapping not extracted)', () => {
    const inner = 'api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const l1 = Buffer.from(inner).toString('base64');
    const l2 = Buffer.from(l1).toString('base64');
    const l3 = Buffer.from(l2).toString('base64');
    const exts = extractEncoded(`x: ${l3}`);
    // l3 -> l2 (depth 1), l2 -> l1 (depth 2). l1 -> inner would be depth 3, skipped.
    expect(exts.some((e) => e.decoded === inner)).toBe(false);
  });
});
