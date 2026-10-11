/**
 * P1 Step 6: Acceptance tests for dual-layer merge with ARP verification.
 *
 * Tests the end-to-end pipeline:
 * - Regex catches violations independently
 * - Valid signed Guard + clean regex = CLEAN
 * - Valid signed Guard with violation + clean regex = VIOLATION
 * - Invalid signature = DENY (parse-to-deny, CR-001)
 * - Regex catches even when Guard says clean
 * - comply() verifies a supplied Guard result on empty content too
 */

import { classifyDualLayer } from '..';
import type { DualLayerOptions } from '..';
import { comply } from '../../..';
import {
  generateTestKeyPair,
  signGuardResult,
  makeManifest,
  makeVerifyOptions,
  TestKeyPair,
} from '../../../arp/__tests__/test-helpers';

let keys: TestKeyPair;

beforeAll(() => {
  keys = generateTestKeyPair();
}, 30000);

describe('dual-layer with ARP verification', () => {
  it('returns CLEAN when valid signature + clean Guard + clean regex', async () => {
    const content = 'This is safe documentation text.';
    const guardResult = signGuardResult(keys, 'documentation', content);
    const options = makeVerifyOptions(keys);

    const result = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: options,
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.signatureValid).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('returns VIOLATION when Guard classifies as non-read operation', async () => {
    const content = 'This is safe documentation text.';
    const guardResult = signGuardResult(keys, 'file-write', content);
    const options = makeVerifyOptions(keys, makeManifest('mutate'));

    const result = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: options,
    });

    expect(result.verdict).toBe('VIOLATION');
    expect(result.signatureValid).toBe(true);
    expect(result.classifierResults.guard?.violations).toHaveLength(1);
    expect(result.classifierResults.guard?.violations[0].type).toBe('file-write');
  });

  it('returns DENY on invalid signature (parse-to-deny, CR-001)', async () => {
    const content = 'This is safe text.';
    const otherKeys = generateTestKeyPair();
    // Sign with one key pair, verify with another
    const guardResult = signGuardResult(otherKeys, 'documentation', content);
    const options = makeVerifyOptions(keys);

    const result = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: options,
    });

    expect(result.verdict).toBe('DENY');
    expect(result.signatureValid).toBe(false);
    expect(result.verifyError?.code).toBe('SIGNATURE_INVALID');
  });

  it('regex catches SSN even when Guard says clean', async () => {
    const content = 'My SSN is 123-45-6789 please store it.';
    const guardResult = signGuardResult(keys, 'documentation', content);
    const options = makeVerifyOptions(keys);

    const result = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: options,
    });

    // Regex should catch the SSN
    expect(result.classifierResults.regex.verdict).toBe('VIOLATION');
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations.some(v => v.type === 'SSN')).toBe(true);
    // Overall verdict is VIOLATION because either flagging = violation
    expect(result.verdict).toBe('VIOLATION');
  });

  it('regex catches Luhn-valid card number independently', async () => {
    const content = 'Card: 4111111111111111';
    const guardResult = signGuardResult(keys, 'documentation', content);
    const options = makeVerifyOptions(keys);

    const result = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: options,
    });

    expect(result.classifierResults.regex.verdict).toBe('VIOLATION');
    expect(result.violations.some(v => v.type === 'PAN')).toBe(true);
  });

  it('returns DENY when tampered Guard result is passed', async () => {
    const content = 'Test content.';
    const guardResult = signGuardResult(keys, 'documentation', content);
    // Tamper: change confidence after signing
    (guardResult as unknown as Record<string, unknown>).confidence = 0.01;

    const result = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: makeVerifyOptions(keys),
    });

    expect(result.verdict).toBe('DENY');
    expect(result.signatureValid).toBe(false);
  });

  it('falls back to regex-only when no Guard options provided (V1)', async () => {
    const content = 'Safe text with no PII.';
    const result = await classifyDualLayer(content);

    expect(result.verdict).toBe('CLEAN');
    expect(result.classifierResults.guard).toBeUndefined();
  });

  it('falls back to regex-only and catches PII', async () => {
    const content = 'My SSN is 078-05-1120.';
    const result = await classifyDualLayer(content);

    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.some(v => v.type === 'SSN')).toBe(true);
  });
});

// comply() does not classify empty content, but the signature check does not
// depend on the content, so a supplied Guard result is verified all the same.
describe('comply() verifies a supplied Guard result on empty content (CR-001)', () => {
  it('returns DENY with the verifyError for a result that fails the schema check, as for other content', async () => {
    const dualLayerOptions = {
      guardResult: { classification: 'documentation', confidence: 0.9 },
      guardVerifyOptions: { manifest: {}, publicKey: {} },
    } as unknown as DualLayerOptions;

    const text = await comply({ content: 'hello world', useGuard: false }, dualLayerOptions);
    for (const empty of [
      await comply({ content: '' }, dualLayerOptions),
      await comply('', dualLayerOptions),
    ]) {
      expect(empty.verdict).toBe('DENY');
      expect(empty.signatureValid).toBe(false);
      expect(empty.verifyError?.code).toBe('SCHEMA_ERROR');
      expect(empty.verifyError).toEqual(text.verifyError);
      // A DENY drops the content echo, and no layer ran on the content.
      expect(empty.originalContent).toBeUndefined();
      expect(empty.layers).toEqual([]);
    }
  });

  it('returns DENY for a result signed with another key', async () => {
    const guardResult = signGuardResult(generateTestKeyPair(), 'documentation', '');

    const result = await comply(
      { content: '' },
      { guardResult, guardVerifyOptions: makeVerifyOptions(keys) },
    );

    expect(result.verdict).toBe('DENY');
    expect(result.signatureValid).toBe(false);
    expect(result.verifyError?.code).toBe('SIGNATURE_INVALID');
  });

  it('accepts a valid result and lists the guard layer', async () => {
    const clean = await comply(
      { content: '' },
      { guardResult: signGuardResult(keys, 'documentation', ''), guardVerifyOptions: makeVerifyOptions(keys) },
    );
    const flagged = await comply(
      { content: '' },
      {
        guardResult: signGuardResult(keys, 'file-write', ''),
        guardVerifyOptions: makeVerifyOptions(keys, makeManifest('mutate')),
      },
    );

    expect(clean.verdict).toBe('CLEAN');
    expect(clean.signatureValid).toBe(true);
    expect(clean.layers).toEqual(['guard']);
    expect(clean.originalContent).toBe('');
    expect(flagged.verdict).toBe('VIOLATION');
    expect(flagged.signatureValid).toBe(true);
    expect(flagged.violations.map(v => [v.type, v.start, v.end])).toEqual([['file-write', 0, 0]]);
  });

  it('leaves empty content CLEAN with no guard layer when no Guard result is supplied', async () => {
    const result = await comply({ content: '' });

    expect(result.verdict).toBe('CLEAN');
    expect(result.signatureValid).toBeUndefined();
    expect(result.layers).toEqual([]);
  });
});
