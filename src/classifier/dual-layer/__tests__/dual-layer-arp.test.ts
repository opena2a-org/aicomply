/**
 * P1 Step 6: Acceptance tests for dual-layer merge with ARP verification.
 *
 * Tests the end-to-end pipeline:
 * - Regex catches violations independently
 * - Valid signed Guard + clean regex = CLEAN
 * - Valid signed Guard with violation + clean regex = VIOLATION
 * - Invalid signature = DENY (parse-to-deny)
 * - Regex catches even when Guard says clean
 */

import { classifyDualLayer } from '..';
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

  it('returns DENY on invalid signature (parse-to-deny)', async () => {
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
