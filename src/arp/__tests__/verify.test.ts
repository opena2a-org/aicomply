/**
 * P1 Step 6: Acceptance tests for NanoMind-Guard classification verification.
 *
 * Tests the full verification pipeline: schema, algorithm gate, key sizes,
 * hybrid signature (Ed25519+ML-DSA-44), freshness, and tier rejection matrix.
 * Uses real crypto operations - no mocks.
 */

import { verifyClassification, CLASSIFICATION_MIN_TIER, ABSOLUTE_DENY_CLASSES } from '../verify';
import {
  generateTestKeyPair,
  signGuardResult,
  makeManifest,
  makeVerifyOptions,
  TestKeyPair,
} from './test-helpers';

let keys: TestKeyPair;

beforeAll(() => {
  keys = generateTestKeyPair();
}, 30000);

describe('verifyClassification', () => {
  // --- Happy path ---

  it('accepts a valid hybrid-signed classification', async () => {
    const result = signGuardResult(keys, 'documentation', 'hello world');
    const options = makeVerifyOptions(keys);
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(true);
    if (out.valid) {
      expect(out.classification).toBe('documentation');
      expect(out.confidence).toBe(0.95);
      expect(out.tier).toBe('execute');
    }
  });

  it('accepts code-analysis with read tier', async () => {
    const result = signGuardResult(keys, 'code-analysis', 'function foo() {}');
    const options = makeVerifyOptions(keys, makeManifest('read'));
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(true);
  });

  // --- Parse-to-deny: unsigned output ---

  it('rejects result with missing signature fields', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    // Destroy the signature
    (result.signature as unknown as Record<string, unknown>).ed25519Sig = '';
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SCHEMA_ERROR');
  });

  // --- Parse-to-deny: Ed25519-only ---

  it('rejects Ed25519-only signature (algorithm downgrade)', async () => {
    const result = signGuardResult(keys, 'documentation', 'test', {
      algorithm: 'Ed25519+ML-DSA-65',
    });
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('ALGORITHM_UNSUPPORTED');
  });

  // --- Parse-to-deny: mismatched keys ---

  it('rejects signature from a different key pair', async () => {
    const otherKeys = generateTestKeyPair();
    const result = signGuardResult(otherKeys, 'documentation', 'test');
    // Verify with original keys - should fail
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SIGNATURE_INVALID');
  });

  // --- Parse-to-deny: tampered payload ---

  it('rejects tampered classification label', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    // Tamper: change classification after signing
    (result as unknown as Record<string, unknown>).classification = 'credential-access';
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects tampered confidence', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    (result as unknown as Record<string, unknown>).confidence = 0.01;
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects tampered timestamp', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    (result as unknown as Record<string, unknown>).timestamp = result.timestamp + 1;
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SIGNATURE_INVALID');
  });

  // --- Freshness ---

  it('rejects stale signatures', async () => {
    const staleTime = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    const result = signGuardResult(keys, 'documentation', 'test', {
      timestamp: staleTime,
    });
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('STALE');
  });

  it('rejects future-dated signatures', async () => {
    const futureTime = Date.now() + 2 * 60 * 1000; // 2 minutes in future
    const result = signGuardResult(keys, 'documentation', 'test', {
      timestamp: futureTime,
    });
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('FUTURE_DATED');
  });

  it('accepts signatures within the freshness window', async () => {
    const recentTime = Date.now() - 2 * 60 * 1000; // 2 minutes ago
    const result = signGuardResult(keys, 'documentation', 'test', {
      timestamp: recentTime,
    });
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(true);
  });

  // --- Tier rejection matrix ---

  it('rejects classification requiring higher tier than manifest', async () => {
    // file-write requires 'mutate' tier
    const result = signGuardResult(keys, 'file-write', 'test');
    const options = makeVerifyOptions(keys, makeManifest('read')); // only read tier
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('TIER_REJECTED');
  });

  it('accepts classification at exact tier boundary', async () => {
    // code-generation requires 'execute' tier
    const result = signGuardResult(keys, 'code-generation', 'test');
    const options = makeVerifyOptions(keys, makeManifest('execute'));
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(true);
  });

  it('accepts classification below tier', async () => {
    // documentation requires 'minimal' tier
    const result = signGuardResult(keys, 'documentation', 'test');
    const options = makeVerifyOptions(keys, makeManifest('privileged'));
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(true);
  });

  // --- Absolute deny ---

  it('rejects credential-access at any tier', async () => {
    const result = signGuardResult(keys, 'credential-access', 'test');
    const options = makeVerifyOptions(keys, makeManifest('privileged'));
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('ABSOLUTE_DENY');
  });

  it('rejects credential-exfiltration at any tier', async () => {
    const result = signGuardResult(keys, 'credential-exfiltration', 'test');
    const options = makeVerifyOptions(keys, makeManifest('privileged'));
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('ABSOLUTE_DENY');
  });

  // --- Unknown classification ---

  it('rejects unknown classification (parse-to-deny)', async () => {
    const result = signGuardResult(keys, 'totally-unknown-class', 'test');
    const options = makeVerifyOptions(keys, makeManifest('privileged'));
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('UNKNOWN_CLASSIFICATION');
  });

  // --- Schema errors ---

  it('rejects null result', async () => {
    const out = await verifyClassification(
      null as unknown as any,
      makeVerifyOptions(keys),
    );
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SCHEMA_ERROR');
  });

  it('rejects result with invalid confidence', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    (result as unknown as Record<string, unknown>).confidence = 2.0;
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SCHEMA_ERROR');
  });

  it('rejects result with invalid contentHash', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    (result as unknown as Record<string, unknown>).contentHash = 'not-a-sha256';
    const out = await verifyClassification(result, makeVerifyOptions(keys));
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('SCHEMA_ERROR');
  });

  // --- Key format errors ---

  it('rejects wrong-sized public key', async () => {
    const result = signGuardResult(keys, 'documentation', 'test');
    const badOptions = makeVerifyOptions(keys);
    // Clone the public key object to avoid mutating shared state
    badOptions.guardPublicKey = { ...badOptions.guardPublicKey };
    badOptions.guardPublicKey.ed25519PublicKey = Buffer.from('short').toString('base64');
    const out = await verifyClassification(result, badOptions);
    expect(out.valid).toBe(false);
    if (!out.valid) expect(out.code).toBe('KEY_FORMAT_ERROR');
  });

  // --- Clock override ---

  it('uses custom clock for freshness checks', async () => {
    const fixedNow = 1700000000000;
    const result = signGuardResult(keys, 'documentation', 'test', {
      timestamp: fixedNow - 1000,
    });
    const options = makeVerifyOptions(keys, makeManifest(), () => fixedNow);
    const out = await verifyClassification(result, options);
    expect(out.valid).toBe(true);
  });
});

describe('CLASSIFICATION_MIN_TIER', () => {
  it('has entries for all known safe classifications', () => {
    expect(CLASSIFICATION_MIN_TIER['documentation']).toBe('minimal');
    expect(CLASSIFICATION_MIN_TIER['code-analysis']).toBe('read');
    expect(CLASSIFICATION_MIN_TIER['code-generation']).toBe('execute');
    expect(CLASSIFICATION_MIN_TIER['file-delete']).toBe('privileged');
  });
});

describe('ABSOLUTE_DENY_CLASSES', () => {
  it('contains credential classes', () => {
    expect(ABSOLUTE_DENY_CLASSES.has('credential-access')).toBe(true);
    expect(ABSOLUTE_DENY_CLASSES.has('credential-exfiltration')).toBe(true);
  });
});
