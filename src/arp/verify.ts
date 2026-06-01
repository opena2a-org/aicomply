/**
 * NanoMind-Guard classification verifier for AIComply.
 *
 * Mirrors HMA's verifyClassification() (hackmyagent/src/arp/intelligence/
 * verify-classification.ts) but lives in AIComply so this package does not
 * depend on the full hackmyagent scanner.
 *
 * Verification order:
 *   1. Schema validation of the result object
 *   2. Algorithm gate: must be Ed25519+ML-DSA-44
 *   3. Key and signature byte-size checks
 *   4. Hybrid signature verification (both halves must pass)
 *   5. Freshness: timestamp within maxAgeMs window
 *   6. Tier rejection matrix
 *
 * Parse-to-deny (CR-001): every failure path returns {valid: false}.
 * Never throws.
 */

import { createPublicKey, verify as cryptoVerify } from 'crypto';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import type {
  CapabilityTier,
  EncodedHybridPublicKey,
  EncodedHybridSignature,
  NanoMindGuardResult,
  NanoMindGuardVerifyErrorCode,
  NanoMindGuardVerifyOptions,
  NanoMindGuardVerifyResult,
} from './types';

const GUARD_SIGNATURE_ALGORITHM = 'Ed25519+ML-DSA-44' as const;
const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000;
const DEFAULT_FUTURE_SKEW_MS = 30 * 1000;

// Expected key/signature sizes per FIPS 204 and RFC 8032
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;
const ML_DSA_44_PUBLIC_KEY_SIZE = 1312;
const ML_DSA_44_SIGNATURE_SIZE = 2420;

const TIER_LEVEL: Record<CapabilityTier, number> = {
  minimal: 0,
  read: 1,
  execute: 2,
  mutate: 3,
  privileged: 4,
};

export const CLASSIFICATION_MIN_TIER: Readonly<Record<string, CapabilityTier>> = {
  'documentation': 'minimal',
  'code-analysis': 'read',
  'data-read': 'read',
  'code-generation': 'execute',
  'network-egress': 'execute',
  'process-spawn': 'execute',
  'data-write': 'mutate',
  'file-write': 'mutate',
  'file-delete': 'privileged',
  'system-mutation': 'privileged',
  'privileged-operation': 'privileged',
};

export const ABSOLUTE_DENY_CLASSES: ReadonlySet<string> = new Set([
  'credential-access',
  'credential-exfiltration',
]);

/**
 * Produce canonical signed-payload bytes for a NanoMind-Guard result.
 * Must be byte-identical to HMA's canonicalizeGuardResultPayload().
 */
function canonicalize(payload: Record<string, unknown>): Uint8Array {
  const stripped: Record<string, unknown> = { ...payload };
  delete stripped.signature;
  return new TextEncoder().encode(stableStringify(stripped));
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`,
  );
  return `{${pairs.join(',')}}`;
}

function invalid(
  code: NanoMindGuardVerifyErrorCode,
  reason: string,
): NanoMindGuardVerifyResult {
  return { valid: false, code, reason };
}

function validateResultSchema(result: NanoMindGuardResult): string | null {
  if (result === null || typeof result !== 'object') {
    return 'result must be an object';
  }
  if (typeof result.classification !== 'string' || result.classification.length === 0) {
    return 'classification must be a non-empty string';
  }
  if (
    typeof result.confidence !== 'number' ||
    !Number.isFinite(result.confidence) ||
    result.confidence < 0 ||
    result.confidence > 1
  ) {
    return 'confidence must be a finite number in [0, 1]';
  }
  if (typeof result.modelVersion !== 'string' || result.modelVersion.length === 0) {
    return 'modelVersion must be a non-empty string';
  }
  if (
    typeof result.contentHash !== 'string' ||
    !/^[0-9a-fA-F]{64}$/.test(result.contentHash)
  ) {
    return 'contentHash must be a 64-character hex string (SHA-256)';
  }
  if (typeof result.timestamp !== 'number' || !Number.isFinite(result.timestamp)) {
    return 'timestamp must be a finite number (Unix ms)';
  }
  const sig = result.signature;
  if (sig === null || typeof sig !== 'object') {
    return 'signature must be a mapping';
  }
  if (typeof sig.alg !== 'string') {
    return 'signature.alg must be a string';
  }
  if (typeof sig.ed25519Sig !== 'string' || sig.ed25519Sig.length === 0) {
    return 'signature.ed25519Sig must be a non-empty base64 string';
  }
  if (typeof sig.mldsaSig !== 'string' || sig.mldsaSig.length === 0) {
    return 'signature.mldsaSig must be a non-empty base64 string';
  }
  if (typeof sig.ts !== 'number' || !Number.isFinite(sig.ts)) {
    return 'signature.ts must be a finite number';
  }
  return null;
}

/**
 * Verify a NanoMind-Guard classification result.
 *
 * Parse-to-deny: never throws. All rejection branches return
 * {valid: false, code, reason}.
 */
export async function verifyClassification(
  result: NanoMindGuardResult,
  options: NanoMindGuardVerifyOptions,
): Promise<NanoMindGuardVerifyResult> {
  // 1. Schema sanity
  const schemaError = validateResultSchema(result);
  if (schemaError !== null) {
    return invalid('SCHEMA_ERROR', schemaError);
  }

  // 2. Algorithm gate
  const sig = result.signature;
  if (sig.alg !== GUARD_SIGNATURE_ALGORITHM) {
    return invalid(
      'ALGORITHM_UNSUPPORTED',
      `signature algorithm must be ${GUARD_SIGNATURE_ALGORITHM}, got ${JSON.stringify(sig.alg)}`,
    );
  }
  if (options.guardPublicKey.algorithm !== GUARD_SIGNATURE_ALGORITHM) {
    return invalid(
      'ALGORITHM_UNSUPPORTED',
      `guard public key algorithm must be ${GUARD_SIGNATURE_ALGORITHM}, got ${JSON.stringify(options.guardPublicKey.algorithm)}`,
    );
  }
  if (options.guardPublicKey.mldsaVariant !== 'ML-DSA-44') {
    return invalid(
      'ALGORITHM_UNSUPPORTED',
      `guard public key mldsaVariant must be ML-DSA-44, got ${JSON.stringify(options.guardPublicKey.mldsaVariant)}`,
    );
  }

  // 3. Decode and validate key/signature sizes
  let ed25519Pk: Uint8Array;
  let mldsaPk: Uint8Array;
  let ed25519Sig: Uint8Array;
  let mldsaSig: Uint8Array;
  try {
    ed25519Pk = Buffer.from(options.guardPublicKey.ed25519PublicKey, 'base64');
    mldsaPk = Buffer.from(options.guardPublicKey.mldsaPublicKey, 'base64');
    ed25519Sig = Buffer.from(sig.ed25519Sig, 'base64');
    mldsaSig = Buffer.from(sig.mldsaSig, 'base64');
  } catch {
    return invalid('KEY_FORMAT_ERROR', 'failed to decode base64 key or signature');
  }

  if (ed25519Pk.length !== ED25519_PUBLIC_KEY_SIZE) {
    return invalid('KEY_FORMAT_ERROR', `ed25519 public key has wrong length: ${ed25519Pk.length}`);
  }
  if (mldsaPk.length !== ML_DSA_44_PUBLIC_KEY_SIZE) {
    return invalid('KEY_FORMAT_ERROR', `ml-dsa-44 public key has wrong length: ${mldsaPk.length}`);
  }
  if (ed25519Sig.length !== ED25519_SIGNATURE_SIZE) {
    return invalid('KEY_FORMAT_ERROR', `ed25519 signature has wrong length: ${ed25519Sig.length}`);
  }
  if (mldsaSig.length !== ML_DSA_44_SIGNATURE_SIZE) {
    return invalid('KEY_FORMAT_ERROR', `ml-dsa-44 signature has wrong length: ${mldsaSig.length}`);
  }

  // 4. Hybrid signature verification - both halves must pass
  const canonical = canonicalize(result as unknown as Record<string, unknown>);

  let ed25519Valid: boolean;
  let mldsaValid: boolean;
  try {
    // Ed25519 via Node.js native crypto (avoids ESM interop issues with @noble/ed25519 v3)
    const ed25519KeyObj = createPublicKey({
      key: Buffer.concat([
        // Ed25519 SPKI DER prefix (RFC 8410)
        Buffer.from('302a300506032b6570032100', 'hex'),
        ed25519Pk,
      ]),
      format: 'der',
      type: 'spki',
    });
    ed25519Valid = cryptoVerify(null, canonical, ed25519KeyObj, ed25519Sig);
    // @noble/post-quantum 0.6.x: verify(sig, msg, publicKey)
    mldsaValid = ml_dsa44.verify(mldsaSig, canonical, mldsaPk);
  } catch {
    return invalid('SIGNATURE_INVALID', 'crypto verification threw an exception');
  }

  if (!ed25519Valid || !mldsaValid) {
    return invalid('SIGNATURE_INVALID', 'hybrid signature rejected by verifier');
  }

  // 5. Freshness
  const now = (options.now ?? Date.now)();
  const maxAgeMs = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
  const futureSkewMs = options.futureSkewMs ?? DEFAULT_FUTURE_SKEW_MS;
  const age = now - result.timestamp;
  if (age > maxAgeMs) {
    return invalid('STALE', `signature timestamp is ${age}ms old, exceeds maxAgeMs=${maxAgeMs}`);
  }
  if (-age > futureSkewMs) {
    return invalid('FUTURE_DATED', `signature timestamp is ${-age}ms in the future, exceeds futureSkewMs=${futureSkewMs}`);
  }

  // 6. Tier rejection matrix
  if (ABSOLUTE_DENY_CLASSES.has(result.classification)) {
    return invalid(
      'ABSOLUTE_DENY',
      `classification ${JSON.stringify(result.classification)} is on the absolute deny list`,
    );
  }
  const requiredTier = CLASSIFICATION_MIN_TIER[result.classification];
  if (requiredTier === undefined) {
    return invalid(
      'UNKNOWN_CLASSIFICATION',
      `classification ${JSON.stringify(result.classification)} is not in the tier registry; parse-to-deny`,
    );
  }
  const manifestLevel = TIER_LEVEL[options.manifest.tier];
  const requiredLevel = TIER_LEVEL[requiredTier];
  if (manifestLevel < requiredLevel) {
    return invalid(
      'TIER_REJECTED',
      `classification ${JSON.stringify(result.classification)} requires tier ${requiredTier}, manifest tier is ${options.manifest.tier}`,
    );
  }

  return {
    valid: true,
    classification: result.classification,
    tier: options.manifest.tier,
    confidence: result.confidence,
  };
}
