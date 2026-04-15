/**
 * Test helpers for generating signed NanoMind-Guard results.
 *
 * Creates real Ed25519+ML-DSA-44 key pairs and signatures so the
 * verification tests exercise the actual crypto path.
 *
 * Ed25519: Node.js native crypto (avoids ESM interop issues)
 * ML-DSA-44: @noble/post-quantum
 */

import { generateKeyPairSync, sign as cryptoSign } from 'crypto';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'crypto';
import type {
  CapabilityManifest,
  EncodedHybridPublicKey,
  NanoMindGuardResult,
  NanoMindGuardVerifyOptions,
} from '../types';

export interface TestKeyPair {
  ed25519PrivateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
  ed25519PublicKeyRaw: Buffer;
  mldsaSecretKey: Uint8Array;
  mldsaPublicKey: Uint8Array;
  encodedPublicKey: EncodedHybridPublicKey;
}

export function generateTestKeyPair(): TestKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  // Extract raw 32-byte public key from SPKI DER (copy to avoid buffer view issues)
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const ed25519PublicKeyRaw = Buffer.from(spki.subarray(spki.length - 32));

  const mldsaKeys = ml_dsa44.keygen();

  return {
    ed25519PrivateKey: privateKey,
    ed25519PublicKeyRaw,
    mldsaSecretKey: mldsaKeys.secretKey,
    mldsaPublicKey: mldsaKeys.publicKey,
    encodedPublicKey: {
      algorithm: 'Ed25519+ML-DSA-44',
      mldsaVariant: 'ML-DSA-44',
      ed25519PublicKey: ed25519PublicKeyRaw.toString('base64'),
      mldsaPublicKey: Buffer.from(mldsaKeys.publicKey).toString('base64'),
    },
  };
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

export function signGuardResult(
  keys: TestKeyPair,
  classification: string,
  content: string,
  overrides?: Partial<{
    confidence: number;
    modelVersion: string;
    timestamp: number;
    algorithm: string;
  }>,
): NanoMindGuardResult {
  const contentHash = createHash('sha256').update(content).digest('hex');
  const timestamp = overrides?.timestamp ?? Date.now();

  const payload: Record<string, unknown> = {
    classification,
    confidence: overrides?.confidence ?? 0.95,
    contentHash,
    modelVersion: overrides?.modelVersion ?? 'sft-v12',
    timestamp,
  };

  const canonical = Buffer.from(stableStringify(payload));

  // Ed25519 sign via Node.js native crypto
  const ed25519Sig = cryptoSign(null, canonical, keys.ed25519PrivateKey);

  // ML-DSA-44 sign via @noble/post-quantum 0.6.x: sign(msg, secretKey)
  const mldsaSig = ml_dsa44.sign(canonical, keys.mldsaSecretKey);

  return {
    classification,
    confidence: overrides?.confidence ?? 0.95,
    modelVersion: overrides?.modelVersion ?? 'sft-v12',
    contentHash,
    timestamp,
    signature: {
      alg: (overrides?.algorithm ?? 'Ed25519+ML-DSA-44') as 'Ed25519+ML-DSA-44',
      ed25519Sig: ed25519Sig.toString('base64'),
      mldsaSig: Buffer.from(mldsaSig).toString('base64'),
      ts: timestamp,
    },
  };
}

export function makeManifest(
  tier: 'minimal' | 'read' | 'execute' | 'mutate' | 'privileged' = 'execute',
): CapabilityManifest {
  return {
    version: '1.0.0',
    agentId: 'test-agent-001',
    tier,
    comply: {
      permitted_classes: ['documentation', 'code-analysis', 'code-generation'],
      prohibited_classes: ['credential-access'],
      on_violation: 'deny',
    },
  };
}

export function makeVerifyOptions(
  keys: TestKeyPair,
  manifest?: CapabilityManifest,
  now?: () => number,
): NanoMindGuardVerifyOptions {
  return {
    guardPublicKey: keys.encodedPublicKey,
    manifest: manifest ?? makeManifest(),
    now,
  };
}
