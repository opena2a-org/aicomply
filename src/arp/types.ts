/**
 * Types for the Agent Runtime Protection (ARP) client.
 *
 * These types mirror the wire format used by HMA's ARP crypto module
 * (hackmyagent/src/arp/) so AIComply can verify NanoMind-Guard
 * classification signatures independently.
 */

// --- Hybrid Crypto Types ---

export type MLDsaVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export type HybridAlgorithm =
  | 'Ed25519+ML-DSA-44'
  | 'Ed25519+ML-DSA-65'
  | 'Ed25519+ML-DSA-87';

export interface EncodedHybridSignature {
  alg: HybridAlgorithm;
  ed25519Sig: string;  // base64
  mldsaSig: string;    // base64
  ts: number;          // Unix ms
}

export interface EncodedHybridPublicKey {
  algorithm: HybridAlgorithm;
  mldsaVariant: MLDsaVariant;
  ed25519PublicKey: string;  // base64
  mldsaPublicKey: string;    // base64
}

// --- NanoMind-Guard Classification ---

export interface NanoMindGuardResult {
  classification: string;
  confidence: number;
  modelVersion: string;
  contentHash: string;
  timestamp: number;
  signature: EncodedHybridSignature;
}

// --- Capability Tiers ---

export type CapabilityTier = 'minimal' | 'read' | 'execute' | 'mutate' | 'privileged';

export type ComplyOnViolation = 'log' | 'alert' | 'pause' | 'kill' | 'deny';

export interface CapabilityManifest {
  version: string;
  agentId: string;
  tier: CapabilityTier;
  comply: {
    permitted_classes: string[];
    prohibited_classes: string[];
    on_violation: ComplyOnViolation;
  };
}

// --- Verification ---

export type NanoMindGuardVerifyErrorCode =
  | 'SCHEMA_ERROR'
  | 'ALGORITHM_UNSUPPORTED'
  | 'KEY_FORMAT_ERROR'
  | 'SIGNATURE_INVALID'
  | 'STALE'
  | 'FUTURE_DATED'
  | 'TIER_REJECTED'
  | 'UNKNOWN_CLASSIFICATION'
  | 'ABSOLUTE_DENY';

export type NanoMindGuardVerifyResult =
  | {
      valid: true;
      classification: string;
      tier: CapabilityTier;
      confidence: number;
    }
  | {
      valid: false;
      code: NanoMindGuardVerifyErrorCode;
      reason: string;
    };

export interface NanoMindGuardVerifyOptions {
  guardPublicKey: EncodedHybridPublicKey;
  manifest: CapabilityManifest;
  maxAgeMs?: number;
  futureSkewMs?: number;
  now?: () => number;
}

// --- ARP Client ---

export interface ArpVerifyResult {
  valid: boolean;
  agentId: string;
  trustLevel: number;
  expiresAt: number;
}

export interface BehavioralRiskSignal {
  agentId: string;
  riskScore: number;
  signals: string[];
  assessedAt: number;
}

export interface ArpClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
}
