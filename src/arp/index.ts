/**
 * ARP (Agent Reputation Protocol) module.
 *
 * Provides classification signature verification and behavioral risk signals.
 */

export { verifyClassification, CLASSIFICATION_MIN_TIER, ABSOLUTE_DENY_CLASSES } from './verify';

export type {
  ArpClientOptions,
  ArpVerifyResult,
  BehavioralRiskSignal,
  CapabilityManifest,
  CapabilityTier,
  ComplyOnViolation,
  EncodedHybridPublicKey,
  EncodedHybridSignature,
  HybridAlgorithm,
  MLDsaVariant,
  NanoMindGuardResult,
  NanoMindGuardVerifyErrorCode,
  NanoMindGuardVerifyOptions,
  NanoMindGuardVerifyResult,
} from './types';

import type { BehavioralRiskSignal, ArpClientOptions } from './types';

/**
 * ARP client for behavioral risk signals.
 * V1: returns neutral defaults. V2: queries ARP service.
 */
export class ArpClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: ArpClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.oa2a.org';
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  async getBehavioralRiskSignal(agentId: string): Promise<BehavioralRiskSignal> {
    // V2: fetch from ${this.baseUrl}/v1/arp/risk/${agentId}
    return {
      agentId,
      riskScore: 50,
      signals: [],
      assessedAt: Date.now(),
    };
  }
}
