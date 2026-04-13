/**
 * ARP (Agent Reputation Protocol) client.
 *
 * Verifies agent identity and retrieves behavioral risk signals
 * from the ARP service.
 *
 * STUB: V1 returns defaults. V2 wires to ARP crypto (HMA).
 */

import type { ArpVerifyResult, BehavioralRiskSignal, ArpClientOptions } from './types';

export class ArpClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: ArpClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? 'https://api.oa2a.org';
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  /**
   * Verify an agent's ARP signature.
   * V1: returns not-valid stub. V2: crypto verification via @noble/post-quantum.
   */
  async verify(_agentId: string, _signature: string): Promise<ArpVerifyResult> {
    // V2: verify hybrid signature using @noble/post-quantum
    return {
      valid: false,
      agentId: _agentId,
      trustLevel: 0,
      expiresAt: 0,
    };
  }

  /**
   * Get behavioral risk signal for an agent.
   * V1: returns neutral stub. V2: queries ARP service.
   */
  async getBehavioralRiskSignal(_agentId: string): Promise<BehavioralRiskSignal> {
    // V2: fetch from ${this.baseUrl}/v1/arp/risk/${agentId}
    return {
      agentId: _agentId,
      riskScore: 50, // neutral
      signals: [],
      assessedAt: Date.now(),
    };
  }
}
