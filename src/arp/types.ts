/**
 * Types for the Agent Reputation Protocol (ARP) client.
 */

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
