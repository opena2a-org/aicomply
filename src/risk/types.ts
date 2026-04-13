/**
 * Types for risk context assembly.
 */

export interface RiskSignal {
  source: string;
  score: number;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface AssembledRiskContext {
  agentId?: string;
  sessionId?: string;
  trustLevel: number;
  signals: RiskSignal[];
  aggregateScore: number;
  recommendation: 'ALLOW' | 'ELEVATED_SCRUTINY' | 'DENY';
}
