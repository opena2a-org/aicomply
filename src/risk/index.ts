/**
 * RiskContext assembly.
 *
 * Combines trust level, behavioral signals, and registry intelligence
 * into an aggregate risk assessment.
 */

import type { RiskContext } from '../types';
import type { AssembledRiskContext, RiskSignal } from './types';

/**
 * Assemble a full risk context from the input context and available signals.
 * V1: pass-through with defaults. V2: query ARP and Registry.
 */
export function assembleRiskContext(
  input?: RiskContext,
  signals: RiskSignal[] = [],
): AssembledRiskContext {
  const trustLevel = input?.trustLevel ?? 0;
  const aggregateScore = computeAggregateScore(trustLevel, signals);

  return {
    agentId: input?.agentId,
    sessionId: input?.sessionId,
    trustLevel,
    signals,
    aggregateScore,
    recommendation: scoreToRecommendation(aggregateScore),
  };
}

function computeAggregateScore(
  trustLevel: number,
  signals: RiskSignal[],
): number {
  // Normalize trustLevel from 0–4 registry tier to 0–100 score scale
  const normalizedTrustLevel = trustLevel * 25;

  if (signals.length === 0) return normalizedTrustLevel;

  const signalAvg =
    signals.reduce((sum, s) => sum + s.score, 0) / signals.length;

  // Weighted: 60% trust level, 40% signal average
  return normalizedTrustLevel * 0.6 + signalAvg * 0.4;
}

function scoreToRecommendation(
  score: number,
): AssembledRiskContext['recommendation'] {
  if (score >= 70) return 'ALLOW';
  if (score >= 40) return 'ELEVATED_SCRUTINY';
  return 'DENY';
}
