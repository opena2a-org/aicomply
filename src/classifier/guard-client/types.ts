/**
 * Types for the NanoMind-Guard IPC client.
 */

export interface GuardRequest {
  content: string;
  sessionId?: string;
}

export interface GuardResponse {
  verdict: 'CLEAN' | 'VIOLATION' | 'DENY';
  violations: Array<{
    type: string;
    confidence: number;
    start: number;
    end: number;
  }>;
  modelVersion: string;
  latencyMs: number;
}

export interface GuardClientOptions {
  socketPath?: string;
  timeoutMs?: number;
}
