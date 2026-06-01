/**
 * Types for the NanoMind-Guard IPC client.
 *
 * The aicomply-side `GuardRequest` / `GuardResponse` are the abstract
 * wire shape the dual-layer classifier expects. The `NanoMindInfer*`
 * types below mirror the concrete wire format spoken by
 * `@nanomind/daemon` v0.2.0 over HTTP. The adapter in
 * `./nanomind-adapter.ts` translates between the two so the
 * dual-layer code stays decoupled from the daemon's specific shape.
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

// ---------------------------------------------------------------------------
// @nanomind/daemon v0.2.0 wire format (frozen — must not drift from upstream)
// ---------------------------------------------------------------------------

/**
 * Canonical attack-class enum emitted by `@nanomind/daemon`. Mirrors the
 * `AttackClass` union in `nanomind/packages/nanomind-daemon/src/server.ts`.
 * The empty string is the always-emitted default for benign / no-block;
 * the four non-empty values are produced by the production classifier
 * (ONNX, nanomind-security-classifier v0.5.0).
 *
 * Block contract per AIM FGA Step 5: `attackClass !== '' && confidence > 0.8`.
 */
export type NanoMindAttackClass =
  | ''
  | 'exfiltration_pattern'
  | 'prompt_injection'
  | 'tool_misuse'
  | 'data_extraction';

/**
 * Body shape sent to `POST /v1/infer` on the nanomind daemon.
 *
 * `intent` is metadata/routing only — the engine classifies `input`
 * regardless of which intent string is passed. `'INTENT_CHECK'` is the
 * convention used by the daemon's own test suite.
 */
export interface NanoMindInferRequest {
  intent: string;
  input: string;
  context?: {
    agentId?: string;
    driftScore?: number;
    declaredPurpose?: string;
  };
  priority?: 'high' | 'medium' | 'low';
}

/**
 * Success-path body shape returned by `POST /v1/infer`.
 *
 * `attackClass` is always a string (Bug 1 contract — never undefined).
 * `confidence` is in [0.0, 1.0]. `modelVersion` carries the active
 * model artifact identifier. `evidence` and `remediation` are
 * advisory; do not pass them into `Violation.value` because they may
 * contain attacker-influenced bytes.
 */
export interface NanoMindInferResponse {
  intent: string;
  result: string;
  confidence: number;
  attackClass: NanoMindAttackClass;
  evidence?: string;
  remediation?: string;
  latencyMs: number;
  modelVersion: string;
}

/**
 * Error-path body shape returned when the daemon's HTTP status is non-2xx.
 * The daemon still emits `attackClass: ''` so consumers don't have to
 * special-case missing fields, but the response is NOT a full
 * `NanoMindInferResponse`. Treat as "classification did not run" → null
 * to the dual-layer (silent fallback to regex-only).
 */
export interface NanoMindErrorResponse {
  error: string;
  message: string;
  attackClass: '';
  confidence: number;
  latencyMs: number;
}
