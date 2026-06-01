/**
 * Adapter between aicomply's GuardClient and @nanomind/daemon v0.2.0.
 *
 * The daemon serves classification over HTTP on `127.0.0.1:47200` by
 * default. This adapter:
 *
 *   - Translates an aicomply `GuardRequest` into the daemon's
 *     `NanoMindInferRequest` and POSTs to `/v1/infer`.
 *   - Validates every field on the response per the frozen wire
 *     contract; any malformed or partially-shaped payload is rejected.
 *   - Maps the canonical `NanoMindAttackClass` enum into aicomply's
 *     three-valued `Verdict`. Empty string is CLEAN; non-empty values
 *     promote to VIOLATION when confidence clears the block threshold,
 *     and stay CLEAN below it (the daemon emits low-confidence guesses
 *     even for benign inputs; AIM FGA Step 5 sets the same threshold).
 *   - Synthesizes a single `Violation` per response anchored at
 *     `[0, content.length)` since the daemon today returns a
 *     class-level verdict, not per-span hits.
 *
 * On any error (network failure, non-2xx HTTP status, malformed JSON,
 * schema violation, request timeout) the adapter returns `null` so the
 * dual-layer classifier silently falls back to regex-only. The
 * daemon is treated as a defense-in-depth layer — its absence must
 * never cause a request to fail.
 *
 * Trust boundary (CHIEF-CSR 2026-06-01): the daemon is a separate
 * process and its responses are an attack surface. The `evidence` and
 * `remediation` fields are NEVER copied into `Violation.value` because
 * they may carry attacker-influenced strings; only the structured
 * `attackClass` enum becomes the type.
 */

import type { ClassifierResult, Violation } from '../../types';
import type {
  NanoMindAttackClass,
  NanoMindInferRequest,
  NanoMindInferResponse,
} from './types';

/**
 * The four non-empty AttackClass values. Used to validate that a
 * response's `attackClass` is a member of the canonical enum and to
 * gate the CLEAN-vs-VIOLATION mapping.
 */
const NON_EMPTY_ATTACK_CLASSES: ReadonlySet<NanoMindAttackClass> = new Set([
  'exfiltration_pattern',
  'prompt_injection',
  'tool_misuse',
  'data_extraction',
]);

/**
 * Block threshold per AIM FGA Step 5: a non-empty `attackClass` only
 * blocks (= promotes to VIOLATION) when confidence exceeds 0.8. Below
 * that the daemon is hedging and the dual-layer should not act on it.
 */
const BLOCK_CONFIDENCE_THRESHOLD = 0.8;

export const DEFAULT_NANOMIND_DAEMON_URL = 'http://127.0.0.1:47200';
export const DEFAULT_NANOMIND_TIMEOUT_MS = 5000;
export const NANOMIND_INFER_ENDPOINT = '/v1/infer';
export const NANOMIND_DEFAULT_INTENT = 'INTENT_CHECK';

export interface NanoMindAdapterOptions {
  /**
   * Base URL the daemon is reachable at. Defaults to
   * `http://127.0.0.1:47200`. The `MOCK_NANOMIND_URL` env var overrides
   * the default for tests and local development.
   */
  baseUrl?: string;
  /**
   * Per-call timeout. Beyond this the request is aborted and the
   * adapter returns null. Defaults to 5000ms.
   */
  timeoutMs?: number;
  /**
   * Optional caller-supplied agent identifier surfaced as
   * `context.agentId` on the daemon request. Has no effect on
   * classification today.
   */
  agentId?: string;
}

/**
 * Validate that a parsed JSON body matches `NanoMindInferResponse`.
 * Returns the typed response on success or null on any schema
 * violation.
 */
function validateInferResponse(raw: unknown): NanoMindInferResponse | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;

  if (typeof r.intent !== 'string') return null;
  if (typeof r.result !== 'string') return null;
  if (typeof r.confidence !== 'number') return null;
  if (r.confidence < 0 || r.confidence > 1) return null;
  if (typeof r.attackClass !== 'string') return null;
  if (r.attackClass !== '' && !NON_EMPTY_ATTACK_CLASSES.has(r.attackClass as NanoMindAttackClass)) {
    return null;
  }
  if (typeof r.latencyMs !== 'number' || r.latencyMs < 0) return null;
  if (typeof r.modelVersion !== 'string' || r.modelVersion.length === 0) return null;
  if (r.evidence !== undefined && typeof r.evidence !== 'string') return null;
  if (r.remediation !== undefined && typeof r.remediation !== 'string') return null;

  return r as unknown as NanoMindInferResponse;
}

/**
 * Map a validated `NanoMindInferResponse` into a `ClassifierResult`
 * the dual-layer can merge. Empty attackClass → CLEAN. Non-empty
 * attackClass below the block threshold → CLEAN with no violations
 * (the daemon hedged; the regex layer remains authoritative). Above
 * the threshold → VIOLATION with a single anchored Violation.
 *
 * Note: `evidence` and `remediation` are deliberately NOT copied into
 * the Violation. Those strings can carry attacker-influenced bytes
 * (the input is reflected through some daemon paths). Only the
 * canonical attackClass enum reaches consumer audit logs.
 */
export function mapInferResponseToClassifierResult(
  response: NanoMindInferResponse,
  contentLength: number,
): ClassifierResult {
  const isBenign = response.attackClass === '';
  const aboveThreshold = response.confidence > BLOCK_CONFIDENCE_THRESHOLD;

  if (isBenign || !aboveThreshold) {
    return {
      classifier: 'guard',
      verdict: 'CLEAN',
      violations: [],
    };
  }

  const violation: Violation = {
    type: response.attackClass,
    value: '***GUARD***',
    start: 0,
    end: contentLength,
    confidence: response.confidence,
    classifier: 'guard',
  };

  return {
    classifier: 'guard',
    verdict: 'VIOLATION',
    violations: [violation],
  };
}

/**
 * Run one classification call against the nanomind daemon. Returns a
 * `ClassifierResult` on a clean round-trip, `null` on any failure
 * (network, non-2xx, malformed payload, timeout). The dual-layer
 * silently falls back to regex-only when this returns null.
 */
export async function classifyWithNanoMindDaemon(
  content: string,
  options: NanoMindAdapterOptions = {},
): Promise<ClassifierResult | null> {
  const baseUrl =
    options.baseUrl ??
    process.env.MOCK_NANOMIND_URL ??
    DEFAULT_NANOMIND_DAEMON_URL;
  const timeoutMs = options.timeoutMs ?? DEFAULT_NANOMIND_TIMEOUT_MS;
  const url = baseUrl.replace(/\/+$/, '') + NANOMIND_INFER_ENDPOINT;

  // Skip the daemon for empty/whitespace input. The daemon itself
  // rejects these with 400 because a pure-pad token sequence produces
  // noisy argmax; calling out is wasted work.
  if (content.trim().length === 0) return null;

  const requestBody: NanoMindInferRequest = {
    intent: NANOMIND_DEFAULT_INTENT,
    input: content,
    ...(options.agentId !== undefined ? { context: { agentId: options.agentId } } : {}),
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });

    if (!res.ok) return null;

    let parsed: unknown;
    try {
      parsed = await res.json();
    } catch {
      return null;
    }

    const validated = validateInferResponse(parsed);
    if (validated === null) return null;

    return mapInferResponseToClassifierResult(validated, content.length);
  } catch {
    // Network failure, AbortError, or fetch internals threw.
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Liveness probe against the daemon's `/health` endpoint. Returns
 * true only when the daemon responds 2xx within the configured
 * timeout. Use this before declaring the dual-layer "armed" — but do
 * NOT gate classify() on it; the per-call timeout in
 * `classifyWithNanoMindDaemon` is the authoritative health check.
 */
export async function isNanoMindDaemonAvailable(
  options: Pick<NanoMindAdapterOptions, 'baseUrl' | 'timeoutMs'> = {},
): Promise<boolean> {
  const baseUrl =
    options.baseUrl ??
    process.env.MOCK_NANOMIND_URL ??
    DEFAULT_NANOMIND_DAEMON_URL;
  const timeoutMs = Math.min(options.timeoutMs ?? 200, DEFAULT_NANOMIND_TIMEOUT_MS);
  const url = baseUrl.replace(/\/+$/, '') + '/health';

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', signal: controller.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
