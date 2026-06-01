/**
 * NanoMind-Guard IPC client.
 *
 * Connects to a NanoMind-Guard process over a Unix domain socket and
 * exchanges newline-delimited JSON requests/responses. Frozen wire shape
 * is defined in `./types.ts`.
 *
 * Structural readiness (v1.0, CHIEF-CDS decision 2026-05-28):
 *   - `isAvailable()` checks socket existence + reachability.
 *   - `classify()` performs the request/response round-trip with a
 *     bounded timeout, validates the response shape, and maps to a
 *     ClassifierResult.
 *   - When the socket is absent or unreachable, both methods fail
 *     closed (false / null) so the dual-layer classifier silently
 *     falls back to regex-only.
 *
 * The default socket path is `/tmp/nanomind-guard.sock`, which the
 * real Guard binary will bind once Phase 2b training completes. For
 * tests and local development the path can be overridden via the
 * `MOCK_GUARD_SOCKET` env var or the `socketPath` constructor option.
 *
 * The real Guard binary is intentionally NOT shipped with v1.0 - this
 * is a stub-with-real-IPC, not a stub-with-fake-classification. Until
 * a NanoMind model is trained and released, no socket exists and
 * everything degrades to regex-only.
 */

import { existsSync } from 'node:fs';
import { createConnection } from 'node:net';
import type { ClassifierResult, Violation } from '../../types';
import type { GuardClientOptions, GuardRequest, GuardResponse } from './types';

const DEFAULT_SOCKET_PATH = '/tmp/nanomind-guard.sock';
const DEFAULT_TIMEOUT_MS = 5000;

export class GuardClient {
  private readonly socketPath: string;
  private readonly timeoutMs: number;

  constructor(options: GuardClientOptions = {}) {
    this.socketPath =
      options.socketPath ?? process.env.MOCK_GUARD_SOCKET ?? DEFAULT_SOCKET_PATH;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /**
   * Is the Guard process reachable? Verifies the socket file exists and
   * accepts a connection within the configured timeout. Cheap (existsSync
   * + short TCP handshake-equivalent) so it can run before every classify
   * call without meaningful overhead.
   */
  async isAvailable(): Promise<boolean> {
    if (!existsSync(this.socketPath)) return false;
    let socket;
    try {
      socket = await this.openConnection(Math.min(this.timeoutMs, 200));
    } catch {
      return false;
    }
    // Half-close + force-destroy so the fd is released immediately
    // (end() alone leaves the socket in FIN_WAIT until kernel reaps it,
    // which leaks fds under tight-loop readiness probing).
    socket.end();
    socket.destroy();
    return true;
  }

  /**
   * Classify content via Guard. Returns null when Guard is unavailable,
   * unreachable, times out, or returns a malformed payload - in which
   * case the dual-layer classifier silently falls back to regex-only.
   * Returns a valid ClassifierResult on a successful round-trip.
   */
  async classify(content: string): Promise<ClassifierResult | null> {
    if (!existsSync(this.socketPath)) return null;

    let socket;
    try {
      socket = await this.openConnection(this.timeoutMs);
    } catch {
      return null;
    }

    try {
      const request: GuardRequest = { content };
      const responseText = await this.sendAndRead(socket, JSON.stringify(request));
      const parsed = this.parseResponse(responseText);
      if (parsed === null) return null;
      return this.toClassifierResult(parsed);
    } catch {
      return null;
    } finally {
      socket.end();
      socket.destroy();
    }
  }

  /**
   * Socket path for diagnostics.
   */
  getSocketPath(): string {
    return this.socketPath;
  }

  /**
   * Configured timeout for diagnostics.
   */
  getTimeoutMs(): number {
    return this.timeoutMs;
  }

  // ---- internals --------------------------------------------------------

  private openConnection(timeoutMs: number): Promise<import('node:net').Socket> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(this.socketPath);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('connect timeout'));
      }, timeoutMs);
      socket.once('connect', () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  private sendAndRead(
    socket: import('node:net').Socket,
    payload: string,
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      let buf = '';
      const timer = setTimeout(() => {
        reject(new Error('read timeout'));
      }, this.timeoutMs);

      socket.setEncoding('utf8');
      socket.on('data', (chunk) => {
        buf += chunk;
        const nl = buf.indexOf('\n');
        if (nl !== -1) {
          clearTimeout(timer);
          resolve(buf.slice(0, nl));
        }
      });
      socket.on('end', () => {
        clearTimeout(timer);
        if (buf.length > 0) resolve(buf);
        else reject(new Error('socket closed before response'));
      });
      socket.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      socket.write(payload + '\n');
    });
  }

  private parseResponse(raw: string): GuardResponse | null {
    try {
      const parsed = JSON.parse(raw) as Partial<GuardResponse>;
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        typeof parsed.verdict !== 'string' ||
        !['CLEAN', 'VIOLATION', 'DENY'].includes(parsed.verdict) ||
        !Array.isArray(parsed.violations) ||
        typeof parsed.modelVersion !== 'string' ||
        typeof parsed.latencyMs !== 'number'
      ) {
        return null;
      }
      return parsed as GuardResponse;
    } catch {
      return null;
    }
  }

  private toClassifierResult(response: GuardResponse): ClassifierResult {
    const violations: Violation[] = response.violations.map((v) => ({
      type: typeof v.type === 'string' ? v.type : 'GUARD',
      value: '***GUARD***',
      start: typeof v.start === 'number' ? v.start : 0,
      end: typeof v.end === 'number' ? v.end : 0,
      confidence: typeof v.confidence === 'number' ? v.confidence : 0,
      classifier: 'guard',
    }));
    return {
      classifier: 'guard',
      verdict: response.verdict,
      violations,
    };
  }
}
