/**
 * NanoMind-Guard IPC client.
 *
 * STUB: V1 ships with regex-only classification (Decision D1).
 * This client will connect to a NanoMind-Guard process via Unix socket
 * in V2 when the Mamba compliance head is trained.
 */

import type { ClassifierResult } from '../../types';
import type { GuardClientOptions } from './types';

export class GuardClient {
  private readonly socketPath: string;
  private readonly timeoutMs: number;
  private connected = false;

  constructor(options: GuardClientOptions = {}) {
    this.socketPath = options.socketPath ?? '/tmp/nanomind-guard.sock';
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  /**
   * Check if the Guard process is available.
   * Always returns false in V1 (stub).
   */
  async isAvailable(): Promise<boolean> {
    // V2: check if Unix socket exists and responds to health check
    return false;
  }

  /**
   * Classify content using NanoMind-Guard.
   * Returns null in V1 (stub) -- dual-layer falls back to regex-only.
   */
  async classify(_content: string): Promise<ClassifierResult | null> {
    if (!await this.isAvailable()) {
      return null;
    }

    // V2: send content over IPC, parse GuardResponse, map to ClassifierResult
    return null;
  }

  /**
   * Returns true if Guard is connected and healthy.
   */
  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Socket path getter for diagnostics.
   */
  getSocketPath(): string {
    return this.socketPath;
  }

  /**
   * Timeout getter for diagnostics.
   */
  getTimeoutMs(): number {
    return this.timeoutMs;
  }
}
