/**
 * Session vault -- in-memory AES-256-GCM encrypted storage.
 *
 * Provides temporary encrypted storage for sensitive content
 * during compliance processing. Keys are derived per-session
 * and never persisted to disk.
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV for GCM
const TAG_LENGTH = 16; // 128-bit auth tag
const KEY_LENGTH = 32; // 256-bit key

export interface VaultEntry {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
  createdAt: number;
}

export class SessionVault {
  private readonly key: Buffer;
  private readonly entries = new Map<string, VaultEntry>();
  private readonly maxEntries: number;
  private readonly ttlMs: number;

  /**
   * Create a new session vault with a random encryption key.
   *
   * @param maxEntries - Maximum number of entries before oldest are evicted (default 1000)
   * @param ttlMs - Time-to-live for entries in milliseconds (default 5 minutes)
   */
  constructor(maxEntries = 1000, ttlMs = 5 * 60 * 1000) {
    this.key = randomBytes(KEY_LENGTH);
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
  }

  /**
   * Store a value encrypted under a given key.
   * Returns the entry ID.
   */
  store(id: string, plaintext: string): string {
    this.evictExpired();

    if (this.entries.size >= this.maxEntries) {
      // Evict oldest entry
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) {
        this.entries.delete(oldest);
      }
    }

    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    this.entries.set(id, {
      encrypted,
      iv,
      authTag,
      createdAt: Date.now(),
    });

    return id;
  }

  /**
   * Retrieve and decrypt a value by ID.
   * Returns null if not found or expired.
   */
  retrieve(id: string): string | null {
    const entry = this.entries.get(id);
    if (!entry) return null;

    if (Date.now() - entry.createdAt > this.ttlMs) {
      this.entries.delete(id);
      return null;
    }

    const decipher = createDecipheriv(ALGORITHM, this.key, entry.iv);
    decipher.setAuthTag(entry.authTag);

    const decrypted = Buffer.concat([
      decipher.update(entry.encrypted),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Delete an entry by ID.
   */
  delete(id: string): boolean {
    return this.entries.delete(id);
  }

  /**
   * Clear all entries and zero the key material.
   */
  destroy(): void {
    this.entries.clear();
    this.key.fill(0);
  }

  /**
   * Number of active (non-expired) entries.
   */
  size(): number {
    this.evictExpired();
    return this.entries.size;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [id, entry] of this.entries) {
      if (now - entry.createdAt > this.ttlMs) {
        this.entries.delete(id);
      }
    }
  }
}
