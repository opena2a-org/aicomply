/**
 * Tests for the NanoMind-Guard IPC client.
 *
 * Each test spins up an in-process Unix-socket server bound to a temp
 * path, points the GuardClient at it via the `socketPath` option, and
 * exercises one wire-format path:
 *   - Socket file missing → isAvailable=false, classify=null.
 *   - Valid response → mapped ClassifierResult.
 *   - Malformed JSON / wrong shape → classify=null (silent fallback).
 *   - Read timeout (server accepts but never replies) → classify=null.
 *
 * Design constraint: the Guard socket binary is not shipped, so in a
 * real install GuardClient is an IPC stub that returns null when the
 * socket is absent. The IPC layer is still fully wired and testable,
 * so a deployed socket is all a real Guard binary would need - no
 * code change.
 */

import { createServer, Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GuardClient } from '../index';

interface MockServer {
  socketPath: string;
  close: () => Promise<void>;
}

function startMockServer(
  handler: (sock: Socket) => void,
  socketPath: string,
): Promise<MockServer> {
  return new Promise((resolve, reject) => {
    const liveSockets = new Set<Socket>();
    const server = createServer((sock) => {
      liveSockets.add(sock);
      sock.once('close', () => liveSockets.delete(sock));
      handler(sock);
    });
    server.on('error', reject);
    server.listen(socketPath, () => {
      resolve({
        socketPath,
        close: () =>
          new Promise<void>((res) => {
            // Forcibly tear down any still-open client connections so
            // server.close() doesn't hang on the silent-server test.
            for (const s of liveSockets) s.destroy();
            liveSockets.clear();
            server.close(() => res());
          }),
      });
    });
  });
}

describe('GuardClient', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aicomply-guard-'));
  });

  afterEach(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* noop */ }
  });

  it('isAvailable=false when the socket path does not exist', async () => {
    const client = new GuardClient({ socketPath: join(tmpDir, 'missing.sock') });
    expect(await client.isAvailable()).toBe(false);
  });

  it('classify returns null when Guard is unavailable (silent fallback)', async () => {
    const client = new GuardClient({ socketPath: join(tmpDir, 'missing.sock') });
    const r = await client.classify('any content');
    expect(r).toBeNull();
  });

  it('reads MOCK_GUARD_SOCKET env var when no socketPath is supplied', () => {
    const prev = process.env.MOCK_GUARD_SOCKET;
    process.env.MOCK_GUARD_SOCKET = '/tmp/some-mock.sock';
    try {
      const c = new GuardClient();
      expect(c.getSocketPath()).toBe('/tmp/some-mock.sock');
    } finally {
      if (prev === undefined) delete process.env.MOCK_GUARD_SOCKET;
      else process.env.MOCK_GUARD_SOCKET = prev;
    }
  });

  it.each([['production'], [undefined], ['staging']])(
    'ignores MOCK_GUARD_SOCKET when NODE_ENV=%s',
    (nodeEnv) => {
      const prevSocket = process.env.MOCK_GUARD_SOCKET;
      const prevNodeEnv = process.env.NODE_ENV;
      process.env.MOCK_GUARD_SOCKET = '/tmp/some-mock.sock';
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      try {
        expect(new GuardClient().getSocketPath()).toBe('/tmp/nanomind-guard.sock');
        expect(new GuardClient({ socketPath: '/tmp/explicit.sock' }).getSocketPath()).toBe(
          '/tmp/explicit.sock',
        );
      } finally {
        if (prevSocket === undefined) delete process.env.MOCK_GUARD_SOCKET;
        else process.env.MOCK_GUARD_SOCKET = prevSocket;
        if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = prevNodeEnv;
      }
    },
  );

  it('isAvailable=true when a server is listening on the socket', async () => {
    const sockPath = join(tmpDir, 'live.sock');
    const server = await startMockServer((sock) => sock.end(), sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath });
      expect(await client.isAvailable()).toBe(true);
    } finally {
      await server.close();
    }
  });

  it('classify returns a mapped ClassifierResult on a valid response', async () => {
    const sockPath = join(tmpDir, 'guard.sock');
    const response = {
      verdict: 'VIOLATION',
      violations: [
        { type: 'data-exfiltration', confidence: 0.92, start: 0, end: 20 },
      ],
      modelVersion: 'nanomind-guard-test-0',
      latencyMs: 1.5,
    };
    const server = await startMockServer((sock) => {
      sock.setEncoding('utf8');
      sock.on('data', () => {
        sock.write(JSON.stringify(response) + '\n');
        sock.end();
      });
    }, sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath });
      const result = await client.classify('look at this content');
      expect(result).not.toBeNull();
      expect(result?.classifier).toBe('guard');
      expect(result?.verdict).toBe('VIOLATION');
      expect(result?.violations).toHaveLength(1);
      expect(result?.violations[0]?.type).toBe('data-exfiltration');
      expect(result?.violations[0]?.classifier).toBe('guard');
    } finally {
      await server.close();
    }
  });

  it('classify returns null on malformed JSON (silent fallback, not throw)', async () => {
    const sockPath = join(tmpDir, 'broken.sock');
    const server = await startMockServer((sock) => {
      sock.on('data', () => {
        sock.write('this is not json\n');
        sock.end();
      });
    }, sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath });
      const result = await client.classify('anything');
      expect(result).toBeNull();
    } finally {
      await server.close();
    }
  });

  it('classify returns null on a response missing required fields', async () => {
    const sockPath = join(tmpDir, 'partial.sock');
    const server = await startMockServer((sock) => {
      sock.on('data', () => {
        sock.write(JSON.stringify({ verdict: 'CLEAN' }) + '\n');
        sock.end();
      });
    }, sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath });
      const result = await client.classify('anything');
      expect(result).toBeNull();
    } finally {
      await server.close();
    }
  });

  it('classify returns null on a response with an invalid verdict', async () => {
    const sockPath = join(tmpDir, 'bogus-verdict.sock');
    const server = await startMockServer((sock) => {
      sock.on('data', () => {
        sock.write(
          JSON.stringify({
            verdict: 'PROBABLY_FINE',
            violations: [],
            modelVersion: 'x',
            latencyMs: 0,
          }) + '\n',
        );
        sock.end();
      });
    }, sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath });
      const result = await client.classify('anything');
      expect(result).toBeNull();
    } finally {
      await server.close();
    }
  });

  it('classify returns null on read timeout (server accepts but never replies)', async () => {
    const sockPath = join(tmpDir, 'silent.sock');
    const server = await startMockServer(() => {
      // accept; do nothing. The connection stays open silently.
    }, sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath, timeoutMs: 50 });
      const start = Date.now();
      const result = await client.classify('anything');
      const elapsed = Date.now() - start;
      expect(result).toBeNull();
      // Node starts a timer from the event loop's cached clock, which can lag
      // Date.now() by a millisecond or so, so a 50 ms timer can measure 49.
      // The bound allows for that and still fails a timeout that fires early.
      expect(elapsed).toBeGreaterThanOrEqual(45);
      expect(elapsed).toBeLessThan(1000);
    } finally {
      await server.close();
    }
  });

  it('passes the verdict through directly: DENY response → DENY result', async () => {
    const sockPath = join(tmpDir, 'deny.sock');
    const server = await startMockServer((sock) => {
      sock.on('data', () => {
        sock.write(
          JSON.stringify({
            verdict: 'DENY',
            violations: [{ type: 'prompt-injection', confidence: 0.99, start: 0, end: 10 }],
            modelVersion: 'test',
            latencyMs: 2,
          }) + '\n',
        );
        sock.end();
      });
    }, sockPath);
    try {
      const client = new GuardClient({ socketPath: sockPath });
      const result = await client.classify('content');
      expect(result?.verdict).toBe('DENY');
    } finally {
      await server.close();
    }
  });
});
