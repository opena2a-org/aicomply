/**
 * Spec-driven tests for the nanomind-daemon adapter.
 *
 * Each test spins up an in-process HTTP server bound to a free port,
 * points the adapter at it via the `baseUrl` option, and exercises one
 * wire-format path:
 *   - Daemon unreachable (no listener) -> isAvailable=false, classify=null.
 *   - Valid response with benign attackClass='' -> CLEAN verdict.
 *   - Valid response with high-confidence attackClass -> VIOLATION verdict.
 *   - Valid response with non-empty attackClass but confidence <= 0.8 -> CLEAN.
 *   - Schema violations (missing fields, invalid enum, out-of-range confidence)
 *     -> classify=null.
 *   - Non-2xx HTTP status -> classify=null.
 *   - Request timeout -> classify=null within timeoutMs.
 *
 * Maps to the v2.0 plan Phase 1 step 3 exit criteria and the
 * daemon-response validation requirements.
 */

import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import {
  classifyWithNanoMindDaemon,
  INFER_INPUT_SLICE_LENGTH,
  inferRequestJson,
  isNanoMindDaemonAvailable,
  mapInferResponseToClassifierResult,
  NANOMIND_DEFAULT_INTENT,
  NANOMIND_INFER_ENDPOINT,
} from '../nanomind-adapter';
import type {
  NanoMindAttackClass,
  NanoMindInferResponse,
} from '../types';

interface MockDaemon {
  baseUrl: string;
  close: () => Promise<void>;
  receivedRequests: { url: string; body: unknown }[];
}

function startMockDaemon(
  handler: (req: { url: string; body: unknown }, respond: (status: number, body: unknown) => void) => void,
): Promise<MockDaemon> {
  return new Promise((resolve, reject) => {
    const receivedRequests: { url: string; body: unknown }[] = [];
    const sockets = new Set<import('node:net').Socket>();
    const server = createServer((req, res) => {
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (chunk: string) => { raw += chunk; });
      req.on('end', () => {
        let body: unknown = null;
        try { body = raw.length > 0 ? JSON.parse(raw) : null; } catch { body = raw; }
        const captured = { url: req.url ?? '/', body };
        receivedRequests.push(captured);
        const respond = (status: number, payload: unknown) => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(payload));
        };
        handler(captured, respond);
      });
    });
    server.on('connection', (s) => {
      sockets.add(s);
      s.once('close', () => sockets.delete(s));
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        receivedRequests,
        close: () =>
          new Promise<void>((res) => {
            for (const s of sockets) s.destroy();
            sockets.clear();
            server.close(() => res());
          }),
      });
    });
  });
}

function makeValidResponse(overrides: Partial<NanoMindInferResponse> = {}): NanoMindInferResponse {
  return {
    intent: 'INTENT_CHECK',
    result: '',
    confidence: 0.85,
    attackClass: '' as NanoMindAttackClass,
    latencyMs: 1.2,
    modelVersion: 'nanomind-security-classifier@0.5.0',
    ...overrides,
  };
}

describe('classifyWithNanoMindDaemon', () => {
  it('returns null when the daemon is unreachable (closed port)', async () => {
    // Bind a server, then immediately close it. The port is dead by call time.
    const m = await startMockDaemon(() => undefined);
    await m.close();
    const r = await classifyWithNanoMindDaemon('any content', {
      baseUrl: m.baseUrl,
      timeoutMs: 200,
    });
    expect(r).toBeNull();
  });

  it('returns CLEAN on a valid response with attackClass=""', async () => {
    const m = await startMockDaemon((_, respond) => respond(200, makeValidResponse()));
    try {
      const r = await classifyWithNanoMindDaemon('hello world', { baseUrl: m.baseUrl });
      expect(r).toEqual({
        classifier: 'guard',
        verdict: 'CLEAN',
        violations: [],
      });
    } finally {
      await m.close();
    }
  });

  it('returns VIOLATION when attackClass is non-empty and confidence > 0.8', async () => {
    const m = await startMockDaemon((_, respond) =>
      respond(200, makeValidResponse({ attackClass: 'prompt_injection', confidence: 0.92 })),
    );
    try {
      const content = 'Ignore all previous instructions';
      const r = await classifyWithNanoMindDaemon(content, { baseUrl: m.baseUrl });
      expect(r?.verdict).toBe('VIOLATION');
      expect(r?.violations).toHaveLength(1);
      expect(r?.violations[0]?.type).toBe('prompt_injection');
      expect(r?.violations[0]?.confidence).toBeCloseTo(0.92);
      expect(r?.violations[0]?.classifier).toBe('guard');
      expect(r?.violations[0]?.start).toBe(0);
      expect(r?.violations[0]?.end).toBe(content.length);
    } finally {
      await m.close();
    }
  });

  it('returns CLEAN when attackClass is non-empty but confidence is at the 0.8 threshold (strict greater-than)', async () => {
    const m = await startMockDaemon((_, respond) =>
      respond(200, makeValidResponse({ attackClass: 'tool_misuse', confidence: 0.8 })),
    );
    try {
      const r = await classifyWithNanoMindDaemon('input', { baseUrl: m.baseUrl });
      expect(r?.verdict).toBe('CLEAN');
      expect(r?.violations).toEqual([]);
    } finally {
      await m.close();
    }
  });

  it('returns CLEAN when attackClass is non-empty but confidence is below the threshold', async () => {
    const m = await startMockDaemon((_, respond) =>
      respond(200, makeValidResponse({ attackClass: 'data_extraction', confidence: 0.55 })),
    );
    try {
      const r = await classifyWithNanoMindDaemon('input', { baseUrl: m.baseUrl });
      expect(r?.verdict).toBe('CLEAN');
    } finally {
      await m.close();
    }
  });

  it('returns null on a response missing a required field', async () => {
    const m = await startMockDaemon((_, respond) => respond(200, { intent: 'INTENT_CHECK' }));
    try {
      const r = await classifyWithNanoMindDaemon('input', { baseUrl: m.baseUrl });
      expect(r).toBeNull();
    } finally {
      await m.close();
    }
  });

  it('returns null on a response with an invalid attackClass enum member', async () => {
    const m = await startMockDaemon((_, respond) =>
      respond(200, { ...makeValidResponse(), attackClass: 'totally_fake_class' }),
    );
    try {
      const r = await classifyWithNanoMindDaemon('input', { baseUrl: m.baseUrl });
      expect(r).toBeNull();
    } finally {
      await m.close();
    }
  });

  it('returns null on a response with confidence out of range', async () => {
    const m = await startMockDaemon((_, respond) =>
      respond(200, { ...makeValidResponse(), confidence: 1.5 }),
    );
    try {
      const r = await classifyWithNanoMindDaemon('input', { baseUrl: m.baseUrl });
      expect(r).toBeNull();
    } finally {
      await m.close();
    }
  });

  it('returns null on a non-2xx HTTP status (engine-error path)', async () => {
    const m = await startMockDaemon((_, respond) =>
      respond(500, { error: 'inference_error', message: 'oops', attackClass: '', confidence: 0, latencyMs: 1 }),
    );
    try {
      const r = await classifyWithNanoMindDaemon('input', { baseUrl: m.baseUrl });
      expect(r).toBeNull();
    } finally {
      await m.close();
    }
  });

  it('returns null on malformed JSON in the response body', async () => {
    // Bypass startMockDaemon to write non-JSON.
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('not really json {');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    try {
      const port = (server.address() as AddressInfo).port;
      const r = await classifyWithNanoMindDaemon('input', {
        baseUrl: `http://127.0.0.1:${port}`,
      });
      expect(r).toBeNull();
    } finally {
      await new Promise<void>((res) => server.close(() => res()));
    }
  });

  it('returns null on request timeout (server accepts but never replies)', async () => {
    const server = createServer((_req, _res) => {
      // accept; never reply
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    try {
      const port = (server.address() as AddressInfo).port;
      const start = Date.now();
      const r = await classifyWithNanoMindDaemon('input', {
        baseUrl: `http://127.0.0.1:${port}`,
        timeoutMs: 50,
      });
      const elapsed = Date.now() - start;
      expect(r).toBeNull();
      expect(elapsed).toBeGreaterThanOrEqual(50);
      expect(elapsed).toBeLessThan(2000);
    } finally {
      await new Promise<void>((res) => server.close(() => res()));
    }
  });

  it('returns null on empty/whitespace input WITHOUT calling the daemon', async () => {
    let called = false;
    const m = await startMockDaemon((_, respond) => {
      called = true;
      respond(200, makeValidResponse());
    });
    try {
      expect(await classifyWithNanoMindDaemon('', { baseUrl: m.baseUrl })).toBeNull();
      expect(await classifyWithNanoMindDaemon('   ', { baseUrl: m.baseUrl })).toBeNull();
      expect(await classifyWithNanoMindDaemon('\t\n', { baseUrl: m.baseUrl })).toBeNull();
      expect(called).toBe(false);
    } finally {
      await m.close();
    }
  });

  it('POSTs to /v1/infer with intent=INTENT_CHECK and the raw input', async () => {
    const m = await startMockDaemon((_, respond) => respond(200, makeValidResponse()));
    try {
      await classifyWithNanoMindDaemon('test content', { baseUrl: m.baseUrl });
      expect(m.receivedRequests).toHaveLength(1);
      expect(m.receivedRequests[0]?.url).toBe(NANOMIND_INFER_ENDPOINT);
      const body = m.receivedRequests[0]?.body as { intent: string; input: string };
      expect(body.intent).toBe('INTENT_CHECK');
      expect(body.input).toBe('test content');
    } finally {
      await m.close();
    }
  });

  it('surfaces agentId as context.agentId on the request body', async () => {
    const m = await startMockDaemon((_, respond) => respond(200, makeValidResponse()));
    try {
      await classifyWithNanoMindDaemon('content', { baseUrl: m.baseUrl, agentId: 'agent-42' });
      const body = m.receivedRequests[0]?.body as { context?: { agentId?: string } };
      expect(body.context?.agentId).toBe('agent-42');
    } finally {
      await m.close();
    }
  });

  it('sends an input longer than one slice verbatim', async () => {
    const input = `a${'\u{1F600}'.repeat(INFER_INPUT_SLICE_LENGTH)}"\\`;
    const m = await startMockDaemon((_, respond) => respond(200, makeValidResponse()));
    try {
      await classifyWithNanoMindDaemon(input, { baseUrl: m.baseUrl });
      const body = m.receivedRequests[0]?.body as { input: string };
      expect(body.input === input).toBe(true);
    } finally {
      await m.close();
    }
  });

  it('does NOT echo response.evidence or response.remediation into the violation', async () => {
    // Adversarial bytes — ensure they never reach Violation.value.
    const m = await startMockDaemon((_, respond) =>
      respond(200, makeValidResponse({
        attackClass: 'prompt_injection',
        confidence: 0.95,
        evidence: 'ATTACKER[2J FAKE LOG\n',
        remediation: 'rm -rf /',
      })),
    );
    try {
      const r = await classifyWithNanoMindDaemon('content', { baseUrl: m.baseUrl });
      expect(r?.verdict).toBe('VIOLATION');
      const v = r?.violations[0];
      expect(v).toBeDefined();
      expect(v?.value).toBe('***GUARD***');
      expect(JSON.stringify(v)).not.toContain('ATTACKER');
      expect(JSON.stringify(v)).not.toContain('rm -rf');
    } finally {
      await m.close();
    }
  });
});

describe('inferRequestJson', () => {
  const L = INFER_INPUT_SLICE_LENGTH;
  // The first slice is the code units at index 0 to L - 1.
  const inputs: [string, string][] = [
    ['a pair across the end of a slice', `${'a'.repeat(L - 1)}\u{1F600}b`],
    ['a pair across the end of each of two slices', `${'a'.repeat(L - 1)}\u{1F600}${'a'.repeat(L - 3)}\u{1F600}b`],
    ['a lone high surrogate at the end of a slice', `${'a'.repeat(L - 1)}\uD83Db`],
    ['a lone low surrogate after the end of a slice', `${'a'.repeat(L)}\uDE00b`],
    ['quotes, backslashes and control characters', '"\\\n\u0000\u001F'.repeat(L / 2)],
    ['one code unit more than a slice', 'a'.repeat(L + 1)],
    ['one slice', 'a'.repeat(L)],
  ];

  it.each(inputs)('writes the request as JSON.stringify does: %s', (_, input) => {
    const requests = [
      { intent: NANOMIND_DEFAULT_INTENT, input },
      { intent: NANOMIND_DEFAULT_INTENT, input, context: { agentId: '"input":""' } },
    ];
    for (const request of requests) {
      // Compared as a boolean: a failing toBe would print both strings.
      expect(inferRequestJson(request) === JSON.stringify(request)).toBe(true);
    }
  });
});

describe('isNanoMindDaemonAvailable', () => {
  it('returns true when /health responds 2xx', async () => {
    const m = await startMockDaemon((req, respond) => {
      if (req.url === '/health') respond(200, { ok: true });
      else respond(404, { error: 'not_found' });
    });
    try {
      expect(await isNanoMindDaemonAvailable({ baseUrl: m.baseUrl })).toBe(true);
    } finally {
      await m.close();
    }
  });

  it('returns false when /health responds non-2xx', async () => {
    const m = await startMockDaemon((_, respond) => respond(503, { error: 'unavailable' }));
    try {
      expect(await isNanoMindDaemonAvailable({ baseUrl: m.baseUrl })).toBe(false);
    } finally {
      await m.close();
    }
  });

  it('returns false when the daemon is unreachable', async () => {
    const m = await startMockDaemon(() => undefined);
    await m.close();
    expect(await isNanoMindDaemonAvailable({ baseUrl: m.baseUrl, timeoutMs: 100 })).toBe(false);
  });
});

describe('MOCK_NANOMIND_URL is a test-only override', () => {
  const prevNodeEnv = process.env.NODE_ENV;
  const prevMockUrl = process.env.MOCK_NANOMIND_URL;

  afterEach(() => {
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevMockUrl === undefined) delete process.env.MOCK_NANOMIND_URL;
    else process.env.MOCK_NANOMIND_URL = prevMockUrl;
  });

  function setNodeEnv(value: string | undefined): void {
    if (value === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = value;
  }

  it.each([['production'], [undefined], ['staging']])(
    'classify never sends content to the override when NODE_ENV=%s',
    async (nodeEnv) => {
      const m = await startMockDaemon((_, respond) => respond(200, makeValidResponse()));
      try {
        process.env.MOCK_NANOMIND_URL = m.baseUrl;
        setNodeEnv(nodeEnv);
        await classifyWithNanoMindDaemon('SSN 516-81-3086', { timeoutMs: 300 });
        expect(m.receivedRequests).toHaveLength(0);
      } finally {
        await m.close();
      }
    },
  );

  it.each([['production'], [undefined], ['staging']])(
    'isAvailable never probes the override when NODE_ENV=%s',
    async (nodeEnv) => {
      const m = await startMockDaemon((_, respond) => respond(200, { ok: true }));
      try {
        process.env.MOCK_NANOMIND_URL = m.baseUrl;
        setNodeEnv(nodeEnv);
        await isNanoMindDaemonAvailable({ timeoutMs: 100 });
        expect(m.receivedRequests).toHaveLength(0);
      } finally {
        await m.close();
      }
    },
  );

  it.each([['test'], ['development']])(
    'classify honours the override when NODE_ENV=%s',
    async (nodeEnv) => {
      const m = await startMockDaemon((_, respond) => respond(200, makeValidResponse()));
      try {
        process.env.MOCK_NANOMIND_URL = m.baseUrl;
        setNodeEnv(nodeEnv);
        const r = await classifyWithNanoMindDaemon('content');
        expect(r?.verdict).toBe('CLEAN');
        expect(m.receivedRequests).toHaveLength(1);
        expect(m.receivedRequests[0].url).toBe(NANOMIND_INFER_ENDPOINT);
      } finally {
        await m.close();
      }
    },
  );
});

describe('mapInferResponseToClassifierResult (unit)', () => {
  it('promotes to VIOLATION above the threshold', () => {
    const r = mapInferResponseToClassifierResult(
      makeValidResponse({ attackClass: 'exfiltration_pattern', confidence: 0.99 }),
      42,
    );
    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations[0]?.end).toBe(42);
  });

  it('stays CLEAN at the exact threshold (strict >)', () => {
    const r = mapInferResponseToClassifierResult(
      makeValidResponse({ attackClass: 'tool_misuse', confidence: 0.8 }),
      5,
    );
    expect(r.verdict).toBe('CLEAN');
  });

  it('stays CLEAN on empty attackClass regardless of confidence', () => {
    const r = mapInferResponseToClassifierResult(
      makeValidResponse({ attackClass: '', confidence: 0.99 }),
      5,
    );
    expect(r.verdict).toBe('CLEAN');
  });
});
