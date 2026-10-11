/**
 * comply() and ClassificationSession reach a Guard daemon on the address
 * given in `guardOptions`.
 *
 * NODE_ENV is set to `production` here, so the MOCK_NANOMIND_URL test
 * override is ignored and `guardOptions` is the only way a request can
 * reach the stub daemon.
 */

import { createServer } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { comply, ClassificationSession } from '..';
import { RegistryIntelligenceCache } from '../registry';
import type { ComplyOptions } from '../types';
import type { NanoMindInferResponse } from '../classifier/guard-client/types';

interface StubDaemon {
  baseUrl: string;
  inputs: string[];
  close: () => Promise<void>;
}

function startStubDaemon(response: Partial<NanoMindInferResponse>): Promise<StubDaemon> {
  return new Promise((resolve, reject) => {
    const inputs: string[] = [];
    const sockets = new Set<Socket>();
    const server = createServer((req, res) => {
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (c: string) => { raw += c; });
      req.on('end', () => {
        inputs.push((JSON.parse(raw) as { input: string }).input);
        const payload: NanoMindInferResponse = {
          intent: 'INTENT_CHECK',
          result: '',
          confidence: 0.99,
          attackClass: '',
          latencyMs: 1,
          modelVersion: 'nanomind-security-classifier@0.5.0',
          ...response,
        };
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
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
        inputs,
        close: () =>
          new Promise((res) => {
            for (const s of sockets) s.destroy();
            sockets.clear();
            server.close(() => res());
          }),
      });
    });
  });
}

const originalNodeEnv = process.env.NODE_ENV;
let daemon: StubDaemon | undefined;

beforeEach(() => {
  process.env.NODE_ENV = 'production';
});

afterEach(async () => {
  process.env.NODE_ENV = originalNodeEnv;
  jest.restoreAllMocks();
  if (daemon) await daemon.close();
  daemon = undefined;
});

describe('comply({ guardOptions })', () => {
  it('sends the content to the daemon at guardOptions.baseUrl', async () => {
    daemon = await startStubDaemon({ attackClass: '' });

    const r = await comply({ content: 'hello world', guardOptions: { baseUrl: daemon.baseUrl } });

    expect(daemon.inputs).toEqual(['hello world']);
    expect(r.classifierResults.guard).toEqual({ classifier: 'guard', verdict: 'CLEAN', violations: [] });
    expect(r.layers).toEqual(['normalize', 'regex', 'guard']);
  });

  it('merges a Guard violation from that daemon into the verdict', async () => {
    daemon = await startStubDaemon({ attackClass: 'prompt_injection', confidence: 0.95 });

    const r = await comply({ content: 'hello world', guardOptions: { baseUrl: daemon.baseUrl } });

    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations.map((v) => [v.type, v.classifier])).toEqual([['prompt_injection', 'guard']]);
  });

  it('takes guardOptions from dualLayerOptions when the options object has none', async () => {
    daemon = await startStubDaemon({ attackClass: '' });

    const r = await comply({ content: 'hello world' }, { guardOptions: { baseUrl: daemon.baseUrl } });

    expect(daemon.inputs).toEqual(['hello world']);
    expect(r.layers).toContain('guard');
  });

  it('falls back to regex-only when the daemon at guardOptions.baseUrl is unreachable', async () => {
    const r = await comply({
      content: 'hello world',
      guardOptions: { baseUrl: 'http://127.0.0.1:1', timeoutMs: 500 },
    });

    expect('guard' in r.classifierResults).toBe(false);
    expect(r.layers).toEqual(['normalize', 'regex']);
  });

  it('rejects a guardOptions that is not an object, naming the expected shape', async () => {
    const bad = { content: 'hello world', guardOptions: 'http://10.0.0.5:47200' } as unknown as ComplyOptions;

    await expect(comply(bad)).rejects.toThrow(TypeError);
    await expect(comply(bad)).rejects.toThrow(
      "comply: options.guardOptions must be an object like { baseUrl: 'http://host:port' }, got string",
    );
    await expect(
      comply({ content: 'hello world', guardOptions: null } as unknown as ComplyOptions),
    ).rejects.toThrow(/got null$/);
  });
});

describe('ClassificationSession guardOptions', () => {
  beforeEach(() => {
    jest.spyOn(RegistryIntelligenceCache.prototype, 'warm').mockResolvedValue(undefined);
  });

  it('sends every session.comply() to the daemon given to create()', async () => {
    daemon = await startStubDaemon({ attackClass: '' });

    const session = await ClassificationSession.create({ guardOptions: { baseUrl: daemon.baseUrl } });
    const first = await session.comply({ content: 'first input' });
    const second = await session.comply({ content: 'second input' });

    expect(daemon.inputs).toEqual(['first input', 'second input']);
    expect(first.layers).toContain('guard');
    expect(second.layers).toContain('guard');
  });

  it('keeps the Registry baseUrl apart from the Guard baseUrl', async () => {
    const session = await ClassificationSession.create({
      baseUrl: 'https://registry.example',
      timeoutMs: 1234,
      guardOptions: { baseUrl: 'http://127.0.0.1:1' },
    });

    const cache = (session as unknown as { cache: Record<string, unknown> }).cache;
    expect(cache.baseUrl).toBe('https://registry.example');
    expect(cache.timeoutMs).toBe(1234);
  });

  it('lets guardOptions on a call take precedence over the session setting', async () => {
    daemon = await startStubDaemon({ attackClass: '' });

    const session = await ClassificationSession.create({
      guardOptions: { baseUrl: 'http://127.0.0.1:1', timeoutMs: 500 },
    });
    const viaOptions = await session.comply({
      content: 'per-call options',
      guardOptions: { baseUrl: daemon.baseUrl },
    });
    const viaDualLayer = await session.comply(
      { content: 'per-call dual-layer options' },
      { guardOptions: { baseUrl: daemon.baseUrl } },
    );

    expect(daemon.inputs).toEqual(['per-call options', 'per-call dual-layer options']);
    expect(viaOptions.layers).toContain('guard');
    expect(viaDualLayer.layers).toContain('guard');
  });
});
