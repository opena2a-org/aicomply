/**
 * The Guard attempt is a network request: for each non-empty input comply()
 * POSTs the content verbatim to the nanomind-daemon infer endpoint. These
 * tests pin what that request carries, that `useGuard: false` makes no request
 * at all, and that the README and SECURITY.md describe the request instead of
 * claiming comply() does no network I/O.
 */

import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { join } from 'node:path';
import {
  ClassificationSession,
  DEFAULT_NANOMIND_DAEMON_URL,
  NANOMIND_INFER_ENDPOINT,
  comply,
} from '../index';
import { classifyDualLayer } from '../classifier/dual-layer';
import { RegistryIntelligenceCache } from '../registry';
import {
  generateTestKeyPair,
  makeVerifyOptions,
  signGuardResult,
} from '../arp/__tests__/test-helpers';

const ROOT = join(__dirname, '..', '..');
const SSN_TEXT = 'My SSN is 123-45-6789.';
const BENIGN_TEXT = 'The weather is nice today.';

interface RecordedRequest {
  method: string | undefined;
  url: string | undefined;
  body: unknown;
}

interface RecordingDaemon {
  baseUrl: string;
  requests: RecordedRequest[];
  close: () => Promise<void>;
}

/**
 * A stand-in daemon that records every request and flags every input as a
 * prompt injection above the block threshold, so a consulted Guard is visible
 * in the verdict as well as in the request log.
 */
function startRecordingDaemon(): Promise<RecordingDaemon> {
  return new Promise((resolve, reject) => {
    const sockets = new Set<Socket>();
    const requests: RecordedRequest[] = [];
    const server = createServer((req, res) => {
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (c: string) => { raw += c; });
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, body: JSON.parse(raw) });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            intent: 'INTENT_CHECK',
            result: '',
            confidence: 0.99,
            attackClass: 'prompt_injection',
            latencyMs: 1,
            modelVersion: 'nanomind-security-classifier@0.5.0',
          }),
        );
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
        requests,
        close: () =>
          new Promise((done) => {
            for (const s of sockets) s.destroy();
            sockets.clear();
            server.close(() => done());
          }),
      });
    });
  });
}

describe('comply() Guard request', () => {
  const originalUrl = process.env.MOCK_NANOMIND_URL;
  let daemon: RecordingDaemon;
  let fetchSpy: jest.SpyInstance;

  beforeEach(async () => {
    daemon = await startRecordingDaemon();
    process.env.MOCK_NANOMIND_URL = daemon.baseUrl;
    // Passes through to the real fetch; counts every request to any address.
    fetchSpy = jest.spyOn(globalThis, 'fetch');
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    if (originalUrl === undefined) delete process.env.MOCK_NANOMIND_URL;
    else process.env.MOCK_NANOMIND_URL = originalUrl;
    await daemon.close();
  });

  it('by default POSTs the content verbatim to the infer endpoint, once per input', async () => {
    const r = await comply(SSN_TEXT);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(daemon.requests).toEqual([
      {
        method: 'POST',
        url: NANOMIND_INFER_ENDPOINT,
        body: { intent: 'INTENT_CHECK', input: SSN_TEXT },
      },
    ]);
    expect(r.layers).toEqual(['normalize', 'regex', 'guard']);
  });

  it('makes no request when useGuard is false, and still reports the regex finding', async () => {
    const r = await comply({ content: SSN_TEXT, useGuard: false });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(daemon.requests).toEqual([]);
    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations.map((v) => v.type)).toEqual(['SSN']);
    expect('guard' in r.classifierResults).toBe(false);
    expect(r.layers).toEqual(['normalize', 'regex']);
  });

  it('classifies with the regex layer alone when useGuard is false', async () => {
    const consulted = await comply({ content: BENIGN_TEXT });
    expect(consulted.verdict).toBe('VIOLATION');
    expect(consulted.violations.map((v) => v.classifier)).toEqual(['guard']);

    const skipped = await comply({ content: BENIGN_TEXT, useGuard: false });
    expect(skipped.verdict).toBe('CLEAN');
    expect(skipped.violations).toEqual([]);
    expect(daemon.requests).toHaveLength(1);
  });

  it('attempts the Guard when useGuard is true', async () => {
    const r = await comply({ content: BENIGN_TEXT, useGuard: true });
    expect(daemon.requests).toHaveLength(1);
    expect(r.layers).toEqual(['normalize', 'regex', 'guard']);
  });

  it('takes useGuard: false as the second argument and on classifyDualLayer', async () => {
    await comply(SSN_TEXT, { useGuard: false });
    await comply({ content: SSN_TEXT }, { useGuard: false });
    await classifyDualLayer(SSN_TEXT, { useGuard: false });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(daemon.requests).toEqual([]);
  });

  it('lets useGuard on the first argument win over the second', async () => {
    await comply({ content: SSN_TEXT, useGuard: false }, { useGuard: true });
    expect(daemon.requests).toEqual([]);

    await comply({ content: SSN_TEXT, useGuard: true }, { useGuard: false });
    expect(daemon.requests).toHaveLength(1);
  });

  it('makes no request from ClassificationSession.comply() when useGuard is false', async () => {
    jest.spyOn(RegistryIntelligenceCache.prototype, 'warm').mockResolvedValue(undefined);
    const session = await ClassificationSession.create();

    for (let i = 0; i < 6; i++) {
      await session.comply({ content: SSN_TEXT, useGuard: false });
    }
    expect(fetchSpy).not.toHaveBeenCalled();

    await session.comply({ content: SSN_TEXT });
    expect(daemon.requests).toHaveLength(1);
  });

  it('still rejects a supplied Guard result with a bad signature when useGuard is false', async () => {
    const r = await comply(
      { content: BENIGN_TEXT, useGuard: false },
      {
        guardResult: signGuardResult(generateTestKeyPair(), 'documentation', BENIGN_TEXT),
        guardVerifyOptions: makeVerifyOptions(generateTestKeyPair()),
      },
    );

    expect(r.verdict).toBe('DENY');
    expect(r.signatureValid).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  }, 30000);

  it('rejects a useGuard that is not a boolean without making a request', async () => {
    const notBoolean = (v: unknown) => v as boolean;

    await expect(comply({ content: SSN_TEXT, useGuard: notBoolean('false') })).rejects.toThrow(
      new TypeError('comply: useGuard must be a boolean (got string)'),
    );
    await expect(comply({ content: '', useGuard: notBoolean(0) })).rejects.toThrow(
      new TypeError('comply: useGuard must be a boolean (got number)'),
    );
    await expect(comply({ content: SSN_TEXT, useGuard: notBoolean(null) })).rejects.toThrow(
      new TypeError('comply: useGuard must be a boolean (got object)'),
    );
    await expect(comply(SSN_TEXT, { useGuard: notBoolean('false') })).rejects.toThrow(
      new TypeError('comply: useGuard must be a boolean (got string)'),
    );
    await expect(classifyDualLayer(SSN_TEXT, { useGuard: notBoolean('false') })).rejects.toThrow(
      new TypeError('classifyDualLayer: options.useGuard must be a boolean (got string)'),
    );

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(daemon.requests).toEqual([]);
  });
});

describe('docs on the Guard request', () => {
  const INFER_URL = `${DEFAULT_NANOMIND_DAEMON_URL}${NANOMIND_INFER_ENDPOINT}`;
  const DOCS = ['README.md', 'SECURITY.md'].map((file) => ({
    file,
    text: readFileSync(join(ROOT, file), 'utf8'),
  }));

  /** `file:line` for each place `re` matches in the two documents. */
  function occurrences(re: RegExp): string[] {
    return DOCS.flatMap(({ file, text }) =>
      [...text.matchAll(re)].map((m) => `${file}:${text.slice(0, m.index).split('\n').length}`),
    );
  }

  it.each(DOCS)('$file names the infer URL the content is posted to and the switch that skips it', ({ text }) => {
    expect(text).toContain(INFER_URL);
    expect(text).toContain('useGuard: false');
    expect(text).toMatch(/\bverbatim\b/);
  });

  it('carries no claim that comply() makes no request or transmits no content', () => {
    expect(occurrences(/\bno\s+external\s+calls\b/gi)).toEqual([]);
    expect(occurrences(/\bdo\s+no\s+network\s+I\/O\b/gi)).toEqual([]);
    expect(occurrences(/\bNo\s+PII\s+content\s+is\s+transmitted\b/gi)).toEqual([]);
  });

  it('scopes contract AC-005 to Registry network I/O', () => {
    const security = DOCS.find((d) => d.file === 'SECURITY.md')!.text;
    const row = security.split('\n').find((l) => /^\|\s*AC-005\s*\|/.test(l));
    expect(row).toBeDefined();
    expect(row).toMatch(/\|\s*No Registry network I\/O in the classification hot path\b/);
    expect(row).not.toMatch(/\|\s*No network I\/O\b/);
  });
});
