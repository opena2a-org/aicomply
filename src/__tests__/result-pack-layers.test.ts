/**
 * Every comply() result names the pattern pack the regex layer ran
 * (`pack: { version, sha256 }`) and the layers that ran on the content
 * (`layers`, in order, drawn from normalize, regex and guard).
 *
 * `guard` is listed only when a Guard classification was accepted into the
 * result: the daemon answered, or a supplied Guard result passed signature
 * verification. A regex-only fallback or a rejected signature must not claim
 * the Guard layer ran.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { comply, PACK_SHA256, PACK_VERSION } from '../index';
import { classifyDualLayer } from '../classifier/dual-layer';
import {
  generateTestKeyPair,
  makeVerifyOptions,
  signGuardResult,
  type TestKeyPair,
} from '../arp/__tests__/test-helpers';

const PACK_BYTES = readFileSync(join(__dirname, '..', '..', 'pack', 'patterns.json'));
const FILE_SHA256 = createHash('sha256').update(PACK_BYTES).digest('hex');
const FILE_VERSION = (JSON.parse(PACK_BYTES.toString('utf8')) as { packVersion: string }).packVersion;

function startCleanDaemon(): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const sockets = new Set<import('node:net').Socket>();
    const server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            intent: 'INTENT_CHECK',
            result: '',
            confidence: 0.99,
            attackClass: '',
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
        close: () =>
          new Promise((done) => {
            for (const s of sockets) s.destroy();
            server.close(() => done());
          }),
      });
    });
  });
}

describe('ComplyResult.pack', () => {
  it('names the embedded pack by its packVersion and the SHA-256 of its bytes', async () => {
    const r = await comply('SSN 516-81-3086');
    expect(r.pack).toEqual({ version: PACK_VERSION, sha256: PACK_SHA256 });
    expect(r.pack).toEqual({ version: FILE_VERSION, sha256: FILE_SHA256 });
  });

  it('is set on a CLEAN result and on the empty-content short-circuit', async () => {
    expect((await comply('nothing to see here')).pack?.sha256).toBe(FILE_SHA256);
    expect((await comply('')).pack?.sha256).toBe(FILE_SHA256);
  });

  it('is a fresh object per result, so mutating one result cannot rewrite another', async () => {
    const a = await comply('first');
    a.pack!.sha256 = 'tampered';
    const b = await comply('second');
    expect(b.pack?.sha256).toBe(FILE_SHA256);
  });

  it('survives a policy-pack DENY, where the raw content fields are dropped', async () => {
    const r = await classifyDualLayer('SSN 516-81-3086', {
      policyPack: {
        name: 'deny-ssn',
        version: '1.0.0',
        rules: [
          {
            id: 'no-ssn',
            name: 'No SSN',
            description: 'Block any SSN',
            patterns: ['SSN'],
            action: 'DENY',
            severity: 'critical',
          },
        ],
      },
    });
    expect(r.verdict).toBe('DENY');
    expect(r.originalContent).toBeUndefined();
    expect(r.pack).toEqual({ version: FILE_VERSION, sha256: FILE_SHA256 });
    expect(r.layers).toEqual(['normalize', 'regex']);
  });
});

describe('ComplyResult.layers', () => {
  it('is normalize then regex on the regex-only fallback (daemon unreachable)', async () => {
    const r = await comply('SSN 516-81-3086');
    expect(r.classifierResults.guard).toBeUndefined();
    expect(r.layers).toEqual(['normalize', 'regex']);
  });

  it('is empty when there was no content to run any layer on', async () => {
    expect((await comply('')).layers).toEqual([]);
    expect((await comply({ content: '' })).layers).toEqual([]);
  });

  it('adds guard when the daemon answered', async () => {
    const original = process.env.MOCK_NANOMIND_URL;
    const daemon = await startCleanDaemon();
    process.env.MOCK_NANOMIND_URL = daemon.baseUrl;
    try {
      const r = await comply('hello world');
      expect(r.classifierResults.guard).toBeDefined();
      expect(r.layers).toEqual(['normalize', 'regex', 'guard']);
    } finally {
      if (original === undefined) delete process.env.MOCK_NANOMIND_URL;
      else process.env.MOCK_NANOMIND_URL = original;
      await daemon.close();
    }
  });

  describe('with a supplied Guard result', () => {
    let keys: TestKeyPair;

    beforeAll(() => {
      keys = generateTestKeyPair();
    }, 30000);

    it('adds guard when the signature verifies', async () => {
      const content = 'This is safe documentation text.';
      const r = await classifyDualLayer(content, {
        guardResult: signGuardResult(keys, 'documentation', content),
        guardVerifyOptions: makeVerifyOptions(keys),
      });
      expect(r.signatureValid).toBe(true);
      expect(r.layers).toEqual(['normalize', 'regex', 'guard']);
    });

    it('omits guard when the signature is rejected (parse-to-deny)', async () => {
      const content = 'This is safe text.';
      const r = await classifyDualLayer(content, {
        guardResult: signGuardResult(generateTestKeyPair(), 'documentation', content),
        guardVerifyOptions: makeVerifyOptions(keys),
      });
      expect(r.verdict).toBe('DENY');
      expect(r.signatureValid).toBe(false);
      expect(r.layers).toEqual(['normalize', 'regex']);
      expect(r.pack).toEqual({ version: FILE_VERSION, sha256: FILE_SHA256 });
    }, 30000);
  });
});
