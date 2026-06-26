/**
 * CLI behavior tests. The CLI is the zero-integration try-path; these assert the
 * contract a consumer (or a CI gate) relies on: exit codes, masking, and output
 * shape. Detection accuracy itself is covered by the regex/dual-layer suites.
 */

import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { run } from '../cli';

function capture(): { out: string[]; err: string[]; restore: () => void } {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = jest.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => {
    out.push(String(c));
    return true;
  });
  const errSpy = jest.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => {
    err.push(String(c));
    return true;
  });
  return { out, err, restore: () => { outSpy.mockRestore(); errSpy.mockRestore(); } };
}

let dir: string;
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'aicomply-cli-')); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });
afterEach(() => jest.restoreAllMocks());

function fixture(name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content, 'utf8');
  return p;
}

describe('aicomply CLI', () => {
  it('--version prints version and exits 0', async () => {
    const cap = capture();
    const code = await run(['--version']);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('')).toMatch(/^\d+\.\d+\.\d+/);
  });

  // Drift guard: the hardcoded CLI VERSION must match package.json. A version
  // bump that forgets the constant would otherwise ship a CLI reporting the
  // wrong version (caught at release 2.2.1).
  it('--version matches package.json version', async () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const pkg = require('../../package.json') as { version: string };
    const cap = capture();
    await run(['--version']);
    cap.restore();
    expect(cap.out.join('').trim()).toBe(pkg.version);
  });

  it('--help exits 0 and documents the scan command', async () => {
    const cap = capture();
    const code = await run(['--help']);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('')).toContain('aicomply scan');
  });

  it('scan --help exits 0 and shows scan-specific help, not the generic banner', async () => {
    const cap = capture();
    const code = await run(['scan', '--help']);
    cap.restore();
    expect(code).toBe(0);
    const out = cap.out.join('');
    // The scan help must lead with a scan-scoped synopsis, not the top-level
    // "aicomply -- inline content classifier..." banner.
    expect(out.trimStart().startsWith('aicomply scan')).toBe(true);
    expect(out).toContain('--json');
    expect(out).toContain('--quiet');
    // Scan reads from files or stdin; the scan help must say so.
    expect(out.toLowerCase()).toContain('stdin');
  });

  it('top-level --help leads with the generic banner, not the scan synopsis', async () => {
    const cap = capture();
    await run(['--help']);
    cap.restore();
    const out = cap.out.join('');
    expect(out.trimStart().startsWith('aicomply --')).toBe(true);
  });

  it('no command exits 2 (usage)', async () => {
    const cap = capture();
    const code = await run([]);
    cap.restore();
    expect(code).toBe(2);
  });

  it('unknown command exits 2 with guidance', async () => {
    const cap = capture();
    const code = await run(['frobnicate']);
    cap.restore();
    expect(code).toBe(2);
    expect(cap.err.join('')).toContain("unknown command 'frobnicate'");
  });

  it('missing file exits 2', async () => {
    const cap = capture();
    const code = await run(['scan', join(dir, 'does-not-exist.txt')]);
    cap.restore();
    expect(code).toBe(2);
  });

  it('clean content exits 0', async () => {
    const f = fixture('clean.txt', 'The weather is nice today.');
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('')).toContain('CLEAN');
  });

  it('PII content exits 1 and masks the value (never prints the full secret)', async () => {
    const f = fixture('pii.txt', 'My SSN is 123-45-6789 please update.');
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    const text = cap.out.join('');
    expect(code).toBe(1);
    expect(text).toContain('SSN');
    expect(text).toContain('•'); // masked
    expect(text).not.toContain('123-45-6789'); // full value never leaks
  });

  it('--json emits structured findings with maskedValue', async () => {
    const f = fixture('cred.txt', 'aws key AKIAIOSFODNN7EXAMPLE here');
    const cap = capture();
    const code = await run(['scan', f, '--json']);
    cap.restore();
    expect(code).toBe(1);
    const payload = JSON.parse(cap.out.join(''));
    expect(Array.isArray(payload)).toBe(true);
    expect(payload[0].verdict).toBe('VIOLATION');
    expect(payload[0].findings[0]).toHaveProperty('maskedValue');
    expect(payload[0].findings[0].maskedValue).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('--quiet prints only the verdict word', async () => {
    const f = fixture('pii2.txt', 'SSN 078-05-1120');
    const cap = capture();
    const code = await run(['scan', f, '--quiet']);
    cap.restore();
    expect(code).toBe(1);
    expect(cap.out.join('').trim()).toBe('VIOLATION');
  });

  it('multi-file scan surfaces the worst verdict and exits 1 if any input is dirty', async () => {
    const clean = fixture('a.txt', 'nothing here');
    const dirty = fixture('b.txt', 'card 4111111111111111');
    const cap = capture();
    const code = await run(['scan', clean, dirty, '--quiet']);
    cap.restore();
    expect(code).toBe(1);
    expect(cap.out.join('').trim()).toBe('VIOLATION');
  });
});
