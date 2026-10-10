/**
 * Release gate: `scripts/release-gate.mjs` is the check a publish runs after
 * the conformance suite. It must exit non-zero unless the conformance record
 * was written by this package version, against the pack the package ships,
 * with every case passing. These tests run the script itself, so they pin the
 * exit code a release workflow acts on.
 */

import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runConformance } from '../conformance';

const ROOT = join(__dirname, '..', '..');
const GATE = join(ROOT, 'scripts', 'release-gate.mjs');
const CASES_DIR = join(ROOT, 'pack', 'conformance');

describe('npm release gate', () => {
  // The record exactly as the conformance run writes it for this package.
  const record = runConformance(CASES_DIR);
  let root: string;

  /** A scratch package root carrying this package's package.json and pack. */
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aicomply-gate-'));
    mkdirSync(join(root, 'pack'));
    mkdirSync(join(root, 'conformance'));
    copyFileSync(join(ROOT, 'package.json'), join(root, 'package.json'));
    copyFileSync(join(ROOT, 'pack', 'patterns.json'), join(root, 'pack', 'patterns.json'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function writeRecord(value: unknown): void {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n';
    writeFileSync(join(root, 'conformance', 'typescript.json'), text);
  }

  function gate(args: string[] = ['--root', root]): { status: number | null; output: string } {
    const run = spawnSync(process.execPath, [GATE, ...args], { encoding: 'utf8' });
    return { status: run.status, output: run.stdout + run.stderr };
  }

  it('passes the record the conformance run writes for this package', () => {
    expect(record.cases).toBeGreaterThan(0);
    expect(record.passed).toBe(record.cases);
    writeRecord(record);
    const { status, output } = gate();
    expect(output).toContain('release gate: passed');
    expect(output).not.toContain('REFUSED');
    expect(status).toBe(0);
  });

  it('refuses when the shipped pack is not the pack the record was written against', () => {
    writeRecord(record);
    appendFileSync(join(root, 'pack', 'patterns.json'), '\n');
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain(`REFUSED packSha256: the record was written against pack "${record.packSha256}"`);
    expect(output).toContain('release gate: refused, do not publish');
    expect(output).not.toContain('release gate: passed');
  });

  it('refuses when a case failed', () => {
    writeRecord({ ...record, passed: record.cases - 1 });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain(`REFUSED passed: ${record.cases - 1} of ${record.cases} cases passed`);
    expect(output).toContain('fix: run `npm run conformance`');
  });

  it('refuses a record that ran no cases', () => {
    writeRecord({ ...record, cases: 0, passed: 0 });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED cases: the record ran no cases');
  });

  it("refuses the other runtime's record, which carries the same pack and case count", () => {
    writeRecord({ ...record, runtime: 'python' });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED runtime: the record is for "python", this gate publishes "typescript"');
  });

  it('refuses a record written by another version of the package', () => {
    writeRecord({ ...record, runtimeVersion: '0.0.0' });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain(
      `REFUSED runtimeVersion: the record was written by "0.0.0", this package is "${record.runtimeVersion}"`,
    );
  });

  it('refuses when there is no record', () => {
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED record: conformance/typescript.json does not exist');
    expect(output).toContain('fix: run `npm run conformance`');
  });

  it.each([
    ['text that is not JSON', '{', /REFUSED record: conformance\/typescript\.json is not a JSON object/],
    ['a JSON array', '[]', /REFUSED record: conformance\/typescript\.json is not a JSON object/],
    ['counts stored as strings', { cases: '12', passed: '12' }, /REFUSED cases: the record needs integer cases and passed, got "12" and "12"/],
    ['no passed count', { passed: undefined }, /REFUSED cases: the record needs integer cases and passed, got \d+ and missing/],
    ['more passed than cases', { passed: 1e9 }, /REFUSED passed: 1000000000 of \d+ cases passed/],
    ['no pack hash', { packSha256: undefined }, /REFUSED packSha256: the record was written against pack missing/],
  ])('refuses a record with %s', (_label, change, message) => {
    writeRecord(typeof change === 'string' ? change : { ...record, ...change });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toMatch(message);
    expect(output).not.toContain('release gate: passed');
  });

  it('prints every reason, not only the first', () => {
    writeRecord({ ...record, runtime: 'python', runtimeVersion: '0.0.0', packSha256: 'f'.repeat(64), passed: 0 });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output.split('\n').filter((l) => l.startsWith('REFUSED ')).map((l) => l.split(':')[0])).toEqual([
      'REFUSED runtime',
      'REFUSED runtimeVersion',
      'REFUSED packSha256',
      'REFUSED passed',
    ]);
  });

  it('refuses when the package carries no pack to compare against', () => {
    writeRecord(record);
    rmSync(join(root, 'pack', 'patterns.json'));
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED gate: ');
    expect(output).not.toContain('release gate: passed');
  });

  it('exits 2 on an argument it does not know', () => {
    const { status, output } = gate(['--skip']);
    expect(status).toBe(2);
    expect(output).toContain('usage: node scripts/release-gate.mjs [--root <dir>]');
  });

  it('is the release:gate npm script', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['release:gate']).toBe('node scripts/release-gate.mjs');
  });
});
