import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { conformanceOutcome, loadConformanceCases, runConformance } from '../conformance';
import { PACK_SHA256, PACK_VERSION } from '../classifier/regex/pack';

const CASES_DIR = join(__dirname, '..', '..', 'pack', 'conformance');
const PACKAGE_VERSION = (
  JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8')) as { version: string }
).version;

describe('pattern pack conformance suite', () => {
  // Per-case exact equality: every stored outcome, not an aggregate rate.
  const record = runConformance(CASES_DIR);

  it('passes every case against the loaded pack', () => {
    expect(record.failures.map((f) => f.id)).toEqual([]);
    expect(record.passed).toBe(record.cases);
  });

  it('records the pack it ran against', () => {
    expect(record.runtime).toBe('typescript');
    expect(record.runtimeVersion).toBe(PACKAGE_VERSION);
    expect(record.packVersion).toBe(PACK_VERSION);
    expect(record.packSha256).toBe(PACK_SHA256);
  });

  it('covers the full corpus plus the regression cases', () => {
    const ids = loadConformanceCases(CASES_DIR).map((c) => c.id);
    expect(ids.length).toBe(record.cases);
    expect(ids.filter((id) => !id.startsWith('regression-') && !id.startsWith('mrn-containsdigit-'))).toHaveLength(3200);
    expect(ids).toEqual(
      expect.arrayContaining([
        'regression-19-process-env',
        'regression-19-bearer-reference',
        'regression-19-control-literal-beside-reference',
        'regression-20-empty-key-next-line',
        'regression-20-env-example-template',
        'regression-20-control-next-line-value',
      ]),
    );
  });

  it('fails a case whose stored outcome differs from this runtime', () => {
    // The suite is not vacuous: one wrong field in one case turns it red.
    const dir = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      const text = 'const apiKey = process.env.OPENAI_API_KEY;';
      const good = { id: 'good', text, expected: conformanceOutcome(text) };
      const bad = {
        id: 'bad',
        text: 'SSN 123-45-6789',
        expected: { verdict: 'VIOLATION', violations: [] },
      };
      writeFileSync(join(dir, 'cases.jsonl'), `${JSON.stringify(good)}\n${JSON.stringify(bad)}\n`);
      const result = runConformance(dir);
      expect(result.cases).toBe(2);
      expect(result.passed).toBe(1);
      expect(result.failures.map((f) => f.id)).toEqual(['bad']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a duplicate case id', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      const c = { id: 'same', text: 'x', expected: { verdict: 'CLEAN', violations: [] } };
      writeFileSync(join(dir, 'a.jsonl'), `${JSON.stringify(c)}\n${JSON.stringify(c)}\n`);
      expect(() => loadConformanceCases(dir)).toThrow(/duplicate case id same/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
