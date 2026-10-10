import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { conformanceOutcome, loadConformanceCases, runConformance } from '../conformance';
import type { ConformanceCase } from '../conformance';
import { PACK_SHA256, PACK_VERSION } from '../classifier/regex/pack';

const ROOT = join(__dirname, '..', '..');
const CASES_DIR = join(ROOT, 'pack', 'conformance');
const PACKAGE_VERSION = (
  JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string }
).version;

/**
 * Every corpus-seeded case under `root` that no longer matches what
 * `scripts/conformance.mjs --seed` would write for it: a file not named
 * `<class>-cases.jsonl` after its corpus file, or text that differs from the
 * corpus record its `origin` names. Line numbers count non-empty lines, as the
 * seed script does.
 */
function seedDrift(root: string): string[] {
  const casesDir = join(root, 'pack', 'conformance');
  const corpus = new Map<string, string[]>();
  const drift: string[] = [];
  for (const file of readdirSync(casesDir).filter((f) => f.endsWith('.jsonl')).sort()) {
    for (const line of readFileSync(join(casesDir, file), 'utf8').split('\n')) {
      if (line.trim() === '') continue;
      const c = JSON.parse(line) as ConformanceCase;
      if (!c.origin?.startsWith('bench/corpus/')) continue;
      const m = /^bench\/corpus\/([^/:]+)\.jsonl:(\d+)$/.exec(c.origin);
      if (m === null) {
        drift.push(`${c.id}: origin ${c.origin} does not name a corpus line`);
        continue;
      }
      const [, klass, lineNumber] = m;
      if (file !== `${klass}-cases.jsonl`) drift.push(`${c.id}: in ${file}, not ${klass}-cases.jsonl`);
      if (!corpus.has(klass)) {
        const lines = readFileSync(join(root, 'bench', 'corpus', `${klass}.jsonl`), 'utf8').split('\n');
        corpus.set(klass, lines.filter((l) => l.length > 0));
      }
      const record = corpus.get(klass)?.[Number(lineNumber) - 1];
      if (record === undefined || (JSON.parse(record) as { text: unknown }).text !== c.text) {
        drift.push(`${c.id}: text differs from ${c.origin}`);
      }
    }
  }
  return drift;
}

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

  it('marks every corpus-seeded case as FAKE fixture text', () => {
    // The seeded text carries token-shaped strings; the marker on the same
    // line is what lets a credential scan over the file pass them.
    const seeded = loadConformanceCases(CASES_DIR).filter((c) => c.origin?.startsWith('bench/corpus/'));
    expect(seeded).toHaveLength(3200);
    expect(seeded.filter((c) => !/FAKE/.test(c.fixture ?? ''))).toEqual([]);
  });

  it('holds each corpus class in <class>-cases.jsonl with the text of the corpus line it names', () => {
    // The suffix keeps every class clear of secret-file name rules (a bare
    // `credential.jsonl` or `secrets.jsonl` is refused on sight). The text
    // check fails a corpus regeneration that was not followed by a re-seed,
    // which would otherwise keep passing on the old text.
    expect(seedDrift(ROOT)).toEqual([]);
    const corpusClasses = readdirSync(join(ROOT, 'bench', 'corpus'))
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => f.replace(/\.jsonl$/, ''));
    const caseFiles = readdirSync(CASES_DIR);
    expect(corpusClasses.filter((k) => !caseFiles.includes(`${k}-cases.jsonl`))).toEqual([]);
  });

  it('reports a seeded case filed under its corpus name or holding stale text', () => {
    const root = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      mkdirSync(join(root, 'bench', 'corpus'), { recursive: true });
      mkdirSync(join(root, 'pack', 'conformance'), { recursive: true });
      writeFileSync(join(root, 'bench', 'corpus', 'secrets.jsonl'), '{"text":"regenerated"}\n{"text":"kept"}\n');
      const expected = { verdict: 'CLEAN', violations: [] };
      const stale = { id: 'secrets-0001', origin: 'bench/corpus/secrets.jsonl:1', text: 'old', expected };
      const kept = { id: 'secrets-0002', origin: 'bench/corpus/secrets.jsonl:2', text: 'kept', expected };
      writeFileSync(join(root, 'pack', 'conformance', 'secrets.jsonl'), `${JSON.stringify(stale)}\n${JSON.stringify(kept)}\n`);
      expect(seedDrift(root)).toEqual([
        'secrets-0001: in secrets.jsonl, not secrets-cases.jsonl',
        'secrets-0001: text differs from bench/corpus/secrets.jsonl:1',
        'secrets-0002: in secrets.jsonl, not secrets-cases.jsonl',
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
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
