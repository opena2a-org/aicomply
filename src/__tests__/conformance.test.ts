import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  conformanceOutcome,
  loadConformanceCases,
  runConformance,
  type ConformanceCase,
  type ConformanceRecord,
} from '../conformance';
import { PACK_SHA256, PACK_VERSION } from '../classifier/regex/pack';
import { scanPatterns } from '../classifier/regex/patterns';
import { normalize } from '../normalize';

const ROOT = join(__dirname, '..', '..');
const CASES_DIR = join(ROOT, 'pack', 'conformance');
const PACKAGE_VERSION = (
  JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string }
).version;

/**
 * Whether `c` claims a corpus origin. The seed script writes every origin as a
 * string, so a missing, null or other non-string origin marks a case that was
 * not seeded from the corpus.
 */
function isSeeded(c: ConformanceCase): c is ConformanceCase & { origin: string } {
  return typeof c.origin === 'string' && c.origin.startsWith('bench/corpus/');
}

function seeded(cases: ConformanceCase[]): ConformanceCase[] {
  return cases.filter(isSeeded);
}

/**
 * Every corpus-seeded case under `root` that no longer matches what
 * `scripts/conformance.mjs --seed` would write for it: a file not named
 * `<class>-cases.jsonl` after its corpus file, or an input that differs from
 * the text of the corpus record its `origin` names. Line numbers count
 * non-empty lines, as the seed script does.
 */
function seedDrift(root: string): string[] {
  const casesDir = join(root, 'pack', 'conformance');
  const corpus = new Map<string, string[]>();
  const drift: string[] = [];
  for (const file of readdirSync(casesDir).filter((f) => f.endsWith('.jsonl')).sort()) {
    for (const line of readFileSync(join(casesDir, file), 'utf8').split('\n')) {
      if (line.trim() === '') continue;
      const c = JSON.parse(line) as ConformanceCase;
      if (!isSeeded(c)) continue;
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
      if (record === undefined || (JSON.parse(record) as { text: unknown }).text !== c.input) {
        drift.push(`${c.id}: text differs from ${c.origin}`);
      }
    }
  }
  return drift;
}

/**
 * Every `*.jsonl` case file in `casesDir` named like a credential store: a leaf
 * of `credential`, `secret` or `password` plus extensions (any characters but
 * `.`, so `secrets.v1-old.jsonl` counts), which secret-file
 * name rules refuse on sight whatever the file holds. Checked over every case
 * file, not only the corpus-seeded ones `seedDrift` reads.
 */
/**
 * The masking rule, written here apart from the library's: 8 characters or
 * fewer are fully starred, 9 to 12 read `...` and the last 2, 13 or more `...`
 * and the last 4. No prefix is ever kept.
 */
function maskedValue(raw: string): string {
  if (raw.length <= 8) return '*'.repeat(raw.length);
  return '...' + raw.slice(raw.length <= 12 ? -2 : -4);
}

/**
 * Every stored violation whose `value` is not `maskedValue()` of the value the
 * pattern captured in its case's `start`..`end` slice. The slice is taken from
 * the view the violation names: the normalized input, or a compact or decoded
 * view of it. The capture is read with the unmasked `scanPatterns()`, so the
 * expected value comes from the input and never from the pack itself.
 */
function maskDrift(cases: ConformanceCase[]): string[] {
  const drift: string[] = [];
  for (const c of cases) {
    const norm = normalize(c.input);
    (c.expect.violations ?? []).forEach((v, i) => {
      const texts =
        v.view === 'normalized'
          ? [norm.normalizedContent]
          : norm.decodedExtractions.filter((e) => e.source === v.view).map((e) => e.decoded);
      const wanted = new Set<string>();
      for (const text of texts) {
        const slice = text.slice(v.start, v.end);
        for (const m of scanPatterns(slice)) {
          if (m.type === v.type && m.start === 0 && m.end === slice.length) wanted.add(maskedValue(m.value));
        }
      }
      if (!wanted.has(v.value)) drift.push(`${c.id}[${i}]: ${v.value} not in ${JSON.stringify([...wanted])}`);
    });
  }
  return drift;
}

function storeNamedCaseFiles(casesDir: string): string[] {
  return readdirSync(casesDir)
    .filter((f) => f.endsWith('.jsonl'))
    .filter((f) => /^\.?(credentials?|secrets?|passwords?)(\.[^.]+)*$/i.test(f))
    .sort();
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
    const corpusCases = seeded(loadConformanceCases(CASES_DIR));
    expect(corpusCases).toHaveLength(3200);
    expect(corpusCases.filter((c) => !/FAKE/.test(c.fixture ?? ''))).toEqual([]);
  });

  it('holds each corpus class in <class>-cases.jsonl with the text of the corpus line it names', () => {
    // The suffix keeps every class clear of secret-file name rules (a bare
    // `credential.jsonl` or `secrets.jsonl` is refused on sight). The input
    // check fails a corpus regeneration that was not followed by a re-seed,
    // which would otherwise keep passing on the old text.
    expect(seedDrift(ROOT)).toEqual([]);
    const corpusClasses = readdirSync(join(ROOT, 'bench', 'corpus'))
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => f.replace(/\.jsonl$/, ''));
    const caseFiles = readdirSync(CASES_DIR);
    expect(corpusClasses.filter((k) => !caseFiles.includes(`${k}-cases.jsonl`))).toEqual([]);
  });

  it('stores each value masked from its own slice of the input, with no leading characters', () => {
    const cases = loadConformanceCases(CASES_DIR);
    const violations = cases.flatMap((c) => c.expect.violations ?? []);
    expect(violations).toHaveLength(1627);
    expect(maskDrift(cases)).toEqual([]);
  });

  it('names no case file like a credential store', () => {
    expect(readdirSync(CASES_DIR)).toContain('credential-cases.jsonl');
    expect(storeNamedCaseFiles(CASES_DIR)).toEqual([]);
  });

  it('reports a store-named case file whose cases are not corpus-seeded', () => {
    // seedDrift skips cases without a bench/corpus origin, so a regression
    // case moved into `secrets.jsonl` passes it; the name check still fails.
    const root = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      const casesDir = join(root, 'pack', 'conformance');
      mkdirSync(casesDir, { recursive: true });
      const clean = { types: [], verdict: 'CLEAN', violations: [] };
      const names = ['secrets.jsonl', '.Passwords.jsonl', 'credential-cases.jsonl', 'regressions.jsonl'];
      names.forEach((name, i) => {
        const c = { id: `regression-${i}`, input: 'x', expect: clean, origin: 'pull request #19' };
        writeFileSync(join(casesDir, name), `${JSON.stringify(c)}\n`);
      });
      expect(seedDrift(root)).toEqual([]);
      expect(storeNamedCaseFiles(casesDir)).toEqual(['.Passwords.jsonl', 'secrets.jsonl']);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports a store-named case file whose extension segment holds - or _', () => {
    const root = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      const names = ['secrets.v1-old.jsonl', 'Credentials.old_copy.jsonl', 'credential-cases.jsonl', 'secretsanta.jsonl'];
      for (const name of names) writeFileSync(join(root, name), '');
      expect(storeNamedCaseFiles(root)).toEqual(['Credentials.old_copy.jsonl', 'secrets.v1-old.jsonl']);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports a seeded case filed under its corpus name or holding stale text', () => {
    const root = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      mkdirSync(join(root, 'bench', 'corpus'), { recursive: true });
      mkdirSync(join(root, 'pack', 'conformance'), { recursive: true });
      writeFileSync(join(root, 'bench', 'corpus', 'secrets.jsonl'), '{"text":"regenerated"}\n{"text":"kept"}\n');
      const clean = { types: [], verdict: 'CLEAN', violations: [] };
      const stale = { id: 'secrets-0001', input: 'old', expect: clean, origin: 'bench/corpus/secrets.jsonl:1' };
      const kept = { id: 'secrets-0002', input: 'kept', expect: clean, origin: 'bench/corpus/secrets.jsonl:2' };
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

  it.each([null, 7])('skips a case whose origin is %p, not a string', (origin) => {
    // The case is not corpus-seeded (the seed script writes every origin as a
    // string), so the drift check passes over it as the Python twin does.
    const root = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      mkdirSync(join(root, 'pack', 'conformance'), { recursive: true });
      const c = { id: 'x', input: 't', expect: { types: [], verdict: 'CLEAN', violations: [] }, origin };
      writeFileSync(join(root, 'pack', 'conformance', 'x-cases.jsonl'), `${JSON.stringify(c)}\n`);
      expect(seedDrift(root)).toEqual([]);
      expect(seeded([c as unknown as ConformanceCase])).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('stores every case as id, input and expect with sorted distinct types', () => {
    for (const c of loadConformanceCases(CASES_DIR)) {
      expect(Object.keys(c).slice(0, 3)).toEqual(['id', 'input', 'expect']);
      expect(Object.keys(c.expect)).toEqual(['types', 'verdict', 'violations']);
      expect(c.expect.types).toEqual([...new Set(c.expect.types)].sort());
    }
  });

  it('reports the distinct violation types, sorted', () => {
    const outcome = conformanceOutcome('SSN 123-45-6788 card 4111 1111 1111 1111 and SSN 219-09-9999');
    const found = outcome.violations.map((v) => v.type);
    expect(found).toHaveLength(3);
    // The types first appear out of order, so dropping the sort changes the result.
    expect([...new Set(found)]).not.toEqual(outcome.types);
    expect(outcome.types).toEqual(['PAN', 'SSN']);
  });

  it('fails a case whose stored outcome differs from this runtime', () => {
    // The suite is not vacuous: one wrong field in one case turns it red.
    const input = 'const apiKey = process.env.OPENAI_API_KEY;';
    const outcome = conformanceOutcome('SSN 123-45-6788');
    const result = runCases([
      { id: 'good', input, expect: conformanceOutcome(input) },
      { id: 'bad-types', input: 'SSN 123-45-6788', expect: { types: [], verdict: 'VIOLATION', violations: [] } },
      {
        id: 'bad-offset',
        input: 'SSN 123-45-6788',
        expect: { ...outcome, violations: outcome.violations.map((v) => ({ ...v, start: v.start + 1 })) },
      },
    ]);
    expect(result.cases).toBe(3);
    expect(result.passed).toBe(1);
    expect(result.failures.map((f) => f.id)).toEqual(['bad-types', 'bad-offset']);
    expect(result.failures[0].expect.types).toEqual([]);
  });

  it('runs a case that states only the contract fields, types and verdict', () => {
    const result = runCases([
      { id: 'ssn', input: 'SSN 123-45-6788', expect: { types: ['SSN'], verdict: 'VIOLATION' } },
      { id: 'clean', input: 'nothing here', expect: { types: [], verdict: 'CLEAN' } },
      { id: 'wrong', input: 'SSN 123-45-6788', expect: { types: ['PAN'], verdict: 'VIOLATION' } },
    ]);
    expect(result.cases).toBe(3);
    expect(result.failures.map((f) => f.id)).toEqual(['wrong']);
  });

  it.each([
    ['the superseded text/expected shape', { id: 'old', text: 'x', expected: { verdict: 'CLEAN', violations: [] } }, /needs id, input and expect/],
    ['unsorted types', { id: 'c', input: 'x', expect: { types: ['SSN', 'CREDENTIAL'], verdict: 'VIOLATION' } }, /sorted and distinct/],
    ['repeated types', { id: 'c', input: 'x', expect: { types: ['SSN', 'SSN'], verdict: 'VIOLATION' } }, /sorted and distinct/],
    ['a missing verdict', { id: 'c', input: 'x', expect: { types: [] } }, /expect\.verdict/],
    [
      'types that disagree with the stored violations',
      { id: 'c', input: 'x', expect: { types: ['PAN'], verdict: 'VIOLATION', violations: [{ type: 'SSN' }] } },
      /expect\.types does not match expect\.violations/,
    ],
  ])('refuses a case with %s', (_label, c, message) => {
    expect(() => withCases([c], (dir) => loadConformanceCases(dir))).toThrow(message);
  });

  it('refuses a duplicate case id', () => {
    const c = { id: 'same', input: 'x', expect: { types: [], verdict: 'CLEAN' } };
    expect(() => withCases([c, c], (dir) => loadConformanceCases(dir))).toThrow(/duplicate case id same/);
  });

  it.each([[null], [7], [['bench/corpus/ssn.jsonl:1']]])('refuses a case whose origin is %p, not a string', (origin) => {
    // The drift check passes over such a case, so the loader is where it is reported.
    const dir = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
    try {
      const c = { id: 'x', input: 't', expect: { types: [], verdict: 'CLEAN', violations: [] }, origin };
      writeFileSync(join(dir, 'a.jsonl'), `\n${JSON.stringify(c)}\n`);
      expect(() => loadConformanceCases(dir)).toThrow('a.jsonl:2: origin must be a string');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** Write `cases` to a scratch case directory, run `fn` on it, then remove it. */
function withCases<T>(cases: unknown[], fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'aicomply-conformance-'));
  try {
    writeFileSync(join(dir, 'cases.jsonl'), cases.map((c) => JSON.stringify(c)).join('\n') + '\n');
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runCases(cases: unknown[]): ConformanceRecord {
  return withCases(cases, (dir) => runConformance(dir));
}
