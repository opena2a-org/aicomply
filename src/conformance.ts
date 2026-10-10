/**
 * Pattern pack conformance: per-case exact equality across runtimes.
 *
 * Each case in `pack/conformance/*.jsonl` carries an input text and the exact
 * regex-layer outcome every runtime must produce for it: the verdict and every
 * violation's type, masked value, offsets, confidence and view. Aggregate
 * precision and recall can stay inside tolerance while individual inputs
 * diverge between runtimes; this suite fails on the first divergent case.
 *
 * The outcome is the deterministic layer only (normalization plus the regex
 * scan over every content view). The semantic Guard is never consulted, so a
 * locally running daemon cannot change a result.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { normalize } from './normalize';
import { scanAllViews } from './classifier/dual-layer';
import { PACK_SHA256, PACK_VERSION } from './classifier/regex/pack';
import type { Verdict } from './types';

export interface ConformanceViolation {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
  view: string | null;
  originalStart: number | null;
  originalEnd: number | null;
}

export interface ConformanceOutcome {
  verdict: Verdict;
  violations: ConformanceViolation[];
}

export interface ConformanceCase {
  id: string;
  text: string;
  expected: ConformanceOutcome;
  /** Where the case came from, e.g. `bench/corpus/ssn.jsonl:12` or an issue. */
  origin?: string;
  /**
   * Set on every corpus-seeded case: names the token-shaped text as FAKE
   * generator output so a credential scan over the file can tell it from a
   * leak. Not compared; `scripts/conformance.mjs --seed` writes it.
   */
  fixture?: string;
  note?: string;
}

export interface ConformanceFailure {
  id: string;
  expected: ConformanceOutcome;
  actual: ConformanceOutcome;
}

/** The record CI writes per runtime and the release workflows read. */
export interface ConformanceRecord {
  runtime: string;
  /** Version of this runtime's package (package.json `version`). */
  runtimeVersion: string;
  packVersion: string;
  packSha256: string;
  cases: number;
  passed: number;
  failures: ConformanceFailure[];
}

/** The deterministic outcome for one input, in the shape cases are stored in. */
export function conformanceOutcome(text: string): ConformanceOutcome {
  const result = scanAllViews(normalize(text));
  return {
    verdict: result.verdict,
    violations: result.violations.map((v) => ({
      type: v.type,
      value: v.value,
      start: v.start,
      end: v.end,
      confidence: v.confidence,
      view: v.view ?? null,
      originalStart: v.originalStart ?? null,
      originalEnd: v.originalEnd ?? null,
    })),
  };
}

/** Read every `*.jsonl` case file in `dir`, in file-name order. */
export function loadConformanceCases(dir: string): ConformanceCase[] {
  const cases: ConformanceCase[] = [];
  const ids = new Set<string>();
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.jsonl')).sort()) {
    const lines = readFileSync(join(dir, file), 'utf8').split('\n');
    lines.forEach((line, index) => {
      if (line.trim() === '') return;
      const c = JSON.parse(line) as ConformanceCase;
      if (typeof c.id !== 'string' || typeof c.text !== 'string' || c.expected === undefined) {
        throw new Error(`${file}:${index + 1}: a case needs id, text and expected`);
      }
      if (ids.has(c.id)) throw new Error(`${file}:${index + 1}: duplicate case id ${c.id}`);
      ids.add(c.id);
      cases.push(c);
    });
  }
  return cases;
}

function sameOutcome(a: ConformanceOutcome, b: ConformanceOutcome): boolean {
  if (a.verdict !== b.verdict || a.violations.length !== b.violations.length) return false;
  return a.violations.every((v, i) => {
    const w = b.violations[i];
    return (
      v.type === w.type &&
      v.value === w.value &&
      v.start === w.start &&
      v.end === w.end &&
      v.confidence === w.confidence &&
      v.view === w.view &&
      v.originalStart === w.originalStart &&
      v.originalEnd === w.originalEnd
    );
  });
}

/**
 * The package version. From `src/` (tests) and from `dist/` (the published
 * package) one level up is the package root, which carries package.json.
 */
function packageVersion(): string {
  const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as {
    version?: unknown;
  };
  if (typeof pkg.version !== 'string' || pkg.version === '') {
    throw new Error('conformance: package.json has no version');
  }
  return pkg.version;
}

/** Run every case in `dir` against this runtime and build its record. */
export function runConformance(dir: string): ConformanceRecord {
  const cases = loadConformanceCases(dir);
  const failures: ConformanceFailure[] = [];
  for (const c of cases) {
    const actual = conformanceOutcome(c.text);
    if (!sameOutcome(c.expected, actual)) {
      failures.push({ id: c.id, expected: c.expected, actual });
    }
  }
  return {
    runtime: 'typescript',
    runtimeVersion: packageVersion(),
    packVersion: PACK_VERSION,
    packSha256: PACK_SHA256,
    cases: cases.length,
    passed: cases.length - failures.length,
    failures,
  };
}
