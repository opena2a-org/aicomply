/**
 * Pattern pack conformance: per-case exact equality across runtimes.
 *
 * Each case in `pack/conformance/*.jsonl` is one JSON line:
 *
 *   { "id", "input", "expect": { "types", "verdict", "violations"? }, "origin"?, "fixture"?, "note"? }
 *
 * `expect.types` is the sorted list of distinct violation types and
 * `expect.verdict` the verdict; together they are the outcome every runtime
 * must reproduce exactly. A case may also store `expect.violations`, every
 * violation's type, masked value, offsets, confidence and view, and then those
 * must match exactly as well. Aggregate precision and recall can stay inside
 * tolerance while individual inputs diverge between runtimes; this suite fails
 * on the first divergent case.
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
import { packageVersion } from './version';

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

/** What this runtime produced for one input. */
export interface ConformanceOutcome {
  /** Distinct violation types, sorted. */
  types: string[];
  verdict: Verdict;
  violations: ConformanceViolation[];
}

/** What a case requires. `violations`, when present, must match exactly too. */
export interface ConformanceExpect {
  /** Distinct violation types, sorted. */
  types: string[];
  verdict: Verdict;
  violations?: ConformanceViolation[];
}

export interface ConformanceCase {
  id: string;
  input: string;
  expect: ConformanceExpect;
  /** Where the case came from, e.g. `bench/corpus/ssn.jsonl:12` or a pull request. */
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
  expect: ConformanceExpect;
  actual: ConformanceOutcome;
}

/**
 * The record each runtime's conformance runner writes to
 * `conformance/<runtime>.json` (`scripts/conformance.mjs`,
 * `python/bench/conformance.py`).
 */
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

/** Distinct values, sorted. Type names are ASCII, so every runtime's default string order agrees. */
function sortedDistinct(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** The deterministic outcome for one input, in the shape cases are stored in. */
export function conformanceOutcome(input: string): ConformanceOutcome {
  const result = scanAllViews(normalize(input));
  const violations = result.violations.map((v) => ({
    type: v.type,
    value: v.value,
    start: v.start,
    end: v.end,
    confidence: v.confidence,
    view: v.view ?? null,
    originalStart: v.originalStart ?? null,
    originalEnd: v.originalEnd ?? null,
  }));
  return {
    types: sortedDistinct(violations.map((v) => v.type)),
    verdict: result.verdict,
    violations,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Check one parsed line against the case contract; `where` is `file:line`. */
function checkCase(where: string, c: unknown): ConformanceCase {
  if (!isRecord(c) || typeof c.id !== 'string' || typeof c.input !== 'string' || !isRecord(c.expect)) {
    throw new Error(`${where}: a case needs id, input and expect`);
  }
  if (c.origin !== undefined && typeof c.origin !== 'string') {
    throw new Error(`${where}: origin must be a string`);
  }
  const { types, verdict, violations } = c.expect;
  if (!Array.isArray(types) || !types.every((t) => typeof t === 'string')) {
    throw new Error(`${where}: expect.types must be an array of strings`);
  }
  if (!sameList(types, sortedDistinct(types))) {
    throw new Error(`${where}: expect.types must be sorted and distinct`);
  }
  if (typeof verdict !== 'string') throw new Error(`${where}: expect.verdict must be a string`);
  if (violations !== undefined) {
    if (!Array.isArray(violations) || !violations.every(isRecord)) {
      throw new Error(`${where}: expect.violations must be an array of objects`);
    }
    if (!sameList(types, sortedDistinct(violations.map((v) => String(v.type))))) {
      throw new Error(`${where}: expect.types does not match expect.violations`);
    }
  }
  return c as unknown as ConformanceCase;
}

/** Read every `*.jsonl` case file in `dir`, in file-name order. */
export function loadConformanceCases(dir: string): ConformanceCase[] {
  const cases: ConformanceCase[] = [];
  const ids = new Set<string>();
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.jsonl')).sort()) {
    const lines = readFileSync(join(dir, file), 'utf8').split('\n');
    lines.forEach((line, index) => {
      if (line.trim() === '') return;
      const c = checkCase(`${file}:${index + 1}`, JSON.parse(line));
      if (ids.has(c.id)) throw new Error(`${file}:${index + 1}: duplicate case id ${c.id}`);
      ids.add(c.id);
      cases.push(c);
    });
  }
  return cases;
}

function sameOutcome(expect: ConformanceExpect, actual: ConformanceOutcome): boolean {
  if (expect.verdict !== actual.verdict || !sameList(expect.types, actual.types)) return false;
  if (expect.violations === undefined) return true;
  if (expect.violations.length !== actual.violations.length) return false;
  return expect.violations.every((v, i) => {
    const w = actual.violations[i];
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

/** Run every case in `dir` against this runtime and build its record. */
export function runConformance(dir: string): ConformanceRecord {
  const cases = loadConformanceCases(dir);
  const failures: ConformanceFailure[] = [];
  for (const c of cases) {
    const actual = conformanceOutcome(c.input);
    if (!sameOutcome(c.expect, actual)) {
      failures.push({ id: c.id, expect: c.expect, actual });
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
