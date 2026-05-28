#!/usr/bin/env node
// Accuracy measurement harness: runs comply() against the synthetic corpus
// at bench/corpus/*.jsonl and computes per-class precision, recall, F1, plus
// per-variant breakdowns so we can see how much normalization actually lifts
// recall on adversarial inputs.
//
// Compares against bench/baseline.json. Exits non-zero if any class's recall
// or precision drops by more than REGRESSION_TOLERANCE from the baseline.
// Use `--update-baseline` to write the current measurements back to baseline.json
// (run after intentional pattern improvements).
//
// CI:  invoked from .github/workflows/accuracy.yml on every PR.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = resolve(__dirname, 'corpus');
const BASELINE_PATH = resolve(__dirname, 'baseline.json');

const REGRESSION_TOLERANCE = 0.02; // fail if precision or recall drops > 2 pp

const updateBaseline = process.argv.includes('--update-baseline');

const { comply } = await import('../dist/index.js');

function loadJsonl(path) {
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));
}

function metricsFromCounts(tp, fp, fn) {
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1, tp, fp, fn };
}

async function measureClass(klass, records) {
  // Per-variant counts: tp/fn for positives, fp for negatives.
  const perVariant = {};
  let tpTotal = 0;
  let fnTotal = 0;
  let fpTotal = 0;

  for (const rec of records) {
    const result = await comply({ content: rec.text });
    const detectedTypes = new Set(result.violations.map((v) => v.type));
    const matched = detectedTypes.has(klass);
    const variant = rec.variant ?? 'canonical';
    if (!perVariant[variant]) perVariant[variant] = { tp: 0, fp: 0, fn: 0 };

    if (rec.label === 'positive') {
      if (matched) {
        perVariant[variant].tp += 1;
        tpTotal += 1;
      } else {
        perVariant[variant].fn += 1;
        fnTotal += 1;
      }
    } else {
      if (matched) {
        perVariant[variant].fp += 1;
        fpTotal += 1;
      }
    }
  }

  const aggregate = metricsFromCounts(tpTotal, fpTotal, fnTotal);
  const byVariant = Object.fromEntries(
    Object.entries(perVariant).map(([v, c]) => [
      v,
      { ...c, ...(c.tp + c.fn > 0 ? { recall: c.tp / (c.tp + c.fn) } : {}) },
    ]),
  );

  return { aggregate, byVariant };
}

async function main() {
  const files = readdirSync(CORPUS_DIR).filter((f) => f.endsWith('.jsonl')).sort();
  const measurements = {};

  for (const file of files) {
    const records = loadJsonl(resolve(CORPUS_DIR, file));
    const klass = records[0]?.class;
    if (!klass) continue;
    const result = await measureClass(klass, records);
    measurements[klass] = result;
    const { precision, recall, f1, tp, fp, fn } = result.aggregate;
    console.log(
      `${klass.padEnd(12)} P=${precision.toFixed(3)}  R=${recall.toFixed(3)}  F1=${f1.toFixed(3)}` +
      `  (tp=${tp} fp=${fp} fn=${fn})`,
    );
    for (const [v, c] of Object.entries(result.byVariant)) {
      const r = c.recall;
      if (r !== undefined) console.log(`  ${v.padEnd(14)} recall=${r.toFixed(3)} (tp=${c.tp} fn=${c.fn})`);
      else console.log(`  ${v.padEnd(14)} fp=${c.fp}`);
    }
  }

  if (updateBaseline) {
    const baseline = {};
    for (const [klass, m] of Object.entries(measurements)) {
      const { precision, recall, f1 } = m.aggregate;
      baseline[klass] = {
        precision: Number(precision.toFixed(4)),
        recall: Number(recall.toFixed(4)),
        f1: Number(f1.toFixed(4)),
      };
    }
    writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n', 'utf8');
    console.log(`\nbaseline updated → ${BASELINE_PATH}`);
    return;
  }

  // Compare against baseline.
  let baseline;
  try {
    baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));
  } catch {
    console.log('\nno baseline.json found — run with --update-baseline to create one.');
    process.exit(0);
  }

  const failures = [];
  for (const [klass, m] of Object.entries(measurements)) {
    const b = baseline[klass];
    if (!b) {
      console.log(`\n${klass}: new class, no baseline entry yet`);
      continue;
    }
    const dP = m.aggregate.precision - b.precision;
    const dR = m.aggregate.recall - b.recall;
    if (dP < -REGRESSION_TOLERANCE) {
      failures.push(`${klass}: precision dropped ${(-dP * 100).toFixed(2)}pp (${b.precision.toFixed(3)} → ${m.aggregate.precision.toFixed(3)})`);
    }
    if (dR < -REGRESSION_TOLERANCE) {
      failures.push(`${klass}: recall dropped ${(-dR * 100).toFixed(2)}pp (${b.recall.toFixed(3)} → ${m.aggregate.recall.toFixed(3)})`);
    }
  }

  if (failures.length > 0) {
    console.log('\nREGRESSIONS:');
    for (const f of failures) console.log(`  ${f}`);
    process.exit(1);
  } else {
    console.log('\nno regressions vs baseline.');
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
