#!/usr/bin/env node
// ML-DSA-44 VERIFY p99 microbenchmark (AIComply AC-016).
//
// AIComply's production crypto path only VERIFIES — the sign happens upstream
// in hackmyagent/src/arp/. This bench measures the verify budget (D17: p99
// < 1.5ms).
//
// For the sign budget, see hackmyagent/scripts/bench-ml-dsa-44.mjs.

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { performance } from 'node:perf_hooks';
import os from 'node:os';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, v] = a.replace(/^--/, '').split('=');
    return [k, v ?? true];
  }),
);

const ITERS = Number(args.iters ?? 1000);
const WARMUP = Number(args.warmup ?? 100);
const PAYLOAD = new TextEncoder().encode(
  'nanomind-guard classification benchmark payload',
);
const VERIFY_P99_BUDGET_MS = 1.5;

function percentile(samples, p) {
  const sorted = [...samples].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[idx];
}

function bench(name, fn) {
  for (let i = 0; i < WARMUP; i++) fn();
  const samples = new Array(ITERS);
  for (let i = 0; i < ITERS; i++) {
    const t = performance.now();
    fn();
    samples[i] = performance.now() - t;
  }
  return {
    op: name,
    p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95),
    p99: percentile(samples, 0.99),
    max: Math.max(...samples),
    iters: ITERS,
  };
}

const here = dirname(fileURLToPath(import.meta.url));
const noblePkg = JSON.parse(
  readFileSync(join(here, '..', 'node_modules', '@noble', 'post-quantum', 'package.json'), 'utf8'),
);

const keys = ml_dsa44.keygen();
// noble 0.6.x API: sign(msg, key), verify(sig, msg, pk).
const sig = ml_dsa44.sign(PAYLOAD, keys.secretKey);

const verifyResult = bench('ml-dsa-44-verify', () =>
  ml_dsa44.verify(sig, PAYLOAD, keys.publicKey),
);

const env = {
  platform: `${os.platform()}/${os.arch()}`,
  cpu: os.cpus()[0]?.model ?? 'unknown',
  cpuCount: os.cpus().length,
  node: process.version,
  totalMemGB: Math.round(os.totalmem() / 1024 / 1024 / 1024),
  nobleVersion: noblePkg.version,
  loadAvg: os.loadavg(),
};

console.log(`env: ${env.platform} ${env.cpu} (${env.cpuCount} CPU) node=${env.node} noble=${env.nobleVersion}`);
console.log(`load avg: ${env.loadAvg.map((n) => n.toFixed(2)).join(', ')}`);
console.log(
  `${verifyResult.op.padEnd(18)} p50=${verifyResult.p50.toFixed(3)}ms p95=${verifyResult.p95.toFixed(3)}ms p99=${verifyResult.p99.toFixed(3)}ms max=${verifyResult.max.toFixed(3)}ms`,
);

const verifyOver = verifyResult.p99 > VERIFY_P99_BUDGET_MS;
console.log(`budget: verify p99 ${verifyOver ? 'OVER' : 'under'} ${VERIFY_P99_BUDGET_MS}ms`);

const summary = { env, budget: { verify: VERIFY_P99_BUDGET_MS }, verify: verifyResult, verifyOver };
console.log(`__BENCH_JSON__${JSON.stringify(summary)}`);

if (verifyOver && process.env.BENCH_FAIL_ON_OVER === '1') {
  process.exit(1);
}
