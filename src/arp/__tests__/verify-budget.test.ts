/**
 * D17: ML-DSA-44 verify p99 budget. scripts/bench-ml-dsa-44.mjs measures the
 * verify p99 and exits non-zero over budget when BENCH_FAIL_ON_OVER=1, so the
 * budget it enforces must be the one SECURITY.md states. A timed run here
 * would depend on machine load; this test pins the number and the bench
 * measures against it.
 */

import { readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..', '..');

describe('D17: ML-DSA-44 verify p99 budget', () => {
  it('the bench enforces the budget SECURITY.md states', () => {
    const bench = readFileSync(join(ROOT, 'scripts', 'bench-ml-dsa-44.mjs'), 'utf8');
    const security = readFileSync(join(ROOT, 'SECURITY.md'), 'utf8');
    const enforced = bench.match(/^const VERIFY_P99_BUDGET_MS = ([\d.]+);$/m)?.[1];
    const stated = security.match(/^\|\s*D17\s*\|[^|\n]*<\s*([\d.]+)\s*ms\s*\|/m)?.[1];
    expect(enforced).toBeDefined();
    expect(stated).toBeDefined();
    expect(Number(enforced)).toBe(Number(stated));
  });
});
