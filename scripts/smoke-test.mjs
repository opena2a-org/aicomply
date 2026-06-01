#!/usr/bin/env node
// Smoke test: pack the package, install it into a clean temp dir, and exercise
// the public API as a real consumer would. Catches packaging bugs (missing
// files in dist/, broken exports, missing runtime deps) that unit tests can't.
//
// Network endpoints (Registry L2) are intentionally skipped - those require
// ClassificationSession.create() / warmRegistryCache() which hit api.oa2a.org.
// The smoke gate is "does the artifact install and classify offline-safe
// content correctly," not "is the Registry up."
//
// Run: npm run smoke-test
// CI:  invoked from .github/workflows/release.yml between `npm test` and tag.

import { execSync } from 'node:child_process';
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(__dirname, '..');

function run(cmd, opts = {}) {
  console.log(`  $ ${cmd}`);
  return execSync(cmd, { stdio: 'pipe', encoding: 'utf8', ...opts });
}

let tmpDir;
let tarballPath;
let exitCode = 0;

try {
  console.log('[1/5] Building tarball ...');
  const packOutput = run('npm pack --json', { cwd: pkgRoot });
  const packInfo = JSON.parse(packOutput);
  const tarballName = packInfo[0].filename;
  tarballPath = resolve(pkgRoot, tarballName);
  console.log(`      ${tarballName} (${packInfo[0].size} bytes, ${packInfo[0].entryCount} entries)`);

  console.log('[2/5] Verifying tarball contents ...');
  const required = [
    'package/dist/index.js',
    'package/dist/index.d.ts',
    'package/README.md',
    'package/LICENSE',
    'package/SECURITY.md',
    'package/package.json',
  ];
  const tarList = run(`tar -tzf "${tarballPath}"`).split('\n');
  const missing = required.filter((f) => !tarList.includes(f));
  if (missing.length > 0) {
    throw new Error(`tarball missing required files: ${missing.join(', ')}`);
  }
  console.log(`      ${required.length} required files present`);

  console.log('[3/5] Creating clean consumer dir ...');
  tmpDir = mkdtempSync(join(tmpdir(), 'aicomply-smoke-'));
  writeFileSync(
    join(tmpDir, 'package.json'),
    JSON.stringify(
      { name: 'aicomply-smoke-consumer', version: '1.0.0', type: 'module', private: true },
      null,
      2,
    ),
  );
  console.log(`      ${tmpDir}`);

  console.log('[4/5] Installing tarball ...');
  run(`npm install --no-save --no-audit --no-fund "${tarballPath}"`, { cwd: tmpDir });

  console.log('[5/5] Exercising public API ...');
  const consumerScript = `
    import {
      comply,
      classifyWithRegex,
      ClassificationSession,
      warmRegistryCache,
    } from '@opena2a/aicomply';

    function fail(msg) { console.error('  SMOKE FAIL: ' + msg); process.exit(1); }

    // ─── Export surface ───────────────────────────────────────────────
    if (typeof comply !== 'function') fail('comply not exported as function');
    if (typeof classifyWithRegex !== 'function') fail('classifyWithRegex not exported');
    if (typeof ClassificationSession?.create !== 'function') fail('ClassificationSession.create not exported');
    if (typeof warmRegistryCache !== 'function') fail('warmRegistryCache not exported');
    console.log('      public exports OK (comply, classifyWithRegex, ClassificationSession, warmRegistryCache)');

    // ─── Real classification: SSN must violate ────────────────────────
    const piiResult = await comply({ content: 'Please update my SSN to 123-45-6789 in the system.' });
    if (piiResult.verdict !== 'VIOLATION') fail('expected VIOLATION on SSN content, got ' + piiResult.verdict);
    if (!Array.isArray(piiResult.violations) || piiResult.violations.length === 0) {
      fail('expected non-empty violations array on SSN content');
    }
    const hasSSN = piiResult.violations.some((v) => v.type === 'SSN' || v.type === 'ssn');
    if (!hasSSN) fail('expected at least one SSN violation, got types: ' + piiResult.violations.map((v) => v.type).join(', '));
    console.log('      SSN content → VIOLATION (' + piiResult.violations.length + ' violations) OK');

    // ─── Real classification: benign must clean ───────────────────────
    const cleanResult = await comply({ content: 'The agent fetched the weather for Toronto and reported it back.' });
    if (cleanResult.verdict !== 'CLEAN') fail('expected CLEAN on benign content, got ' + cleanResult.verdict);
    if (cleanResult.violations.length !== 0) fail('expected zero violations on benign content, got ' + cleanResult.violations.length);
    console.log('      benign content → CLEAN OK');

    // ─── Empty content edge case ──────────────────────────────────────
    const emptyResult = await comply({ content: '' });
    if (emptyResult.verdict !== 'CLEAN') fail('expected CLEAN on empty content, got ' + emptyResult.verdict);
    console.log('      empty content → CLEAN OK');

    // ─── Direct regex layer ───────────────────────────────────────────
    const regexResult = classifyWithRegex('My card is 4532015112830366 (Visa test).');
    if (regexResult.verdict !== 'VIOLATION') fail('expected regex VIOLATION on PAN, got ' + regexResult.verdict);
    console.log('      classifyWithRegex(PAN) → VIOLATION OK');
  `;
  writeFileSync(join(tmpDir, 'smoke.mjs'), consumerScript);
  const result = run('node smoke.mjs', { cwd: tmpDir });
  process.stdout.write(result);

  console.log('\n✓ SMOKE TEST PASSED');
} catch (err) {
  console.error('\n✗ SMOKE TEST FAILED');
  console.error('  ' + (err.message || err));
  if (err.stdout) console.error('  stdout: ' + err.stdout.toString().trim().replace(/\n/g, '\n  '));
  if (err.stderr) console.error('  stderr: ' + err.stderr.toString().trim().replace(/\n/g, '\n  '));
  exitCode = 1;
} finally {
  if (tarballPath && existsSync(tarballPath)) {
    rmSync(tarballPath, { force: true });
  }
  if (tmpDir && existsSync(tmpDir)) {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

process.exit(exitCode);
