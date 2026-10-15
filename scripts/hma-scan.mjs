#!/usr/bin/env node
// HackMyAgent scan of this repository, run with the HackMyAgent dev dependency.
//
//   node scripts/hma-scan.mjs [<option> ...]   runs `hackmyagent secure --ci .`
//                                             at the repository root, with each
//                                             option appended (for example
//                                             `npm run hma:scan -- --json`)
//
// The rule `package.json:AIM-001` in .hmaignore names one check on one file.
// HackMyAgent reads that `<path>:<check>` form from 0.33.0 on. HackMyAgent
// 0.30.0, 0.31.0 and 0.32.0 read every rule line that does not start with `!`
// as a path, so they take the whole line for a path that names no file, and
// HackMyAgent 0.30.0 still reports AIM-001 on package.json under it.
// A `hackmyagent` found on PATH can be one of those, so this script runs the
// copy installed in node_modules and refuses a missing one, or one older than
// 0.33.0, instead of falling back to another.
//
// Exit 2 when it refuses; otherwise the exit code is the scan's own.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MINIMUM = '0.33.0';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkgDir = join(root, 'node_modules', 'hackmyagent');
const INSTALL_FIX = 'run `npm ci` at the repository root to install the hackmyagent version package-lock.json pins';

function refuse(reason) {
  console.error(`hma-scan: REFUSED ${reason}`);
  console.error(`  fix: ${INSTALL_FIX}`);
  process.exit(2);
}

/** The numeric `major.minor.patch` of a version string, or null. */
function parts(version) {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(version));
  return m ? m.slice(1, 4).map(Number) : null;
}

function atLeast(version, minimum) {
  const a = parts(version);
  const b = parts(minimum);
  if (!a) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

let pkg;
try {
  pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
} catch {
  refuse('no hackmyagent dev dependency is installed in node_modules');
}

if (!atLeast(pkg.version, MINIMUM)) {
  refuse(
    `node_modules/hackmyagent is ${pkg.version ?? 'a package with no version'}; ` +
      `the package.json:AIM-001 rule in .hmaignore is read from ${MINIMUM} on`,
  );
}

const bin = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.hackmyagent;
if (typeof bin !== 'string') {
  refuse(`node_modules/hackmyagent ${pkg.version} declares no hackmyagent executable`);
}

const run = spawnSync(process.execPath, [join(pkgDir, bin), 'secure', '--ci', '.', ...process.argv.slice(2)], {
  cwd: root,
  stdio: 'inherit',
});
if (run.error) {
  console.error(`hma-scan: ${run.error.message}`);
  process.exit(1);
}
process.exit(run.status ?? 1);
