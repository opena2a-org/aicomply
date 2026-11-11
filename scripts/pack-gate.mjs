// The pack gate. It lists the files `npm pack` would publish from the package
// in the working directory, reads every one of them, and refuses the pack when
// a line carries an internal attribution, names a vendor as the author of the
// work, or publishes an accuracy figure without its withdrawal notice. The
// three expressions, their guidance and the exemptions are defined in
// scripts/pack-gate-expressions.mjs.
//
// It is the package's `prepack` script, so `npm pack` and `npm publish` both
// run it, on a laptop and in the release job alike, and the release test runs
// the same command with the same arguments. It takes no arguments: the package
// is the working directory, which npm sets to the package root before it runs
// a lifecycle script. It is a command only, and nothing imports it.
//
// The population is the artifact, not the tree: the file list
// `npm pack --dry-run --json` prints for this package. Every listed file is
// read, declaration files and source maps included, since a source map can
// embed the source it maps. A file whose first 8000 bytes carry a NUL byte is
// skipped and listed. The baseline is zero: no count is frozen, and the only
// exemptions are the exact file-and-line entries of EXEMPT.
//
// Exit 0: no hit. Exit 1: refused, each hit named by file, line, expression and
// guidance. Exit 2: the gate could not run, which refuses the pack as well: it
// was given an argument, its expressions did not load (they refuse a runtime
// older than Node 23), or it could not list or read the pack. It prints the
// reason, not a stack trace. Everything it prints goes to standard error,
// because `npm pack --json` copies a lifecycle script's standard output into
// its JSON.
//
// This file is byte-identical in every repository that publishes with it.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const log = (message) => process.stderr.write(`${message}\n`);

// The npm that is running this script when it runs as a lifecycle script, or
// the one on the PATH when it is run by hand.
function npmInvocation() {
  const execpath = process.env.npm_execpath;
  if (execpath && path.basename(execpath) === 'npm-cli.js' && fs.existsSync(execpath)) {
    return { command: process.execPath, prefix: [execpath], shell: false };
  }
  const windows = process.platform === 'win32';
  return { command: windows ? 'npm.cmd' : 'npm', prefix: [], shell: windows };
}

// The paths of the files `npm pack` would publish from `root`, sorted. The
// listing runs with scripts ignored, so it cannot start this script again, and
// without the npm_config_ variables of an npm run that may be calling this
// script, so a workspace, destination or dry-run setting cannot change it.
// Anything other than one package with at least one file is an error.
function listPackFiles(root) {
  const npm = npmInvocation();
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^npm_config_/i.test(key)));
  const run = spawnSync(npm.command, [...npm.prefix, 'pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root,
    env,
    encoding: 'utf8',
    shell: npm.shell,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (run.error) throw new Error(`npm pack --dry-run did not start: ${run.error.message}`);
  if (run.status !== 0) throw new Error(`npm pack --dry-run exited ${run.status}`);
  let entries;
  try {
    entries = JSON.parse(run.stdout);
  } catch {
    throw new Error('npm pack --dry-run --json printed no JSON');
  }
  if (!Array.isArray(entries) || entries.length !== 1 || !Array.isArray(entries[0].files)) {
    throw new Error('npm pack --dry-run --json did not describe exactly one package');
  }
  const files = entries[0].files.map((entry) => entry.path).sort();
  if (files.length === 0) throw new Error('npm pack --dry-run --json listed no files');
  return files;
}

// Reads every file of `files` under `root` with the loaded expressions module
// and returns each refused line as { file, line, rule }, the files skipped for
// a NUL byte, and the exemptions for `pkg` whose file is packed but carries no
// exempted line.
function scanPack(root, files, pkg, { EXEMPT, PATTERN, VENDOR, figureLines }) {
  const exempt = EXEMPT.filter((entry) => entry.pkg === pkg);
  const used = new Set();
  const hits = [];
  const binary = [];
  for (const file of files) {
    const buf = fs.readFileSync(path.join(root, file));
    if (buf.subarray(0, 8000).includes(0)) {
      binary.push(file);
      continue;
    }
    const lines = buf.toString('utf8').split('\n');
    const exempted = (number) => {
      const index = exempt.findIndex((entry) => entry.file === file && entry.line === lines[number - 1].trim());
      if (index >= 0) used.add(index);
      return index >= 0;
    };
    lines.forEach((line, index) => {
      if (PATTERN.test(line) && !exempted(index + 1)) hits.push({ file, line: index + 1, rule: 'PATTERN' });
      if (VENDOR.test(line) && !exempted(index + 1)) hits.push({ file, line: index + 1, rule: 'VENDOR' });
    });
    for (const number of figureLines(lines)) {
      if (!exempted(number)) hits.push({ file, line: number, rule: 'FIGURES' });
    }
  }
  const stale = exempt.filter((entry, index) => files.includes(entry.file) && !used.has(index));
  return { hits, binary, stale };
}

async function main(argv) {
  if (argv.length > 0) {
    log(`pack gate: takes no arguments, got ${argv.length}; the pack is refused`);
    return 2;
  }
  const root = process.cwd();
  // The expressions are imported here rather than at the top of this file, so
  // an error the module throws while it loads, as it does on a runtime older
  // than Node 23, reaches this handler and its exit 2 instead of escaping as
  // an uncaught error with a stack trace.
  let expressions;
  let pkg;
  let files;
  try {
    expressions = await import('./pack-gate-expressions.mjs');
    pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).name;
    files = listPackFiles(root);
  } catch (error) {
    log(`pack gate: ${error.message}; the pack is refused`);
    return 2;
  }
  const guidance = Object.freeze({
    PATTERN: expressions.PATTERN_GUIDANCE,
    VENDOR: expressions.VENDOR_GUIDANCE,
    FIGURES: expressions.FIGURES_GUIDANCE,
  });
  let result;
  try {
    result = scanPack(root, files, pkg, expressions);
  } catch (error) {
    log(`pack gate: a packed file could not be read (${error.message}); the pack is refused`);
    return 2;
  }
  const { hits, binary, stale } = result;
  for (const file of binary) log(`pack gate: skipped, NUL byte in the first 8000 bytes: ${file}`);
  for (const hit of hits) log(`${hit.file}:${hit.line}: ${hit.rule}: ${guidance[hit.rule]}`);
  for (const entry of stale) log(`pack gate: an exemption matches no line of ${entry.file}; delete it`);
  if (hits.length > 0 || stale.length > 0) {
    log(`pack gate: ${pkg} refused: ${hits.length} hits, ${stale.length} stale exemptions, ${files.length} packed files`);
    return 1;
  }
  log(`pack gate: ${pkg}: ${files.length} packed files read, ${binary.length} skipped, 0 hits`);
  return 0;
}

process.exitCode = await main(process.argv.slice(2));
