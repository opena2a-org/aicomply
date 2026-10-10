#!/usr/bin/env node
// Release gate for the npm package.
//
//   node scripts/release-gate.mjs               exit 0 only when
//                                               conformance/typescript.json was
//                                               written by this package version,
//                                               against the pack this package
//                                               ships, with every case passing
//   node scripts/release-gate.mjs --root <dir>  gate the package rooted at <dir>
//
// `npm publish` runs it: the prepublishOnly script runs `npm run conformance`
// and then this gate before anything is packed, and a non-zero exit from
// either stops the publish. npm skips that script under --ignore-scripts and
// when it is handed a tarball instead of the package directory. The pack a
// publish embeds is pack/patterns.json at the package root: the `files` list
// ships it and the built runtime loads it from there. A record written against
// other pack bytes, by another runtime or version, or with a failing case says
// nothing about the package being published, so the gate refuses it.
//
// Every reason is printed, one REFUSED line each, then the fix for each. A
// package.json, pack or record that is missing, is a directory or sits under a
// file is named as such with its path, and the record's own fields are still
// checked beside a package.json or pack the gate could not read. A
// package.json that names no version is refused on its own: a record that
// names none either would otherwise compare equal. Exit 1 on a refusal, 2 on a
// usage error. Needs no build: it reads the record, package.json and the pack.

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RUNTIME = 'typescript';
const RECORD = 'conformance/typescript.json';
const PACK = 'pack/patterns.json';

const RERUN_FIX =
  'run `npm run conformance` on the commit being released, resolve every FAIL it prints, then run this gate again';
const ROOT_FIX = `pass --root the package directory, the one that holds package.json and ${PACK}`;
const PACKAGE_FIX =
  'restore package.json from the commit being released: the record is compared against its "version" string';
const PACK_FIX = `restore ${PACK} from the commit being released: the package ships it and the record is compared against its bytes`;
const RECORD_FIX = `remove what stands in place of ${RECORD}, then ${RERUN_FIX}`;

const args = process.argv.slice(2);
let root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (args.length === 2 && args[0] === '--root') {
  root = resolve(args[1]);
} else if (args.length !== 0) {
  console.error('usage: node scripts/release-gate.mjs [--root <dir>]');
  process.exit(2);
}

/** `value` as JSON, so a missing or mistyped field reads as what it is. */
function show(value) {
  return value === undefined ? 'missing' : JSON.stringify(value);
}

function isCount(value) {
  return Number.isInteger(value) && value >= 0;
}

function isDirectory(path) {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** The path, from `root` down towards `file`, that is not the directory it has to be. */
function nonDirectory(file) {
  let dir = root;
  for (const part of file.split('/').slice(0, -1)) {
    if (!isDirectory(dir)) break;
    dir = resolve(dir, part);
  }
  return dir;
}

/**
 * The bytes of `file` under `root`, or in `problem` why there are none: the
 * path and the condition for a file that is missing, is a directory or sits
 * under a file, and the system's own message for anything else. `where` says
 * where the file was looked for.
 */
function read(file, where = '') {
  try {
    return { bytes: readFileSync(resolve(root, file)) };
  } catch (err) {
    switch (err?.code) {
      case 'ENOENT':
        return { missing: true, problem: `${file} does not exist${where}` };
      case 'EISDIR':
        return { problem: `${file}${where} is a directory, not a file` };
      case 'ENOTDIR':
        return { problem: `${file} cannot be read, ${nonDirectory(file)} is not a directory` };
      default:
        return { problem: `${file} cannot be read (${err instanceof Error ? err.message : String(err)})` };
    }
  }
}

/** Every reason this record cannot stand for the package at `root`, each with its fix. */
function refusals() {
  const reasons = [];
  const refuse = (reason, fix = RERUN_FIX) => reasons.push({ reason, fix });

  const pkg = read('package.json', ` in ${root}`);
  const pack = read(PACK, ` in ${root}`);
  let version;
  let packSha256;
  if (pkg.bytes === undefined) {
    refuse(`package: ${pkg.problem}`, ROOT_FIX);
  } else {
    const named = JSON.parse(pkg.bytes.toString('utf8'))?.version;
    if (typeof named === 'string' && named !== '') {
      version = named;
      console.log(`package:    ${RUNTIME} ${version}`);
    } else {
      refuse(`package: package.json carries no version string, its version is ${show(named)}`, PACKAGE_FIX);
    }
  }
  if (pack.bytes === undefined) {
    // Without a package.json the root itself is the likely mistake.
    refuse(`pack: ${pack.problem}`, pkg.bytes === undefined ? ROOT_FIX : PACK_FIX);
  } else {
    packSha256 = createHash('sha256').update(pack.bytes).digest('hex');
    console.log(`pack:       sha256 ${packSha256} (${PACK})`);
  }

  const stored = read(RECORD);
  if (stored.bytes === undefined) {
    let fix = RERUN_FIX;
    // As for the pack: without a package.json the root itself is the likely mistake.
    if (!stored.missing) fix = pkg.bytes === undefined ? ROOT_FIX : RECORD_FIX;
    refuse(`record: ${stored.problem}`, fix);
    return reasons;
  }
  let record;
  try {
    record = JSON.parse(stored.bytes.toString('utf8'));
  } catch {
    record = null;
  }
  if (typeof record !== 'object' || record === null || Array.isArray(record)) {
    refuse(`record: ${RECORD} is not a JSON object`);
    return reasons;
  }
  console.log(
    `record:     ${show(record.runtime)} ${show(record.runtimeVersion)}, pack sha256 ${show(record.packSha256)}, ` +
      `${show(record.passed)} of ${show(record.cases)} cases passed`,
  );

  if (record.runtime !== RUNTIME) {
    refuse(`runtime: the record is for ${show(record.runtime)}, this gate publishes "${RUNTIME}"`);
  }
  // A version or pack the gate could not read is already refused above; there is nothing to compare with.
  if (version !== undefined && record.runtimeVersion !== version) {
    refuse(`runtimeVersion: the record was written by ${show(record.runtimeVersion)}, this package is ${show(version)}`);
  }
  if (packSha256 !== undefined && record.packSha256 !== packSha256) {
    refuse(
      `packSha256: the record was written against pack ${show(record.packSha256)}, this package ships "${packSha256}"`,
    );
  }
  if (!isCount(record.cases) || !isCount(record.passed)) {
    refuse(`cases: the record needs integer cases and passed, got ${show(record.cases)} and ${show(record.passed)}`);
  } else if (record.cases === 0) {
    refuse('cases: the record ran no cases');
  } else if (record.passed !== record.cases) {
    refuse(`passed: ${record.passed} of ${record.cases} cases passed`);
  }
  return reasons;
}

let reasons;
try {
  reasons = refusals();
} catch (err) {
  // Anything unforeseen is a refusal too: the gate never passes on an error.
  reasons = [{ reason: `gate: ${err instanceof Error ? err.message : String(err)}`, fix: RERUN_FIX }];
}

if (reasons.length === 0) {
  console.log('release gate: passed');
  process.exit(0);
}
for (const { reason } of reasons) console.error(`REFUSED ${reason}`);
console.error('release gate: refused, do not publish');
for (const fix of new Set(reasons.map((r) => r.fix))) console.error(`fix: ${fix}`);
process.exit(1);
