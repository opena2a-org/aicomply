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
// missing package.json or pack is named as such, and the record's own fields
// are still checked beside it. Exit 1 on a refusal, 2 on a usage error. Needs
// no build: it reads the record, package.json and the pack.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RUNTIME = 'typescript';
const RECORD = 'conformance/typescript.json';
const PACK = 'pack/patterns.json';

const RERUN_FIX =
  'run `npm run conformance` on the commit being released, resolve every FAIL it prints, then run this gate again';
const ROOT_FIX = `pass --root the package directory, the one that holds package.json and ${PACK}`;
const PACK_FIX = `restore ${PACK} from the commit being released: the package ships it and the record is compared against its bytes`;

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

/** The bytes of `file` under `root`, or null when there is no such file. */
function readIfPresent(file) {
  try {
    return readFileSync(resolve(root, file));
  } catch (err) {
    if (err?.code === 'ENOENT') return null;
    throw err;
  }
}

/** Every reason this record cannot stand for the package at `root`, each with its fix. */
function refusals() {
  const reasons = [];
  const refuse = (reason, fix = RERUN_FIX) => reasons.push({ reason, fix });

  const pkg = readIfPresent('package.json');
  const pack = readIfPresent(PACK);
  let version;
  let packSha256;
  if (pkg === null) {
    refuse(`package: package.json does not exist in ${root}`, ROOT_FIX);
  } else {
    version = JSON.parse(pkg.toString('utf8')).version;
    console.log(`package:    ${RUNTIME} ${version}`);
  }
  if (pack === null) {
    // Without a package.json the root itself is the likely mistake.
    refuse(`pack: ${PACK} does not exist in ${root}`, pkg === null ? ROOT_FIX : PACK_FIX);
  } else {
    packSha256 = createHash('sha256').update(pack).digest('hex');
    console.log(`pack:       sha256 ${packSha256} (${PACK})`);
  }

  let text;
  try {
    text = readFileSync(resolve(root, RECORD), 'utf8');
  } catch {
    refuse(`record: ${RECORD} does not exist`);
    return reasons;
  }
  let record;
  try {
    record = JSON.parse(text);
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
  // A missing package.json or pack is already refused above; there is nothing to compare with.
  if (pkg !== null && record.runtimeVersion !== version) {
    refuse(`runtimeVersion: the record was written by ${show(record.runtimeVersion)}, this package is ${show(version)}`);
  }
  if (pack !== null && record.packSha256 !== packSha256) {
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
  // An unreadable package or pack is a refusal too: the gate never passes on an error.
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
