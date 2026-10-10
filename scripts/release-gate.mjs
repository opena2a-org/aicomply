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
// Run it after `npm run conformance` and before `npm publish`. The pack a
// publish embeds is pack/patterns.json at the package root: the `files` list
// ships it and the built runtime loads it from there. A record written against
// other pack bytes, by another runtime or version, or with a failing case says
// nothing about the package being published, so the gate refuses it.
//
// Every reason is printed, one REFUSED line each. Exit 1 on a refusal, 2 on a
// usage error. Needs no build: it reads the record, package.json and the pack.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RUNTIME = 'typescript';
const RECORD = 'conformance/typescript.json';
const PACK = 'pack/patterns.json';

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

/** Every reason this record cannot stand for the package at `root`. */
function refusals() {
  const version = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).version;
  const packSha256 = createHash('sha256').update(readFileSync(resolve(root, PACK))).digest('hex');
  console.log(`package:    ${RUNTIME} ${version}`);
  console.log(`pack:       sha256 ${packSha256} (${PACK})`);

  let text;
  try {
    text = readFileSync(resolve(root, RECORD), 'utf8');
  } catch {
    return [`record: ${RECORD} does not exist`];
  }
  let record;
  try {
    record = JSON.parse(text);
  } catch {
    record = null;
  }
  if (typeof record !== 'object' || record === null || Array.isArray(record)) {
    return [`record: ${RECORD} is not a JSON object`];
  }
  console.log(
    `record:     ${show(record.runtime)} ${show(record.runtimeVersion)}, pack sha256 ${show(record.packSha256)}, ` +
      `${show(record.passed)} of ${show(record.cases)} cases passed`,
  );

  const reasons = [];
  if (record.runtime !== RUNTIME) {
    reasons.push(`runtime: the record is for ${show(record.runtime)}, this gate publishes "${RUNTIME}"`);
  }
  if (record.runtimeVersion !== version) {
    reasons.push(
      `runtimeVersion: the record was written by ${show(record.runtimeVersion)}, this package is ${show(version)}`,
    );
  }
  if (record.packSha256 !== packSha256) {
    reasons.push(
      `packSha256: the record was written against pack ${show(record.packSha256)}, this package ships "${packSha256}"`,
    );
  }
  if (!isCount(record.cases) || !isCount(record.passed)) {
    reasons.push(`cases: the record needs integer cases and passed, got ${show(record.cases)} and ${show(record.passed)}`);
  } else if (record.cases === 0) {
    reasons.push('cases: the record ran no cases');
  } else if (record.passed !== record.cases) {
    reasons.push(`passed: ${record.passed} of ${record.cases} cases passed`);
  }
  return reasons;
}

let reasons;
try {
  reasons = refusals();
} catch (err) {
  // An unreadable package or pack is a refusal too: the gate never passes on an error.
  reasons = [`gate: ${err instanceof Error ? err.message : String(err)}`];
}

if (reasons.length === 0) {
  console.log('release gate: passed');
  process.exit(0);
}
for (const reason of reasons) console.error(`REFUSED ${reason}`);
console.error('release gate: refused, do not publish');
console.error('fix: run `npm run conformance` on the commit being released, resolve every FAIL it prints, then run this gate again');
process.exit(1);
