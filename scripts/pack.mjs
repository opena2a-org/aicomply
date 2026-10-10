#!/usr/bin/env node
// Pattern pack build check.
//
//   node scripts/pack.mjs check   validate pack/patterns.json against the pack
//                                 contract, confirm the Python package carries
//                                 a byte-identical copy, print the null census
//   node scripts/pack.mjs sync    validate, then write the Python package copy
//
// Validation is the TypeScript loader itself (compilePack), so this script and
// the runtime cannot disagree about what a valid pack is.
//
// Requires a build: npm run build.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PACK = resolve(ROOT, 'pack/patterns.json');
const PY_COPY = resolve(ROOT, 'python/src/aicomply/pack/patterns.json');
const CENSUS_FIELDS = ['aiisId', 'techniqueId', 'fpEstimate'];

const require = createRequire(import.meta.url);
const { compilePack } = require(resolve(ROOT, 'dist/classifier/regex/pack.js'));

const mode = process.argv[2];
if (mode !== 'check' && mode !== 'sync') {
  console.error('usage: node scripts/pack.mjs check|sync');
  process.exit(2);
}

const bytes = readFileSync(PACK);
const compiled = compilePack(bytes);
const doc = JSON.parse(bytes.toString('utf8'));

console.log(`pack ${compiled.version} sha256 ${compiled.sha256}`);
console.log(`${compiled.patterns.length} patterns, ${compiled.referenceForms.length} reference forms`);
console.log('null census:');
for (const field of CENSUS_FIELDS) {
  const nulls = doc.patterns.filter((p) => p[field] === null || p[field] === undefined);
  console.log(`  ${field}: ${nulls.length} of ${doc.patterns.length} null`);
}

if (mode === 'sync') {
  writeFileSync(PY_COPY, bytes);
  console.log('wrote python/src/aicomply/pack/patterns.json');
  process.exit(0);
}

let copy;
try {
  copy = readFileSync(PY_COPY);
} catch {
  copy = null;
}
if (copy === null || !copy.equals(bytes)) {
  console.error('python/src/aicomply/pack/patterns.json differs from pack/patterns.json');
  console.error('run: npm run pack:sync');
  process.exit(1);
}
console.log('python copy: identical');
