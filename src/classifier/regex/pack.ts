/**
 * Pattern pack loader: the single construction site of compiled patterns.
 *
 * The detection regexes are data in `pack/patterns.json`, shared byte for byte
 * with every runtime of this classifier. This module reads that file, checks
 * it against the pack contract, and compiles it. Nothing else in the codebase
 * holds a detection pattern literal.
 *
 * The loader fails closed: a missing, malformed or non-portable pack throws at
 * import time rather than leaving the classifier running with no patterns,
 * which would report every input as CLEAN.
 *
 * File shape (camelCase):
 *
 *   { "schemaVersion": 1, "packVersion": "<semver>",
 *     "referenceForms": [ { "id", "source", "note"? } ],
 *     "patterns": [ { "id", "class", "source", "flags", "validator",
 *                     "context": { "confidence" },
 *                     "aiisId", "techniqueId", "fpEstimate", "note"? } ] }
 *
 * `class` is the violation type a match reports, `source` the regex, `validator`
 * a name from `./validators` or "none", and `context.confidence` the confidence
 * a match carries (it also decides which of two overlapping matches is kept).
 * `aiisId`, `techniqueId` and `fpEstimate` are nullable until they are mapped.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NO_VALIDATOR, VALIDATORS, type Validator } from './validators';
import type { PackIdentity } from '../../types';

export const PATTERN_TYPES = [
  'SSN',
  'PAN',
  'CUI',
  'CREDENTIAL',
  'IBAN',
  'PASSPORT',
  'MRN',
  'NPI',
] as const;

export type PatternType = (typeof PATTERN_TYPES)[number];

/** The pack schema this loader reads. A different value is refused. */
export const PACK_SCHEMA_VERSION = 1;

export interface PatternDefinition {
  /** Stable pack identifier, e.g. `aws-access-key-id`. */
  id: string;
  /** The entry's `class`. */
  type: PatternType;
  /** The entry's `source`, compiled with its `flags` plus the global flag. */
  regex: RegExp;
  /** The entry's `context.confidence`. */
  confidence: number;
  /** The entry's `validator`; absent for "none". */
  validate?: Validator;
}

export interface CompiledPack {
  version: string;
  /** SHA-256 (hex) of the exact pack file bytes. */
  sha256: string;
  patterns: PatternDefinition[];
  /** Anchored forms of a value that names a secret without carrying one. */
  referenceForms: RegExp[];
}

/**
 * Return the first construct outside the portable regex subset, or null.
 *
 * The subset is syntax that JavaScript, Python `re` and RE2 (Go) all accept:
 * no lookaround, no backreferences, no named groups, and no inline modifier
 * groups (case-insensitivity is the entry's `flags` field). Accepting the
 * syntax does not make the engines agree on every input: `\s` matches Unicode
 * separators such as U+2028 and U+1680 here but not under Python's `re.ASCII`
 * or in RE2, so the conformance suite is what asserts agreement, case by case.
 */
export function nonPortableConstruct(source: string): string | null {
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') {
      const next = source[i + 1];
      if (next === undefined) return 'trailing backslash';
      if (next >= '1' && next <= '9') return 'backreference';
      if (next === 'k') return 'named backreference';
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      continue;
    }
    if (c === '(' && source[i + 1] === '?') {
      const kind = source[i + 2];
      if (kind === ':') continue;
      if (kind === '=' || kind === '!') return 'lookahead';
      if (kind === '<') {
        const after = source[i + 3];
        return after === '=' || after === '!' ? 'lookbehind' : 'named group';
      }
      if (kind === 'P') return 'named group';
      return 'inline modifier group';
    }
  }
  return null;
}

function fail(message: string): never {
  throw new Error(`aicomply pattern pack: ${message}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function compileRegex(where: string, source: unknown, flags: string): RegExp {
  if (typeof source !== 'string' || source.length === 0) {
    fail(`${where}: source must be a non-empty string`);
  }
  const construct = nonPortableConstruct(source);
  if (construct !== null) {
    fail(`${where}: source uses a ${construct}, which is outside the portable subset`);
  }
  try {
    return new RegExp(source, flags);
  } catch (err) {
    fail(`${where}: source does not compile (${(err as Error).message})`);
  }
}

/** Check the mapping fields: present on every entry, null until mapped. */
function checkMappingFields(id: string, entry: Record<string, unknown>): void {
  for (const key of ['aiisId', 'techniqueId'] as const) {
    if (!(key in entry)) fail(`pattern ${id}: ${key} is missing (use null when unmapped)`);
    const value = entry[key];
    if (value !== null && (typeof value !== 'string' || value === '')) {
      fail(`pattern ${id}: ${key} must be null or a non-empty string`);
    }
  }
  if (!('fpEstimate' in entry)) fail(`pattern ${id}: fpEstimate is missing (use null when unmeasured)`);
  const fp = entry.fpEstimate;
  if (fp !== null && (typeof fp !== 'number' || !(fp >= 0 && fp <= 1))) {
    fail(`pattern ${id}: fpEstimate must be null or a number in [0, 1]`);
  }
}

/**
 * Validate and compile pack file bytes. Exported so tests can prove each
 * contract rule refuses a bad pack; production code uses `PACK` below.
 */
export function compilePack(bytes: Buffer): CompiledPack {
  let doc: unknown;
  try {
    doc = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    fail(`not valid JSON (${(err as Error).message})`);
  }
  if (!isRecord(doc)) fail('top level must be an object');
  if (doc.schemaVersion !== PACK_SCHEMA_VERSION) {
    fail(`schemaVersion ${String(doc.schemaVersion)} is not supported (expected ${PACK_SCHEMA_VERSION})`);
  }
  if (typeof doc.packVersion !== 'string' || !/^\d+\.\d+\.\d+$/.test(doc.packVersion)) {
    fail('packVersion must be a MAJOR.MINOR.PATCH string');
  }
  if (!Array.isArray(doc.patterns) || doc.patterns.length === 0) {
    fail('patterns must be a non-empty array');
  }
  if (!Array.isArray(doc.referenceForms)) fail('referenceForms must be an array');

  const seen = new Set<string>();
  const patterns: PatternDefinition[] = doc.patterns.map((entry: unknown, index: number) => {
    if (!isRecord(entry)) fail(`patterns[${index}] must be an object`);
    const id = entry.id;
    if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(id)) {
      fail(`patterns[${index}].id must be a lowercase kebab-case string`);
    }
    if (seen.has(id)) fail(`pattern id ${id} is duplicated`);
    seen.add(id);

    const klass = entry.class;
    if (typeof klass !== 'string' || !(PATTERN_TYPES as readonly string[]).includes(klass)) {
      fail(`pattern ${id}: class ${String(klass)} is not one of ${PATTERN_TYPES.join(', ')}`);
    }
    if (entry.flags !== '' && entry.flags !== 'i') {
      fail(`pattern ${id}: flags must be "" or "i"`);
    }
    const context = entry.context;
    if (!isRecord(context)) fail(`pattern ${id}: context must be an object`);
    const confidence = context.confidence;
    if (typeof confidence !== 'number' || !(confidence > 0 && confidence <= 1)) {
      fail(`pattern ${id}: context.confidence must be a number in (0, 1]`);
    }

    // The key is required in both runtimes; "none" is how an entry says it has
    // no validator, so a missing key is a malformed entry, not "none".
    if (!Object.prototype.hasOwnProperty.call(entry, 'validator')) {
      fail(`pattern ${id}: validator is required (a validator name, or "${NO_VALIDATOR}" for no check)`);
    }
    const name = entry.validator;
    if (typeof name !== 'string') {
      fail(`pattern ${id}: validator must be a name, or "${NO_VALIDATOR}" for no check`);
    }
    let validate: Validator | undefined;
    if (name !== NO_VALIDATOR) {
      if (!Object.prototype.hasOwnProperty.call(VALIDATORS, name)) {
        fail(`pattern ${id}: validator ${name} is not implemented by this runtime`);
      }
      validate = VALIDATORS[name];
    }
    checkMappingFields(id, entry);

    // Matching is a scan for every occurrence, so the global flag is always on.
    const regex = compileRegex(`pattern ${id}`, entry.source, `g${entry.flags}`);
    const definition: PatternDefinition = { id, type: klass as PatternType, regex, confidence };
    if (validate) definition.validate = validate;
    return definition;
  });

  const referenceForms = doc.referenceForms.map((entry: unknown, index: number) => {
    if (!isRecord(entry)) fail(`referenceForms[${index}] must be an object`);
    const source = entry.source;
    if (typeof source !== 'string' || !source.startsWith('^') || !source.endsWith('$')) {
      fail(`referenceForms[${index}]: source must be anchored with ^ and $`);
    }
    // No global flag: these are tested with .test(), which a global flag
    // would make stateful across calls.
    return compileRegex(`referenceForms[${index}]`, source, '');
  });

  return {
    version: doc.packVersion,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    patterns,
    referenceForms,
  };
}

/**
 * Location of the pack. From `src/classifier/regex` (tests) and from
 * `dist/classifier/regex` (the published package) three levels up is the
 * package root, which carries `pack/patterns.json`.
 */
export const PACK_PATH = join(__dirname, '..', '..', '..', 'pack', 'patterns.json');

/**
 * Read the pack bytes. The pack is a runtime asset beside `dist/`, so a bundle
 * or a copy of `dist/` alone cannot find it; say which file is missing and how
 * to ship it rather than surfacing a bare ENOENT at import.
 */
export function readPackFile(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    fail(
      `${path} not found. The package reads pack/patterns.json from its root at runtime: ` +
        'when bundling, mark @opena2a/aicomply as external; when copying the package, copy pack/ with dist/.',
    );
  }
}

export const PACK: CompiledPack = compilePack(readPackFile(PACK_PATH));

/** Version of the pattern pack this build loaded. */
export const PACK_VERSION: string = PACK.version;

/** SHA-256 (hex) of the pattern pack bytes this build loaded. */
export const PACK_SHA256: string = PACK.sha256;

/** A fresh `{ version, sha256 }` for one result, so no two results share an object. */
export function packIdentity(): PackIdentity {
  return { version: PACK_VERSION, sha256: PACK_SHA256 };
}
