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
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { VALIDATORS, type Validator } from './validators';
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
  type: PatternType;
  regex: RegExp;
  confidence: number;
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
 * The subset is what JavaScript, Python `re` and RE2 (Go) all compile with the
 * same meaning: no lookaround, no backreferences, no named groups, and no
 * inline modifier groups (case-insensitivity is the entry's `flags` field).
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
    fail(`${where}: regex must be a non-empty string`);
  }
  const construct = nonPortableConstruct(source);
  if (construct !== null) {
    fail(`${where}: regex uses a ${construct}, which is outside the portable subset`);
  }
  try {
    return new RegExp(source, flags);
  } catch (err) {
    fail(`${where}: regex does not compile (${(err as Error).message})`);
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

    const type = entry.type;
    if (typeof type !== 'string' || !(PATTERN_TYPES as readonly string[]).includes(type)) {
      fail(`pattern ${id}: type ${String(type)} is not one of ${PATTERN_TYPES.join(', ')}`);
    }
    if (entry.flags !== '' && entry.flags !== 'i') {
      fail(`pattern ${id}: flags must be "" or "i"`);
    }
    const confidence = entry.confidence;
    if (typeof confidence !== 'number' || !(confidence > 0 && confidence <= 1)) {
      fail(`pattern ${id}: confidence must be a number in (0, 1]`);
    }

    let validate: Validator | undefined;
    if (entry.validator !== null) {
      const name = entry.validator;
      if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(VALIDATORS, name)) {
        fail(`pattern ${id}: validator ${String(name)} is not implemented by this runtime`);
      }
      validate = VALIDATORS[name];
    }

    // Matching is a scan for every occurrence, so the global flag is always on.
    const regex = compileRegex(`pattern ${id}`, entry.regex, `g${entry.flags}`);
    const definition: PatternDefinition = { id, type: type as PatternType, regex, confidence };
    if (validate) definition.validate = validate;
    return definition;
  });

  const referenceForms = doc.referenceForms.map((entry: unknown, index: number) => {
    if (!isRecord(entry)) fail(`referenceForms[${index}] must be an object`);
    const source = entry.regex;
    if (typeof source !== 'string' || !source.startsWith('^') || !source.endsWith('$')) {
      fail(`referenceForms[${index}]: regex must be anchored with ^ and $`);
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

export const PACK: CompiledPack = compilePack(readFileSync(PACK_PATH));

/** Version of the pattern pack this build loaded. */
export const PACK_VERSION: string = PACK.version;

/** SHA-256 (hex) of the pattern pack bytes this build loaded. */
export const PACK_SHA256: string = PACK.sha256;

/** A fresh `{ version, sha256 }` for one result, so no two results share an object. */
export function packIdentity(): PackIdentity {
  return { version: PACK_VERSION, sha256: PACK_SHA256 };
}
