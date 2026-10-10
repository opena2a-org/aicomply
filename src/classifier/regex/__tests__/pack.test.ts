import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  PACK,
  PACK_PATH,
  PACK_SHA256,
  PACK_VERSION,
  compilePack,
  nonPortableConstruct,
  readPackFile,
} from '../pack';
import { PATTERNS } from '../patterns';
import * as api from '../../../index';

const ROOT = join(__dirname, '..', '..', '..', '..');
const packBytes = readFileSync(join(ROOT, 'pack', 'patterns.json'));
const packDoc = JSON.parse(packBytes.toString('utf8'));

/** Pack bytes with one pattern entry (by id) overridden. */
function withPattern(id: string, override: Record<string, unknown>): Buffer {
  const doc = JSON.parse(packBytes.toString('utf8'));
  doc.patterns = doc.patterns.map((p: { id: string }) => (p.id === id ? { ...p, ...override } : p));
  return Buffer.from(JSON.stringify(doc));
}

describe('pattern pack', () => {
  it('loads the repository pack file', () => {
    expect(PACK_PATH).toBe(join(ROOT, 'pack', 'patterns.json'));
  });

  it('names the missing pack file and how to ship it when dist/ is moved without it', () => {
    const missing = join(tmpdir(), 'aicomply-relocated', 'pack', 'patterns.json');
    expect(() => readPackFile(missing)).toThrow(
      `aicomply pattern pack: ${missing} not found. The package reads pack/patterns.json from its root at runtime: ` +
        'when bundling, mark @opena2a/aicomply as external; when copying the package, copy pack/ with dist/.',
    );
  });

  it('reports the version and SHA-256 of the exact bytes it loaded', () => {
    expect(PACK_VERSION).toBe(packDoc.packVersion);
    expect(PACK_SHA256).toBe(createHash('sha256').update(packBytes).digest('hex'));
    expect(PACK_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('exports PACK_VERSION and PACK_SHA256 from the package entry point', () => {
    expect(api.PACK_VERSION).toBe(PACK_VERSION);
    expect(api.PACK_SHA256).toBe(PACK_SHA256);
  });

  it('ships a byte-identical copy inside the Python package', () => {
    // Both runtimes must read the same pack. The Python wheel cannot reach
    // outside its package, so it carries a copy; `npm run pack:sync` writes it.
    const copy = readFileSync(join(ROOT, 'python', 'src', 'aicomply', 'pack', 'patterns.json'));
    expect(copy.equals(packBytes)).toBe(true);
  });

  it('compiles every pack entry, in pack order', () => {
    expect(PATTERNS.map((p) => p.id)).toEqual(packDoc.patterns.map((p: { id: string }) => p.id));
    expect(PACK.referenceForms).toHaveLength(packDoc.referenceForms.length);
    for (const p of PATTERNS) {
      expect(p.regex.global).toBe(true);
    }
  });

  it('keeps every pack regex inside the portable subset', () => {
    const sources = [
      ...packDoc.patterns.map((p: { regex: string }) => p.regex),
      ...packDoc.referenceForms.map((f: { regex: string }) => f.regex),
    ];
    expect(sources.filter((s: string) => nonPortableConstruct(s) !== null)).toEqual([]);
  });

  it('turns the former MRN lookahead into the containsDigit validator', () => {
    const mrn = packDoc.patterns.find((p: { id: string }) => p.id === 'mrn');
    expect(mrn.validator).toBe('containsDigit');
    expect(mrn.regex).not.toContain('(?=');
  });
});

describe('nonPortableConstruct', () => {
  it.each([
    ['\\bMRN(?=[A-Z0-9]*\\d)', 'lookahead'],
    ['a(?!b)', 'lookahead'],
    ['(?<=a)b', 'lookbehind'],
    ['(?<!a)b', 'lookbehind'],
    ['(a)\\1', 'backreference'],
    ['(?<key>a)', 'named group'],
    ['(?P<key>a)', 'named group'],
    ['\\k<key>', 'named backreference'],
    ['(?i)abc', 'inline modifier group'],
    ['abc\\', 'trailing backslash'],
  ])('refuses %s as a %s', (source, construct) => {
    expect(nonPortableConstruct(source)).toBe(construct);
  });

  it.each([
    '(?:api[_-]?key|secret)',
    '\\(\\?=literal',
    '[(?=]',
    '\\b(\\d{3}-\\d{2}-\\d{4})\\b',
  ])('accepts %s', (source) => {
    expect(nonPortableConstruct(source)).toBeNull();
  });
});

describe('compilePack refuses a pack that breaks the contract', () => {
  it.each([
    ['a lookahead', withPattern('mrn', { regex: '\\bMRN[:\\s#-]*(?=[A-Z0-9]*\\d)([A-Z0-9]{6,12})\\b' }), /lookahead/],
    ['an unknown validator', withPattern('ssn', { validator: 'luhnModN' }), /validator luhnModN/],
    ['a prototype key as validator', withPattern('ssn', { validator: 'constructor' }), /validator constructor/],
    // JSON.stringify drops an undefined value, so this entry has no validator key.
    ['an entry with no validator key', withPattern('ssn', { validator: undefined }), /ssn: validator is required/],
    ['an unknown type', withPattern('ssn', { type: 'PHONE' }), /type PHONE/],
    ['an unsupported flag', withPattern('ssn', { flags: 'm' }), /flags/],
    ['a confidence above 1', withPattern('ssn', { confidence: 1.5 }), /confidence/],
    ['a duplicate id', withPattern('pan', { id: 'ssn' }), /duplicated/],
    ['a regex that does not compile', withPattern('ssn', { regex: '(\\d{3}' }), /does not compile/],
  ])('refuses %s', (_label, bytes, message) => {
    expect(() => compilePack(bytes)).toThrow(message);
  });

  it('refuses another schema version', () => {
    const doc = { ...packDoc, schemaVersion: 2 };
    expect(() => compilePack(Buffer.from(JSON.stringify(doc)))).toThrow(/schemaVersion 2/);
  });

  it('refuses an unanchored reference form', () => {
    const doc = { ...packDoc, referenceForms: [{ id: 'loose', regex: 'process\\.env' }] };
    expect(() => compilePack(Buffer.from(JSON.stringify(doc)))).toThrow(/anchored/);
  });

  it('refuses bytes that are not JSON', () => {
    expect(() => compilePack(Buffer.from('{"schemaVersion":'))).toThrow(/not valid JSON/);
  });
});
