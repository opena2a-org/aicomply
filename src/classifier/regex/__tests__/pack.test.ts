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
import { VALIDATORS } from '../validators';
import * as api from '../../../index';

const ROOT = join(__dirname, '..', '..', '..', '..');
const packBytes = readFileSync(join(ROOT, 'pack', 'patterns.json'));
const packDoc = JSON.parse(packBytes.toString('utf8'));

type Entry = Record<string, unknown>;

/** Pack bytes with one pattern entry (by id) replaced by `edit(entry)`. */
function withEntry(id: string, edit: (entry: Entry) => Entry): Buffer {
  const doc = JSON.parse(packBytes.toString('utf8'));
  doc.patterns = doc.patterns.map((p: Entry) => (p.id === id ? edit({ ...p }) : p));
  return Buffer.from(JSON.stringify(doc));
}

/** Pack bytes with one pattern entry (by id) overridden. */
function withPattern(id: string, override: Entry): Buffer {
  return withEntry(id, (p) => ({ ...p, ...override }));
}

/** Pack bytes with one key removed from one pattern entry. */
function withoutKey(id: string, key: string): Buffer {
  return withEntry(id, (p) => {
    delete p[key];
    return p;
  });
}

/** The per-pattern fields of the pack contract, in file order. `note` is optional prose. */
const CONTRACT_FIELDS = [
  'id',
  'class',
  'source',
  'flags',
  'validator',
  'context',
  'aiisId',
  'techniqueId',
  'fpEstimate',
];

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
      ...packDoc.patterns.map((p: { source: string }) => p.source),
      ...packDoc.referenceForms.map((f: { source: string }) => f.source),
    ];
    expect(sources.filter((s: string) => nonPortableConstruct(s) !== null)).toEqual([]);
  });

  it('turns the former MRN lookahead into the containsDigit validator', () => {
    const mrn = packDoc.patterns.find((p: { id: string }) => p.id === 'mrn');
    expect(mrn.validator).toBe('containsDigit');
    expect(mrn.source).not.toContain('(?=');
  });
});

describe('pattern pack file follows the pack contract field names', () => {
  it('gives every pattern exactly the contract fields, plus an optional note', () => {
    for (const p of packDoc.patterns as Entry[]) {
      expect(Object.keys(p).filter((k) => k !== 'note')).toEqual(CONTRACT_FIELDS);
    }
  });

  it('keeps the top level to schemaVersion, packVersion, patterns and referenceForms', () => {
    expect(Object.keys(packDoc)).toEqual(['schemaVersion', 'packVersion', 'referenceForms', 'patterns']);
    for (const f of packDoc.referenceForms as Entry[]) {
      expect(Object.keys(f).filter((k) => k !== 'note')).toEqual(['id', 'source']);
    }
  });

  it('names validators by the contract names, with "none" for no check', () => {
    const byId = Object.fromEntries((packDoc.patterns as Entry[]).map((p) => [p.id, p.validator]));
    expect(byId).toMatchObject({
      ssn: 'ssnArea',
      pan: 'luhn',
      iban: 'mod97',
      npi: 'npiLuhn',
      mrn: 'containsDigit',
      'generic-key-assignment': 'notEmptyAssignmentTarget',
      'cui-marking': 'none',
      'aws-access-key-id': 'none',
    });
    for (const name of Object.values(byId) as string[]) {
      expect(name === 'none' || Object.prototype.hasOwnProperty.call(VALIDATORS, name)).toBe(true);
    }
  });

  it('implements the same validator names as every other runtime', () => {
    expect(Object.keys(VALIDATORS).sort()).toEqual([
      'containsDigit',
      'luhn',
      'mod97',
      'notEmptyAssignmentTarget',
      'npiLuhn',
      'ssnArea',
    ]);
  });

  it('carries each pattern confidence in context and compiles it unchanged', () => {
    for (const p of PATTERNS) {
      const entry = (packDoc.patterns as Entry[]).find((e) => e.id === p.id) as Entry;
      expect(p.confidence).toBe((entry.context as { confidence: number }).confidence);
      expect(p.type).toBe(entry.class);
      expect(p.regex.source).toBe(new RegExp(entry.source as string).source);
    }
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
    ['a lookahead', withPattern('mrn', { source: '\\bMRN[:\\s#-]*(?=[A-Z0-9]*\\d)([A-Z0-9]{6,12})\\b' }), /lookahead/],
    ['an unknown validator', withPattern('ssn', { validator: 'luhnModN' }), /validator luhnModN/],
    ['a former validator name', withPattern('ssn', { validator: 'ssn' }), /validator ssn /],
    ['a prototype key as validator', withPattern('ssn', { validator: 'constructor' }), /validator constructor/],
    ['an entry with no validator key', withoutKey('ssn', 'validator'), /ssn: validator is required/],
    ['a null validator', withPattern('cui-marking', { validator: null }), /validator must be a name/],
    ['an unknown class', withPattern('ssn', { class: 'PHONE' }), /class PHONE/],
    ['an unsupported flag', withPattern('ssn', { flags: 'm' }), /flags/],
    ['a confidence above 1', withPattern('ssn', { context: { confidence: 1.5 } }), /context\.confidence/],
    ['a context that is not an object', withPattern('ssn', { context: 0.95 }), /context must be an object/],
    ['a missing aiisId', withoutKey('ssn', 'aiisId'), /aiisId/],
    ['an empty techniqueId', withPattern('ssn', { techniqueId: '' }), /techniqueId/],
    ['an fpEstimate above 1', withPattern('ssn', { fpEstimate: 2 }), /fpEstimate/],
    ['a duplicate id', withPattern('pan', { id: 'ssn' }), /duplicated/],
    ['a source that does not compile', withPattern('ssn', { source: '(\\d{3}' }), /does not compile/],
  ])('refuses %s', (_label, bytes, message) => {
    expect(() => compilePack(bytes)).toThrow(message);
  });

  it('refuses an entry in the superseded type/regex/confidence shape', () => {
    // A pack written to the earlier field names must fail closed, not load
    // with no class or no source.
    const bytes = withEntry('ssn', (p) => {
      const { class: type, source: regex, context } = p;
      const old: Entry = { ...p, type, regex, confidence: (context as { confidence: number }).confidence };
      delete old.class;
      delete old.source;
      delete old.context;
      return old;
    });
    expect(() => compilePack(bytes)).toThrow(/pattern ssn: class undefined/);
  });

  it('accepts a filled-in aiisId, techniqueId and fpEstimate', () => {
    const bytes = withPattern('ssn', { aiisId: 'AIIS-0001', techniqueId: 'T-0001', fpEstimate: 0.02 });
    expect(compilePack(bytes).patterns.find((p) => p.id === 'ssn')).toBeDefined();
  });

  it('refuses another schema version', () => {
    const doc = { ...packDoc, schemaVersion: 2 };
    expect(() => compilePack(Buffer.from(JSON.stringify(doc)))).toThrow(/schemaVersion 2/);
  });

  it('refuses an unanchored reference form', () => {
    const doc = { ...packDoc, referenceForms: [{ id: 'loose', source: 'process\\.env' }] };
    expect(() => compilePack(Buffer.from(JSON.stringify(doc)))).toThrow(/anchored/);
  });

  it('refuses bytes that are not JSON', () => {
    expect(() => compilePack(Buffer.from('{"schemaVersion":'))).toThrow(/not valid JSON/);
  });
});

describe('every counted repeat in the pack has an upper bound', () => {
  it('leaves no counted repeat in the pack file without an upper bound', () => {
    // The shape `grep -c '{[0-9]*,}' pack/patterns.json` counts.
    expect(packBytes.toString('utf8').match(/\{[0-9]*,\}/g)).toBeNull();
  });

  // Each pattern whose token repeat carries the upper bound 1000, with that
  // bound removed again.
  const reopened: Array<[string, string]> = (packDoc.patterns as Entry[])
    .filter((p) => /\{\d+,(1000)?\}/.test(p.source as string))
    .map((p) => [p.id as string, (p.source as string).replace(/\{(\d+),1000\}/, '{$1,}')]);

  it('bounds the token repeat of six credential patterns', () => {
    expect(reopened.map(([id]) => id)).toEqual([
      'anthropic-api-key',
      'openai-project-key',
      'openrouter-key',
      'openai-legacy-key',
      'bearer-token',
      'generic-key-assignment',
    ]);
  });

  it.each(reopened)('refuses pattern %s with its token repeat left open, naming the pattern', (id, source) => {
    expect(() => compilePack(withPattern(id, { source }))).toThrow(
      new RegExp(`^aicomply pattern pack: pattern ${id}: source has the counted repeat \\{\\d+,\\}, which has no upper bound`),
    );
  });

  it.each([
    ['an upper bound above 1000', 'Bearer\\s+([A-Za-z0-9._~+/=-]{20,1001})', '{20,1001}'],
    ['a lower bound above 1000', 'Bearer\\s+([A-Za-z0-9._~+/=-]{1001,2000})', '{1001,2000}'],
    ['an exact count above 1000', 'Bearer\\s+([A-Za-z0-9._~+/=-]{1001})', '{1001}'],
  ])('refuses %s, naming the pattern', (_label, source, repeat) => {
    expect(() => compilePack(withPattern('bearer-token', { source }))).toThrow(
      `aicomply pattern pack: pattern bearer-token: source has the counted repeat ${repeat}, whose count is above 1000`,
    );
  });

  it.each([
    [
      '{,}',
      'Bearer\\s+([A-Za-z0-9._~+/=-]{,})',
      'the brace form {,}, which Python reads as a counted repeat with no upper bound and JavaScript and RE2 read as text',
    ],
    [
      '{,1000}',
      'Bearer\\s+([A-Za-z0-9._~+/=-]{,1000})',
      'the brace form {,1000}, which Python reads as a counted repeat and JavaScript and RE2 read as text',
    ],
  ])('refuses the brace form %s, which Python reads as a repeat and JavaScript as text, naming the pattern', (_form, source, problem) => {
    expect(() => compilePack(withPattern('bearer-token', { source }))).toThrow(
      `aicomply pattern pack: pattern bearer-token: source has ${problem}`,
    );
  });

  it('refuses a counted repeat without an upper bound in a reference form', () => {
    const doc = { ...packDoc, referenceForms: [{ id: 'open', source: '^\\$[A-Z_]{1,}$' }] };
    expect(() => compilePack(Buffer.from(JSON.stringify(doc)))).toThrow(
      'aicomply pattern pack: referenceForms[0]: source has the counted repeat {1,}, which has no upper bound',
    );
  });

  it.each([
    ['escaped braces', 'Bearer\\s+\\{20,\\}'],
    ['braces in a character class', 'Bearer\\s+[{20,}]+'],
    ['an upper bound of 1000', 'Bearer\\s+([A-Za-z0-9._~+/=-]{20,1000})'],
  ])('accepts %s', (_label, source) => {
    const compiled = compilePack(withPattern('bearer-token', { source }));
    expect(compiled.patterns.find((p) => p.id === 'bearer-token')?.regex.source).toBe(new RegExp(source).source);
  });
});
