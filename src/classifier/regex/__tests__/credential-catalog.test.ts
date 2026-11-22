/**
 * The pack's CREDENTIAL rules against the shared OpenA2A credential catalog,
 * @opena2a/credential-patterns, which the opena2a CLI and HackMyAgent scan
 * with. A pack rule for a format the catalog carries is the catalog's regex
 * in one of the pack's shapes, so a change to either side fails here instead
 * of letting the two catalogs drift apart (issue #182: the catalog had a
 * Google API key rule and the pack had none).
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(__dirname, '..', '..', '..', '..');
const packDoc = JSON.parse(readFileSync(join(ROOT, 'pack', 'patterns.json'), 'utf8'));

interface CatalogEntry {
  id: string;
  source: string;
  flags: string;
}

/** The catalog as the installed package exports it. The package is ESM only. */
const catalog: CatalogEntry[] = JSON.parse(
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "import { CREDENTIAL_PATTERNS } from '@opena2a/credential-patterns';" +
        'process.stdout.write(JSON.stringify(CREDENTIAL_PATTERNS.map((p) => ' +
        '({ id: p.id, source: p.regex.source, flags: p.regex.flags }))));',
    ],
    { cwd: ROOT, encoding: 'utf8' },
  ),
);

/**
 * How a pack rule is made from a catalog regex:
 * - `token`: a fixed-length token between word boundaries, captured;
 * - `run`: the token's final repeat bounded at 1000 (the pack refuses an open
 *   repeat), so a longer run is captured and masked whole;
 * - `run-boundary`: a `run` after a word boundary.
 */
type Shape = 'token' | 'run' | 'run-boundary';

const bounded = (source: string): string => source.replace(/\{(\d+),?\}$/, '{$1,1000}');

function derive(source: string, shape: Shape): string {
  switch (shape) {
    case 'token':
      return `\\b(${source})\\b`;
    case 'run':
      return `(${bounded(source)})`;
    case 'run-boundary':
      return `\\b(${bounded(source)})`;
  }
}

/**
 * `source` with each character class written as its characters in code point
 * order, so `[a-zA-Z0-9]` and `[A-Za-z0-9]` compare equal. For comparison
 * only: the result is not compiled.
 */
function canonicalClasses(source: string): string {
  return source.replace(/\[((?:\\.|[^\]\\])*)\]/g, (_, body: string) => {
    const chars = new Set<string>();
    for (let i = 0; i < body.length; i += 1) {
      if (body[i] === '\\') {
        chars.add(body.slice(i, i + 2));
        i += 1;
      } else if (body[i + 1] === '-' && i + 2 < body.length) {
        for (let c = body.charCodeAt(i); c <= body.charCodeAt(i + 2); c += 1) chars.add(String.fromCharCode(c));
        i += 2;
      } else {
        chars.add(body[i]);
      }
    }
    return `[${[...chars].sort().join('')}]`;
  });
}

/** Pack rules made from a catalog entry: pack id, catalog id, shape. */
const DERIVED: Array<[string, string, Shape]> = [
  ['aws-access-key-id', 'aws-access', 'token'],
  ['anthropic-api-key', 'anthropic', 'run'],
  ['openrouter-key', 'openrouter', 'run'],
  ['openai-legacy-key', 'openai-legacy', 'run-boundary'],
  ['github-pat-classic', 'github-pat', 'token'],
  ['google-api-key', 'google', 'run'],
];

/**
 * Pack rules for a catalog format that the pack matches differently, with
 * the catalog regex they were last compared with. A change to that regex
 * fails here, so the difference is looked at again.
 */
const DIFFERS: Array<[string, string, string, string]> = [
  [
    'openai-project-key',
    'openai-proj',
    'sk-proj-[a-zA-Z0-9]{20,}',
    'the pack also takes _ and - in the token, as project keys carry them',
  ],
  [
    'github-pat-fine-grained',
    'github-fine',
    'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
    'the pack takes 82 characters of A-Z, a-z, 0-9 and _ after the prefix, wherever the _ falls',
  ],
];

/** Pack rules that find a credential by the text before it; the catalog has no such rule. */
const CONTEXTUAL = ['aws-secret-access-key', 'bearer-token', 'generic-key-assignment'];

const packSource = (id: string): string => {
  const entry = packDoc.patterns.find((p: { id: string }) => p.id === id);
  if (entry === undefined) throw new Error(`no pack pattern ${id}`);
  return entry.source;
};

const catalogEntry = (id: string): CatalogEntry => {
  const entry = catalog.find((p) => p.id === id);
  if (entry === undefined) throw new Error(`no catalog pattern ${id}`);
  return entry;
};

describe('the CREDENTIAL rules and the @opena2a/credential-patterns catalog', () => {
  it('names every CREDENTIAL rule of the pack once, as derived, different or contextual', () => {
    const credentialIds = packDoc.patterns
      .filter((p: { class: string }) => p.class === 'CREDENTIAL')
      .map((p: { id: string }) => p.id)
      .sort();
    const named = [...DERIVED.map(([id]) => id), ...DIFFERS.map(([id]) => id), ...CONTEXTUAL].sort();
    expect(named).toEqual(credentialIds);
  });

  it.each(DERIVED)('derives %s from the catalog entry %s as a %s', (packId, catalogId, shape) => {
    const entry = catalogEntry(catalogId);
    expect(entry.flags).toBe('');
    expect(canonicalClasses(packSource(packId))).toBe(canonicalClasses(derive(entry.source, shape)));
  });

  it('carries the catalog google form, captured and bounded, byte for byte', () => {
    expect(packSource('google-api-key')).toBe(derive(catalogEntry('google').source, 'run'));
  });

  it.each(DIFFERS)('compared %s with the current catalog entry %s', (_packId, catalogId, source) => {
    expect(catalogEntry(catalogId).source).toBe(source);
  });
});
