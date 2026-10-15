/**
 * .hmaignore contract tests. HackMyAgent's AIM-001 check reports a project
 * whose package.json carries an agent keyword (aicomply lists `ai-agent`) and
 * that has no agent identity file. aicomply is a library and CLI that
 * classifies the input and output of other agents; it does not run as an
 * agent, so it has no identity of its own to declare. The .hmaignore file
 * records that once, as a rule naming the one check on the one file, so every
 * other check still reads package.json and AIM-001 still applies anywhere else.
 *
 * Each rule is read twice: by a copy of HackMyAgent's grammar that counts a
 * refused line as covering, and by the parser and matcher of the HackMyAgent
 * dev dependency. For each line in the tables below the test pins both whether
 * the version in use refuses it and whether it covers AIM-001 on package.json,
 * so a grammar change in that version that changes either answer for one of
 * those lines fails the test.
 *
 * README.md carries no invisible-unicode or look-alike example, so no rule may
 * keep it out of the UNICODE-STEGO checks: a character of that kind added to
 * it later has to be reported.
 */

import { existsSync, readFileSync } from 'fs';
import { dirname, join } from 'path';

const ROOT = join(__dirname, '..', '..');
const HMAIGNORE = readFileSync(join(ROOT, '.hmaignore'), 'utf8');

interface PublishedRule {
  line: number;
  rule: string;
}

interface PublishedParsed {
  present: boolean;
  file: string;
  rules: PublishedRule[];
  errors: { line: number; rule: string; error: string }[];
}

interface PublishedIgnore {
  parseHmaIgnore(content: string, today: string): Pick<PublishedParsed, 'rules' | 'errors'>;
  matchHmaIgnore(f: { checkId: string; file?: string }, parsed: PublishedParsed): { line?: number } | null;
  utcToday(): string;
}

/**
 * HackMyAgent's own .hmaignore parser and matcher, the ones every scan reads.
 * The module is not in the package's `exports`, so it is loaded by its path
 * beside the package entry point.
 */
const hma = require(join(dirname(require.resolve('hackmyagent')), 'hardening', 'scanner.js')) as PublishedIgnore;

interface PublishedTaxonomy {
  getTaxonomyMap(): Record<string, string>;
}

/**
 * The UNICODE-STEGO checks of the HackMyAgent in use, read from its check
 * taxonomy rather than listed here, so a check added to the family in that
 * taxonomy is covered without an edit here. On HackMyAgent 0.33.2 each of
 * UNICODE-STEGO-001 to -005 reports a finding on a README.md that carries its
 * kind of character or pattern, and a tag character such as U+E0041 is
 * reported by -004 alone.
 */
const UNICODE_STEGO_CHECKS = Object.keys(
  (require(join(dirname(require.resolve('hackmyagent')), 'hardening', 'taxonomy.js')) as PublishedTaxonomy)
    .getTaxonomyMap(),
)
  .filter((id) => id.startsWith('UNICODE-STEGO-'))
  .sort();

interface IgnoreRule {
  line: number;
  rule: string;
  reason: string;
}

/**
 * The rule lines of an .hmaignore: blank lines and whole-line comments are
 * skipped, and a `#` preceded by whitespace starts the reason, which is the
 * way HackMyAgent reads the file.
 */
function parseRules(content: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  const lines = content.split('\n');
  lines.forEach((raw, i) => {
    const text = raw.replace(/\r$/, '').trim();
    if (text.length === 0 || text.startsWith('#')) return;
    const comment = text.search(/[ \t]#/);
    rules.push(
      comment < 0
        ? { line: i + 1, rule: text, reason: '' }
        : {
            line: i + 1,
            rule: text.slice(0, comment).trimEnd(),
            reason: text.slice(comment).replace(/^[ \t]+#/, '').trim(),
          },
    );
  });
  return rules;
}

/**
 * Whether a check pattern names `checkId`, the way HackMyAgent matches one:
 * without regard to case, and with `*` standing for any run of characters.
 */
function namesCheck(pattern: string, checkId: string): boolean {
  const source = pattern
    .toUpperCase()
    .split('*')
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${source}$`).test(checkId.toUpperCase());
}

/**
 * Whether a path rule names `file`: the file itself or a directory above it,
 * compared as written, with `\` read as `/` and one trailing `/` dropped.
 * HackMyAgent has no globs in paths, so a `*` there names nothing.
 */
function namesPath(path: string, file: string): boolean {
  const p = path.replace(/\\/g, '/').replace(/\/$/, '');
  return file === p || file.startsWith(`${p}/`);
}

/**
 * Whether a rule keeps a finding of `checkId` on `file` out of a HackMyAgent
 * report. A rule is `!<check pattern>` for every file, `<path>:<check
 * pattern>` (split at the last colon) for one path, or a bare `<path>` for
 * every check, and `expires:<date>` attributes may follow it. A line that
 * HackMyAgent refuses still counts here, so the answer leans towards covered.
 */
function covers(r: IgnoreRule, file: string, checkId: string): boolean {
  const text = r.rule.replace(/(\s+expires:\S*)+$/i, '');
  if (text.startsWith('!')) return namesCheck(text.slice(1), checkId);
  const colon = text.lastIndexOf(':');
  return (
    namesPath(text, file) ||
    (colon >= 0 && namesPath(text.slice(0, colon), file) && namesCheck(text.slice(colon + 1), checkId))
  );
}

/** The rules of an .hmaignore that keep AIM-001 on package.json out of a report. */
function identityRules(content: string): string[] {
  return parseRules(content)
    .filter((r) => covers(r, 'package.json', 'AIM-001'))
    .map((r) => r.rule);
}

/**
 * The lines of an .hmaignore whose rule, on its own, keeps a finding of
 * `checkId` on `file` out of a report by the HackMyAgent in use. Each rule is
 * matched alone, because the matcher names only the first rule of the tier
 * that wins.
 */
function publishedCoveringLines(content: string, file: string, checkId: string): number[] {
  return hma
    .parseHmaIgnore(content, hma.utcToday())
    .rules.filter(
      (r) =>
        hma.matchHmaIgnore({ checkId, file }, { present: true, file: '.hmaignore', rules: [r], errors: [] }) !== null,
    )
    .map((r) => r.line);
}

/** The lines of an .hmaignore whose rule, on its own, keeps AIM-001 on package.json out of a report. */
function publishedIdentityLines(content: string): number[] {
  return publishedCoveringLines(content, 'package.json', 'AIM-001');
}

/** The lines of an .hmaignore that the HackMyAgent in use refuses. */
function publishedErrorLines(content: string): number[] {
  return hma.parseHmaIgnore(content, hma.utcToday()).errors.map((e) => e.line);
}

const IDENTITY_FILES = [
  'agent-card.json',
  '.well-known/agent-card.json',
  'agent.json',
  '.well-known/agent.json',
  'aim.json',
  '.well-known/aim.json',
];

describe('.hmaignore', () => {
  it('records why AIM-001 does not apply to package.json, for that check on that file only', () => {
    const matches = parseRules(HMAIGNORE).filter((r) => r.rule === 'package.json:AIM-001');
    expect(matches).toHaveLength(1);
    expect(matches[0].reason.length).toBeGreaterThan(0);
  });

  it('has no other rule that covers AIM-001 on package.json: no bare path, no `!` rule and no wildcard', () => {
    expect(identityRules(HMAIGNORE)).toEqual(['package.json:AIM-001']);
  });

  it('has no other rule that the HackMyAgent in use reads as covering AIM-001 on package.json', () => {
    const rule = parseRules(HMAIGNORE).filter((r) => r.rule === 'package.json:AIM-001');
    expect(publishedIdentityLines(HMAIGNORE)).toEqual(rule.map((r) => r.line));
  });

  // The HackMyAgent in use agrees on each line: as the only rule of an
  // .hmaignore it removes AIM-001 on package.json from the report.
  it.each([
    ['package.json:AIM-001  # x'],
    ['package.json:aim-001  # x'],
    ['package.json:AIM-*  # x'],
    ['package.json:*-001  # x'],
    ['package.json:A*  # x'],
    ['package.json/:AIM-001  # x'],
    ['package.json:AIM-*  expires:2099-01-01  # x'],
    ['package.json'],
    ['package.json  # x'],
    ['package.json/'],
    ['package.json\\'],
    ['!AIM-001'],
    ['!aim-001'],
    ['!AIM-*'],
    ['!A*  # x'],
    ['!*-001'],
    ['!*'],
    ['!A*  expires:2099-01-01'],
  ])('reads `%s` as a rule that covers AIM-001 on package.json', (line) => {
    expect(identityRules(`${line}\n`)).toHaveLength(1);
    expect(publishedErrorLines(`${line}\n`)).toEqual([]);
    expect(publishedIdentityLines(`${line}\n`)).toEqual([1]);
  });

  // HackMyAgent refuses each of these lines and applies nothing: a path rule
  // that names a check needs a reason, `<path>:*` is not a form, and a rule is
  // dropped the day after its `expires:` date. They are counted all the same.
  it.each([
    ['package.json:AIM-*'],
    ['package.json:*  # x'],
    ['package.json:AIM-*  expires:2001-01-01  # x'],
  ])('reads `%s` as a rule that covers AIM-001 on package.json, although HackMyAgent refuses it', (line) => {
    expect(identityRules(`${line}\n`)).toHaveLength(1);
    expect(publishedErrorLines(`${line}\n`)).toEqual([1]);
    expect(publishedIdentityLines(`${line}\n`)).toEqual([]);
  });

  // The HackMyAgent in use agrees on each line: as the only rule of an
  // .hmaignore it leaves AIM-001 on package.json reported. A check pattern
  // without `*` has to equal the whole check id, so a prefix or a suffix of
  // AIM-001 names nothing. It refuses the lines marked `refused` and applies
  // nothing from them: a path has no globs, and `?` is not part of a check
  // pattern. It accepts the others as rules that name something else.
  it.each([
    ['package.json:GIT-001  # x', 'accepts'],
    ['package.json:UNICODE-*  # x', 'accepts'],
    ['package.json:AIM  # x', 'accepts'],
    ['package.json:IM-001  # x', 'accepts'],
    ['src/index.ts:AIM-001  # x', 'accepts'],
    ['*.json:AIM-001  # x', 'refuses'],
    ['*.json', 'refuses'],
    ['pack', 'accepts'],
    ['pack/', 'accepts'],
    ['package-lock.json', 'accepts'],
    ['!GIT-001', 'accepts'],
    ['!UNICODE-STEGO-*', 'accepts'],
    ['!AIM-00?', 'refuses'],
    ['!AIM-00', 'accepts'],
    ['!IM-001', 'accepts'],
  ])('reads `%s` as a rule that leaves AIM-001 on package.json reported, and HackMyAgent %s it', (line, verdict) => {
    expect(identityRules(`${line}\n`)).toEqual([]);
    expect(publishedErrorLines(`${line}\n`)).toEqual(verdict === 'refuses' ? [1] : []);
    expect(publishedIdentityLines(`${line}\n`)).toEqual([]);
  });

  it('reads the UNICODE-STEGO checks from the HackMyAgent in use, UNICODE-STEGO-001 to -005 among them', () => {
    expect(UNICODE_STEGO_CHECKS).toEqual(
      expect.arrayContaining([
        'UNICODE-STEGO-001',
        'UNICODE-STEGO-002',
        'UNICODE-STEGO-003',
        'UNICODE-STEGO-004',
        'UNICODE-STEGO-005',
      ]),
    );
  });

  it.each(UNICODE_STEGO_CHECKS.map((checkId) => [checkId]))(
    'has no rule that keeps %s on README.md out of a report',
    (checkId) => {
      expect(
        parseRules(HMAIGNORE)
          .filter((r) => covers(r, 'README.md', checkId))
          .map((r) => r.rule),
      ).toEqual([]);
      expect(publishedCoveringLines(HMAIGNORE, 'README.md', checkId)).toEqual([]);
    },
  );

  // Both readers take a rule that names README.md and one UNICODE-STEGO check
  // as keeping that check on README.md out of a report, so the case above
  // fails on such a rule for each check of the family.
  it.each(UNICODE_STEGO_CHECKS.map((checkId) => [checkId]))(
    'reads `README.md:%s  # x` as a rule that keeps that check on README.md out of a report',
    (checkId) => {
      const line = `README.md:${checkId}  # x\n`;
      expect(parseRules(line).filter((r) => covers(r, 'README.md', checkId))).toHaveLength(1);
      expect(publishedErrorLines(line)).toEqual([]);
      expect(publishedCoveringLines(line, 'README.md', checkId)).toEqual([1]);
    },
  );

  it('is needed: package.json has an agent keyword and the project declares no agent identity file', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { keywords?: string[] };
    expect((pkg.keywords ?? []).some((k) => k.includes('agent') || k.includes('a2a'))).toBe(true);
    expect(IDENTITY_FILES.filter((f) => existsSync(join(ROOT, f)))).toEqual([]);
  });
});
