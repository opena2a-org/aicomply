/**
 * .hmaignore contract tests. HackMyAgent's AIM-001 check reports a project
 * whose package.json carries an agent keyword (aicomply lists `ai-agent`) and
 * that has no agent identity file. aicomply is a library and CLI that
 * classifies the input and output of other agents; it does not run as an
 * agent, so it has no identity of its own to declare. The .hmaignore file
 * records that once, as a rule naming the one check on the one file, so every
 * other check still reads package.json and AIM-001 still applies anywhere else.
 */

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const HMAIGNORE = readFileSync(join(ROOT, '.hmaignore'), 'utf8');

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

  // Each line was confirmed against HackMyAgent 0.33.2: as the only rule of an
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
  });

  // Confirmed the same way: with each of these as the only rule, AIM-001 on
  // package.json is still reported. A check pattern without `*` has to equal
  // the whole check id, so a prefix or a suffix of AIM-001 names nothing.
  it.each([
    ['package.json:GIT-001  # x'],
    ['package.json:UNICODE-*  # x'],
    ['package.json:AIM  # x'],
    ['package.json:IM-001  # x'],
    ['src/index.ts:AIM-001  # x'],
    ['*.json:AIM-001  # x'],
    ['*.json'],
    ['pack'],
    ['pack/'],
    ['package-lock.json'],
    ['!GIT-001'],
    ['!UNICODE-STEGO-*'],
    ['!AIM-00?'],
    ['!AIM-00'],
    ['!IM-001'],
  ])('reads `%s` as a rule that leaves AIM-001 on package.json reported', (line) => {
    expect(identityRules(`${line}\n`)).toEqual([]);
  });

  it('is needed: package.json has an agent keyword and the project declares no agent identity file', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { keywords?: string[] };
    expect((pkg.keywords ?? []).some((k) => k.includes('agent') || k.includes('a2a'))).toBe(true);
    expect(IDENTITY_FILES.filter((f) => existsSync(join(ROOT, f)))).toEqual([]);
  });
});
