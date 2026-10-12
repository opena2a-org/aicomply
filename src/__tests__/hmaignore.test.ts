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

interface IgnoreRule {
  line: number;
  rule: string;
  reason: string;
}

/**
 * The rule lines of .hmaignore: blank lines and whole-line comments are
 * skipped, and a `#` preceded by whitespace starts the reason, which is the
 * way HackMyAgent reads the file.
 */
function readRules(): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  const lines = readFileSync(join(ROOT, '.hmaignore'), 'utf8').split('\n');
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
    const matches = readRules().filter((r) => r.rule === 'package.json:AIM-001');
    expect(matches).toHaveLength(1);
    expect(matches[0].reason.length).toBeGreaterThan(0);
  });

  it('does not exclude package.json from every check, or AIM-001 from every file', () => {
    const broad = readRules().filter(
      (r) => r.rule === 'package.json' || /^!AIM-/i.test(r.rule) || /^package\.json:AIM-\*/i.test(r.rule),
    );
    expect(broad).toEqual([]);
  });

  it('is needed: package.json has an agent keyword and the project declares no agent identity file', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { keywords?: string[] };
    expect((pkg.keywords ?? []).some((k) => k.includes('agent') || k.includes('a2a'))).toBe(true);
    expect(IDENTITY_FILES.filter((f) => existsSync(join(ROOT, f)))).toEqual([]);
  });
});
