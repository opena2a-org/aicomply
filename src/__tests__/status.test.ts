/**
 * STATUS.md contract tests. STATUS.md records the decisions a scan would
 * otherwise report as open items. HackMyAgent's AIM-001 ("No agent identity
 * declaration") fires on this repository because package.json carries an
 * agent keyword and no agent identity file exists at the root or under
 * `.well-known/`; aicomply is a classifier library and carries none by design.
 * The rationale must stay in STATUS.md, and must stay true: if an identity
 * file is ever added, an `agentCard` or `a2a` field added to package.json, or
 * the keyword removed, the section has to be rewritten with it.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const STATUS = readFileSync(join(ROOT, 'STATUS.md'), 'utf8');

/** The identity files HackMyAgent AIM-001 looks for, relative to the project root. */
const IDENTITY_FILES = [
  'agent-card.json',
  'agent.json',
  'aim.json',
  '.well-known/agent-card.json',
  '.well-known/agent.json',
  '.well-known/aim.json',
];

/**
 * HackMyAgent raises AIM-001 for a package whose package.json has one of these
 * fields, or a keyword that contains `agent` or `a2a`.
 */
const AGENT_FIELDS = ['agentCard', 'a2a'];
const AGENT_KEYWORD = /agent|a2a/;

/** Body of the `## ` section whose heading matches `re`, or null. */
function section(re: RegExp): string | null {
  const lines = STATUS.split('\n');
  const start = lines.findIndex((l) => l.startsWith('## ') && re.test(l));
  if (start < 0) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith('## '));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

describe('STATUS.md', () => {
  it('documents why aicomply carries no agent identity declaration (AIM-001)', () => {
    const body = section(/agent identity/i);
    expect(body).not.toBeNull();
    expect(body).toContain('AIM-001');
    for (const file of IDENTITY_FILES) expect(body).toContain(`\`${file}\``);
    // The section names the command that reproduces the finding.
    expect(body).toContain('npx hackmyagent secure --ci .');
  });

  it('matches the tree: no identity declaration file at the root or under .well-known/', () => {
    for (const file of IDENTITY_FILES) {
      expect({ file, exists: existsSync(join(ROOT, file)) }).toEqual({ file, exists: false });
    }
  });

  it('names the package.json keyword that makes AIM-001 apply', () => {
    const body = section(/agent identity/i);
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { keywords: string[] };
    const agentKeywords = pkg.keywords.filter((keyword) => AGENT_KEYWORD.test(keyword));
    expect(agentKeywords).not.toEqual([]);
    expect(body).toContain('`keywords`');
    for (const keyword of agentKeywords) expect(body).toContain(`\`${keyword}\``);
  });

  it('has neither agent field in package.json, so the keyword is the only AIM-001 trigger', () => {
    const body = section(/agent identity/i);
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
    for (const field of AGENT_FIELDS) {
      expect(body).toContain(`\`${field}\``);
      expect({ field, present: field in pkg }).toEqual({ field, present: false });
    }
  });

  it('points only at paths that are in the repository', () => {
    // Backticked directories (`dir/`) and relative link targets (](./file)).
    const paths = [
      ...Array.from(STATUS.matchAll(/`([\w.-]+(?:\/[\w.-]+)*)\/`/g), (m) => m[1]),
      ...Array.from(STATUS.matchAll(/\]\(\.\/([^)#]+)[^)]*\)/g), (m) => m[1]),
    ];
    for (const path of paths) {
      expect({ path, exists: existsSync(join(ROOT, path)) }).toEqual({ path, exists: true });
    }
  });
});
