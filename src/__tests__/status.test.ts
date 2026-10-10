/**
 * STATUS.md contract tests. STATUS.md records the decisions a scan would
 * otherwise report as open items. HackMyAgent's AIM-001 ("No agent identity
 * declaration") fires on this repository because it looks for an agent
 * identity file at the root; aicomply is a classifier library and carries none
 * by design. The rationale must stay in STATUS.md, and must stay true: if an
 * identity file is ever added, the section has to be rewritten with it.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const STATUS = readFileSync(join(ROOT, 'STATUS.md'), 'utf8');

/** The identity files HackMyAgent AIM-001 looks for at the project root. */
const IDENTITY_FILES = ['agent-card.json', 'agent.json', 'aim.json'];

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

  it('matches the tree: no identity declaration file at the repository root', () => {
    for (const file of IDENTITY_FILES) {
      expect({ file, exists: existsSync(join(ROOT, file)) }).toEqual({ file, exists: false });
    }
  });
});
