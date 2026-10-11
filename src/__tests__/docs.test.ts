/**
 * Docs contract tests. A section of the tracked Markdown states what the
 * component does in its first sentence, so a "why this exists" heading or
 * phrase is rejected wherever it appears, including when a line wrap splits it.
 */

import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const WHY_THIS_EXISTS = /\bwhy\s+this\s+exists\b/gi;

/** Every Markdown file git tracks, relative to the repository root. */
function trackedMarkdown(): string[] {
  return execFileSync('git', ['ls-files', '-z', '--', '*.md'], { cwd: ROOT, encoding: 'utf8' })
    .split('\0')
    .filter(Boolean);
}

/** `file:line` for each occurrence of the phrase in `text`. */
function whyThisExists(file: string, text: string): string[] {
  return [...text.matchAll(WHY_THIS_EXISTS)].map(
    (m) => `${file}:${text.slice(0, m.index).split('\n').length}`,
  );
}

describe('docs', () => {
  it('carries no "why this exists" heading or phrase in tracked Markdown', () => {
    const files = trackedMarkdown();
    expect(files).toContain('README.md');
    const offenders = files.flatMap((file) =>
      whyThisExists(file, readFileSync(join(ROOT, file), 'utf8')),
    );
    expect(offenders).toEqual([]);
  });

  it('flags the phrase as a heading, in any case and across a line wrap', () => {
    expect(whyThisExists('a.md', '# Title\n\n## Why this exists\n')).toEqual(['a.md:3']);
    expect(whyThisExists('b.md', 'That is WHY THIS\nEXISTS here.')).toEqual(['b.md:1']);
    expect(whyThisExists('c.md', 'It says what it does.\n')).toEqual([]);
  });
});
