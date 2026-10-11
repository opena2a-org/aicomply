/**
 * Docs contract tests. A section of the tracked Markdown states what the
 * component does in its first sentence, so a "why this exists" heading or
 * phrase is rejected wherever it appears, including when a line wrap splits it.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';

const ROOT = join(__dirname, '..', '..');
const WHY_THIS_EXISTS = /\bwhy\s+this\s+exists\b/gi;

/**
 * Every Markdown file git tracks under `root`, relative to it. When git
 * cannot list them, the error names the reason, such as a source archive
 * that is not a git checkout, in place of the raw `Command failed` text.
 */
function trackedMarkdown(root = ROOT, env: NodeJS.ProcessEnv = process.env): string[] {
  let listed: string;
  try {
    listed = execFileSync('git', ['ls-files', '-z', '--', '*.md'], {
      cwd: root,
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    throw new Error(gitFailure(root, err));
  }
  return listed.split('\0').filter(Boolean);
}

/** Why `git ls-files` failed in `root`, and what to do about it. */
function gitFailure(root: string, err: unknown): string {
  const e = err as NodeJS.ErrnoException & { stderr?: string };
  if (e.code === 'ENOENT') {
    return `git is not on PATH; the docs test needs it to list the Markdown git tracks in ${root}. Install git and run the test again.`;
  }
  const said = String(e.stderr || e.message).trim().split('\n')[0];
  if (/not a git repository/i.test(said)) {
    return `${root} is not a git checkout, so the docs test cannot list the Markdown git tracks (git: ${said}). Run the test from a git clone of the repository.`;
  }
  return `git ls-files failed in ${root}, so the docs test cannot list the Markdown git tracks (git: ${said}).`;
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

  it('names a tree that is not a git checkout in place of the raw git error', () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'aicomply-docs-')));
    // Stop git at `dir` so a repository above the temporary directory is not found.
    const env: NodeJS.ProcessEnv = { ...process.env, GIT_CEILING_DIRECTORIES: dirname(dir) };
    delete env.GIT_DIR;
    delete env.GIT_WORK_TREE;
    try {
      expect(() => trackedMarkdown(dir, env)).toThrow(
        `${dir} is not a git checkout, so the docs test cannot list the Markdown git tracks`,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
