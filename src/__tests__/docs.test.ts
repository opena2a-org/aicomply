/**
 * Docs contract tests. A section of the tracked Markdown states what the
 * component does in its first sentence, so a "why this exists" heading or
 * phrase is rejected wherever it appears, including when a line wrap splits it.
 * The Markdown also gives one account of the semantic Guard: a claim that its
 * model has not shipped or that `comply()` is always regex-only is rejected.
 * A release named as the target of work still to come must be one the
 * package version has not yet reached.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';

const ROOT = join(__dirname, '..', '..');
const WHY_THIS_EXISTS = /\bwhy\s+this\s+exists\b/gi;

/**
 * Claims that the Guard model has not shipped or that `comply()` is always
 * regex-only. The model has shipped and `@nanomind/daemon` serves it, so the
 * Guard is a preview that is on whenever a daemon is reachable.
 */
const STALE_GUARD_CLAIMS = [
  /\bno\s+NanoMind-Guard\s+binary\s+is\s+published\b/gi,
  /\bGuard\s+binary\s+depends\s+on\s+NanoMind\b/gi,
  /\bmodel\s+binary\s+depends\s+on\s+external\s+training\b/gi,
  /\buntil\s+(?:that|the\s+Guard|Guard)\s+ships\b/gi,
  /`comply\(\)`\s+is\s+regex-only\b/gi,
  /\bPhase\s+2b\s+training\b/gi,
];

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

/** `file:line` for each match of `re` in `text`. */
function occurrences(re: RegExp, file: string, text: string): string[] {
  return [...text.matchAll(re)].map(
    (m) => `${file}:${text.slice(0, m.index).split('\n').length}`,
  );
}

/** `file:line` for each occurrence of the phrase in `text`. */
function whyThisExists(file: string, text: string): string[] {
  return occurrences(WHY_THIS_EXISTS, file, text);
}

/** `file:line` for each stale Guard claim in `text`, in pattern order. */
function staleGuardClaims(file: string, text: string): string[] {
  return STALE_GUARD_CLAIMS.flatMap((re) => occurrences(re, file, text));
}

/** A release named as the target of work still to come, such as "deferred to v1.1" or "Target: 1.1". */
const RELEASE_TARGET =
  /\b(?:deferred|planned|scheduled|slated|targeted)\s+(?:to|for|in)\s+v?(\d+\.\d+(?:\.\d+)?)\b|\btarget\s*:\s*v?(\d+\.\d+(?:\.\d+)?)\b/gi;

function versionParts(version: string): number[] {
  const [major = 0, minor = 0, patch = 0] = version.split('.').map(Number);
  return [major, minor, patch];
}

/** True when release `a` is at or before release `b`. */
function atOrBefore(a: string, b: string): boolean {
  const x = versionParts(a);
  const y = versionParts(b);
  for (let i = 0; i < 3; i += 1) {
    if (x[i] !== y[i]) return x[i] < y[i];
  }
  return true;
}

/**
 * `file:line (version)` for each release target in `text` that `current`
 * has already reached, so the promised work can no longer land there.
 */
function passedTargets(file: string, text: string, current: string): string[] {
  return [...text.matchAll(RELEASE_TARGET)]
    .filter((m) => atOrBefore(m[1] ?? m[2], current))
    .map((m) => `${file}:${text.slice(0, m.index).split('\n').length} (${m[1] ?? m[2]})`);
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

  it('does not say the Guard model has not shipped or that comply() is regex-only', () => {
    const files = trackedMarkdown();
    expect(files).toEqual(expect.arrayContaining(['README.md', 'SECURITY.md']));
    const offenders = files.flatMap((file) =>
      staleGuardClaims(file, readFileSync(join(ROOT, file), 'utf8')),
    );
    expect(offenders).toEqual([]);
  });

  it('names no release target that the package version has already passed', () => {
    const { version } = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      version: string;
    };
    const offenders = trackedMarkdown().flatMap((file) =>
      passedTargets(file, readFileSync(join(ROOT, file), 'utf8'), version),
    );
    expect(offenders).toEqual([]);
  });

  it('flags a stale Guard claim across a line wrap and leaves the preview account alone', () => {
    expect(
      staleGuardClaims('a.md', 'but no NanoMind-Guard binary is published yet.\nUntil then `comply()`\nis regex-only.'),
    ).toEqual(['a.md:1', 'a.md:2']);
    expect(staleGuardClaims('b.md', 'the real Guard binary depends on NanoMind\nPhase 2b training.')).toEqual([
      'b.md:1',
      'b.md:2',
    ]);
    expect(
      staleGuardClaims(
        'c.md',
        'The Guard is a preview. `comply()` runs regex-only whenever no daemon is reachable, until a recalibrated model ships.',
      ),
    ).toEqual([]);
  });

  it('flags a passed target in either phrasing and across a line wrap, not a later one', () => {
    expect(passedTargets('a.md', 'Not stripped - deferred to v1.1.\n', '2.2.3')).toEqual([
      'a.md:1 (1.1)',
    ]);
    expect(passedTargets('b.md', 'A backend.\nTarget:\n2.2 with an option.', '2.2.3')).toEqual([
      'b.md:2 (2.2)',
    ]);
    expect(passedTargets('c.md', 'Planned for 2.2.3.', '2.2.3')).toEqual(['c.md:1 (2.2.3)']);
    expect(passedTargets('d.md', 'Target: 2.3, deferred to v3.0.', '2.2.3')).toEqual([]);
    expect(passedTargets('e.md', 'Only Base64 is decoded in 1.0. It targets 1.1 users.', '2.2.3')).toEqual([]);
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
