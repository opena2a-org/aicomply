/**
 * Docs contract tests. A section of the tracked Markdown states what the
 * component does in its first sentence, so a "why this exists" heading or
 * phrase is rejected wherever it appears, including when a line wrap splits it.
 * The Markdown also gives one account of the semantic Guard: a claim that its
 * model has not shipped or that `comply()` is always regex-only is rejected.
 * A release named as the target of work still to come must be one the
 * package version has not yet reached.
 * The tracked Markdown also points readers only at a change record the
 * repository has: a CHANGELOG mention needs a tracked CHANGELOG file.
 * The 2.3.0 release notes lead with the exit-code change, repeat the README's
 * staged-diff gate line, and end with the known issues, whose fleet entry
 * names the package that is not listed as the one without a fleet signal and
 * does not say the threshold does not apply against the production Registry.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { basename, dirname, join } from 'path';

const ROOT = join(__dirname, '..', '..');
const WHY_THIS_EXISTS = /\bwhy\s+this\s+exists\b/gi;
const CHANGELOG = /\bchangelog\b/gi;
const RELEASES = 'https://github.com/opena2a-org/aicomply/releases';

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

/**
 * Why `git ls-files` failed in `root`, and what to do about it. A `root` that
 * is not a directory fails to start git with the same ENOENT as a git that is
 * not on PATH, so it is checked first.
 */
function gitFailure(root: string, err: unknown): string {
  if (!statSync(root, { throwIfNoEntry: false })?.isDirectory()) {
    return `${root} is not a directory, so the docs test cannot list the Markdown git tracks. Pass the root of a git clone of the repository.`;
  }
  const e = err as NodeJS.ErrnoException & { stderr?: string };
  if (e.code === 'ENOENT') {
    return `git is not on PATH; the docs test needs it to list the Markdown git tracks in ${root}. Install git and run the test again.`;
  }
  const said = String(e.stderr || e.message).trim().split('\n')[0];
  if (/not a git repository/i.test(said)) {
    return `${root} is not a git checkout, so the docs test cannot list the Markdown git tracks (git: ${said}). Run the test from a git clone of the repository.`;
  }
  return (
    `git ls-files failed in ${root}, so the docs test cannot list the Markdown git tracks (git: ${said}). ` +
    `Run git ls-files in ${root} to see the whole error, fix what it reports and run the test again.`
  );
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

/** A pinned dependency entry for this package, such as `"@opena2a/aicomply": "1.0.0"`. */
const PINNED_VERSION = /"@opena2a\/aicomply"\s*:\s*"[~^]?(\d+\.\d+\.\d+)/g;

/**
 * `file:line (version)` for each pinned version in `text` from a major line
 * older than `current`, which the support policy in SECURITY.md no longer covers.
 */
function unsupportedPins(file: string, text: string, current: string): string[] {
  const [major] = versionParts(current);
  return [...text.matchAll(PINNED_VERSION)]
    .filter((m) => versionParts(m[1])[0] < major)
    .map((m) => `${file}:${text.slice(0, m.index).split('\n').length} (${m[1]})`);
}

/**
 * `file:line` for each CHANGELOG mention in `docs` (file name to text) when
 * `tracked` holds no CHANGELOG file, so a reader is never sent to a file
 * the repository and the published package do not carry.
 */
function changelogWithoutFile(tracked: string[], docs: Record<string, string>): string[] {
  if (tracked.some((file) => /^changelog(\.md)?$/i.test(basename(file)))) return [];
  return Object.entries(docs).flatMap(([file, text]) => occurrences(CHANGELOG, file, text));
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

  it('mentions a CHANGELOG only when the repository tracks one, and SECURITY.md names the release notes', () => {
    const files = trackedMarkdown();
    const docs = Object.fromEntries(
      files.map((file) => [file, readFileSync(join(ROOT, file), 'utf8')]),
    );
    expect(changelogWithoutFile(files, docs)).toEqual([]);
    expect(docs['SECURITY.md']).toContain(RELEASES);
  });

  it('flags a CHANGELOG mention only when no CHANGELOG file is tracked', () => {
    const docs = { 'SECURITY.md': 'Notes.\n\nSee the CHANGELOG entries.\n' };
    expect(changelogWithoutFile(['SECURITY.md'], docs)).toEqual(['SECURITY.md:3']);
    expect(changelogWithoutFile(['SECURITY.md', 'CHANGELOG.md'], docs)).toEqual([]);
    expect(changelogWithoutFile(['SECURITY.md'], { 'SECURITY.md': 'See the release notes.\n' })).toEqual([]);
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

  it('tells no reader to pin a version from a major line the package no longer supports', () => {
    const { version } = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      version: string;
    };
    const offenders = trackedMarkdown().flatMap((file) =>
      unsupportedPins(file, readFileSync(join(ROOT, file), 'utf8'), version),
    );
    expect(offenders).toEqual([]);
  });

  it('flags a pin from an older major line, with or without a range prefix, not a current one', () => {
    expect(unsupportedPins('a.md', 'Pin `"@opena2a/aicomply": "0.1.0"` (no caret).', '2.2.3')).toEqual([
      'a.md:1 (0.1.0)',
    ]);
    expect(unsupportedPins('b.md', 'Text.\n{ "@opena2a/aicomply": "^1.0.0" }', '2.2.3')).toEqual([
      'b.md:2 (1.0.0)',
    ]);
    expect(unsupportedPins('c.md', '"@opena2a/aicomply": "2.0.0"', '2.2.3')).toEqual([]);
    expect(unsupportedPins('d.md', 'Pin the exact version you tested.', '2.2.3')).toEqual([]);
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

  it('says git is not on PATH when git cannot be started', () => {
    const empty = realpathSync(mkdtempSync(join(tmpdir(), 'aicomply-docs-path-')));
    try {
      expect(() => trackedMarkdown(ROOT, { ...process.env, PATH: empty })).toThrow(
        `git is not on PATH; the docs test needs it to list the Markdown git tracks in ${ROOT}. Install git and run the test again.`,
      );
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it('names a root that does not exist in place of git missing from PATH', () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'aicomply-docs-')));
    const missing = join(dir, 'missing');
    try {
      expect(() => trackedMarkdown(missing)).toThrow(
        `${missing} is not a directory, so the docs test cannot list the Markdown git tracks. Pass the root of a git clone of the repository.`,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('names any other git error and how to see all of it', () => {
    const err = Object.assign(new Error('Command failed: git ls-files'), {
      stderr: 'fatal: unable to read index\nmore detail\n',
    });
    expect(gitFailure(ROOT, err)).toBe(
      `git ls-files failed in ${ROOT}, so the docs test cannot list the Markdown git tracks (git: fatal: unable to read index). ` +
        `Run git ls-files in ${ROOT} to see the whole error, fix what it reports and run the test again.`,
    );
  });
});

describe('2.3.0 release notes', () => {
  const notes = () => readFileSync(join(ROOT, 'docs', 'releases', '2.3.0.md'), 'utf8');
  const headings = () => notes().split('\n').filter((line) => line.startsWith('## '));

  it('open with the change of exit code for no input', () => {
    expect(headings()[0]).toBe('## Exit code change: no input exits 2');
  });

  it('show the staged-diff gate exactly as the README does', () => {
    const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
    const gate = readme.split('\n').find((line) => line.startsWith('git diff --cached |'));
    expect(gate).toBeDefined();
    expect(notes().split('\n')).toContain(gate);
  });

  it('end with the known issues, naming the supply-chain lookup defect', () => {
    expect(headings()[headings().length - 1]).toBe('## Known issues');
    const known = notes().slice(notes().indexOf('## Known issues'));
    expect(known).toContain('https://github.com/opena2a-org/aicomply/issues/205');
    expect(known).toContain("onRegistryUnknown: 'deny'");
  });

  it('name the package the open part of #205 leaves without a fleet signal', () => {
    const known = notes().slice(notes().indexOf('## Known issues'));
    // The cache sends the fleet request with a name and type for each package
    // listed in sourcePackages or passed to addSourcePackages(), so the entry
    // names the package that is not listed as the one without a fleet signal,
    // and does not say the threshold does not apply against the production
    // Registry as a whole. The patterns allow a line wrap inside the phrase.
    expect(known).toMatch(/package\s+that\s+is\s+not\s+listed/);
    expect(known).toContain('`addSourcePackages()`');
    expect(known).not.toMatch(/threshold\s+does\s+not\s+apply\s+against/i);
  });
});
