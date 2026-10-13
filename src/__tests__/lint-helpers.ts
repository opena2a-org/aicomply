/**
 * Helpers for the lint contract tests: which source files are read, and how
 * an offender in one of them is named. They live outside the test files so
 * the same code can run once with the platform's own `path` module and once
 * with one that separates paths with backslashes, as on Windows.
 */

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join, relative, sep, type PlatformPath } from 'path';

export const ROOT = join(__dirname, '..', '..');

/** Where the JavaScript and TypeScript sources live, besides the root config files. */
const SOURCE_DIRS = ['src', 'scripts', 'bench'];
const SOURCE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
/**
 * Where the Python sources and stubs live: the `python/` root itself, read
 * without descending so a virtual environment or build output there is not
 * walked, and these directories, read in full.
 */
const PYTHON_ROOT = 'python';
const PYTHON_DIRS = ['python/src', 'python/tests', 'python/bench'];
const PYTHON_FILE = /\.pyi?$/;
/**
 * The comments ESLint reads as directives: one that switches rules off or on
 * again or names an environment, found anywhere on a line, and a block
 * comment whose text starts with the word `eslint`, `global`, `globals` or
 * `exported`, which sets rules or declares globals. The block comment is
 * matched across lines, since its first word may stand on the line after the
 * opening; a comment that opens with two asterisks is documentation, which
 * ESLint does not read. Neither pattern matches its own source.
 */
const ESLINT_DIRECTIVE = /\beslint-(?:disable|enable|env)\b/;
const ESLINT_CONFIG_COMMENT = /\/\*\s*(?:eslint|globals?|exported)(?=\s|\*\/)/g;
const SEPARATOR = /[\u{2028}\u{2029}]/u;

/**
 * A Python tree under a temporary root: the files the separator check reads,
 * and the files beside them it must leave alone.
 */
export const PYTHON_TREE = {
  read: [
    'python/conftest.py',
    'python/stubs.pyi',
    'python/src/pkg/mod.py',
    'python/src/pkg/mod.pyi',
    'python/tests/test_mod.py',
    'python/bench/measure.py',
  ],
  skipped: [
    'python/.venv/lib/site.py',
    'python/build/lib/mod.py',
    'python/README.md',
    'python/src/pkg/__pycache__/mod.cpython-312.pyc',
    'python/tests/test_mod.py.orig',
  ],
};

export function hasEslintConfig(): boolean {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  return (
    'eslintConfig' in pkg ||
    readdirSync(ROOT).some((name) => /^\.eslintrc(?:\..+)?$|^eslint\.config\.[cm]?[jt]s$/.test(name))
  );
}

/**
 * `file` relative to `root`, written with forward slashes on every platform,
 * so an offender reads the same on Windows as on Linux and macOS.
 */
export function relativePath(
  root: string,
  file: string,
  paths: Pick<PlatformPath, 'relative' | 'sep'> = { relative, sep },
): string {
  return paths.relative(root, file).split(paths.sep).join('/');
}

function sourceFiles(dir: string, pattern = SOURCE_FILE, recurse = true): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return recurse ? sourceFiles(path, pattern) : [];
    return pattern.test(entry.name) ? [path] : [];
  });
}

export function allSourceFiles(root = ROOT): string[] {
  return [...sourceFiles(root, SOURCE_FILE, false), ...SOURCE_DIRS.flatMap((dir) => sourceFiles(join(root, dir)))];
}

export function pythonSourceFiles(root = ROOT): string[] {
  return [
    ...sourceFiles(join(root, PYTHON_ROOT), PYTHON_FILE, false),
    ...PYTHON_DIRS.flatMap((dir) => sourceFiles(join(root, dir), PYTHON_FILE)),
  ];
}

/**
 * Each line of `files` that carries an ESLint directive, as `file:line`; a
 * block comment is named by the line it opens on.
 */
export function eslintOffenders(files: string[], root = ROOT): string[] {
  return files.flatMap((file) => {
    const text = readFileSync(file, 'utf8');
    const lines = new Set(text.split('\n').flatMap((line, i) => (ESLINT_DIRECTIVE.test(line) ? [i + 1] : [])));
    for (const comment of text.matchAll(ESLINT_CONFIG_COMMENT)) {
      lines.add(text.slice(0, comment.index).split('\n').length);
    }
    return [...lines].sort((a, b) => a - b).map((line) => `${relativePath(root, file)}:${line}`);
  });
}

/** Each line of `files` that carries a raw line or paragraph separator, with the escape to write instead. */
export function separatorOffenders(files: string[], root = ROOT): string[] {
  return files.flatMap((file) =>
    readFileSync(file, 'utf8')
      .split('\n')
      .flatMap((line, i) => {
        const found = SEPARATOR.exec(line);
        if (!found) return [];
        const escape = `\\u${found[0].charCodeAt(0).toString(16)}`;
        return [`${relativePath(root, file)}:${i + 1}: write the character as the escape ${escape}`];
      }),
  );
}

/**
 * Writes `content` to each of `files` under a new temporary directory, runs
 * `check` with that directory as the root, and removes the directory again.
 */
export function withSourceTree<T>(files: string[], content: string, check: (root: string) => T): T {
  const root = mkdtempSync(join(tmpdir(), 'aicomply-lint-'));
  try {
    for (const file of files) {
      mkdirSync(join(root, dirname(file)), { recursive: true });
      writeFileSync(join(root, file), content);
    }
    return check(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
