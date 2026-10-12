/**
 * Lint contract tests. `npm run lint` is `tsc --noEmit` and the repository has
 * no ESLint configuration, so an ESLint directive comment switches nothing off
 * and only suggests a linter that is not there. If ESLint is ever configured,
 * the directives mean something again and this check steps aside.
 *
 * A raw line or paragraph separator (U+2028, U+2029) in a JavaScript,
 * TypeScript or Python source file reads as a line break in many editors and
 * tools, so the sources write it as the escape instead.
 */

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join, relative, sep, win32, type PlatformPath } from 'path';

const ROOT = join(__dirname, '..', '..');

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
const ESLINT_DIRECTIVE = /\beslint-(?:disable|enable|env)\b/;
const SEPARATOR = /[\u{2028}\u{2029}]/u;

function hasEslintConfig(): boolean {
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
function relativePath(
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

function allSourceFiles(): string[] {
  return [...sourceFiles(ROOT, SOURCE_FILE, false), ...SOURCE_DIRS.flatMap((dir) => sourceFiles(join(ROOT, dir)))];
}

function pythonSourceFiles(root = ROOT): string[] {
  return [
    ...sourceFiles(join(root, PYTHON_ROOT), PYTHON_FILE, false),
    ...PYTHON_DIRS.flatMap((dir) => sourceFiles(join(root, dir), PYTHON_FILE)),
  ];
}

function separatorOffenders(files: string[], root = ROOT): string[] {
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

describe('lint', () => {
  it('carries no ESLint directive while the repository has no ESLint configuration', () => {
    if (hasEslintConfig()) return;
    const files = allSourceFiles();
    expect(files.length).toBeGreaterThan(0);
    const offenders = files
      .filter((file) => file !== __filename)
      .flatMap((file) =>
        readFileSync(file, 'utf8')
          .split('\n')
          .flatMap((line, i) => (ESLINT_DIRECTIVE.test(line) ? [`${relativePath(ROOT, file)}:${i + 1}`] : [])),
      );
    expect(offenders).toEqual([]);
  });

  it('carries no raw line or paragraph separator in a JavaScript, TypeScript or Python source, which many editors and tools show as a line break', () => {
    const scriptFiles = allSourceFiles();
    const pythonFiles = pythonSourceFiles();
    expect(scriptFiles.length).toBeGreaterThan(0);
    expect(pythonFiles.length).toBeGreaterThan(0);
    expect(separatorOffenders([...scriptFiles, ...pythonFiles])).toEqual([]);
  });

  it('reads a Python source or stub at the python/ root and under python/src, python/tests and python/bench, and no other directory or suffix there', () => {
    const root = mkdtempSync(join(tmpdir(), 'aicomply-lint-'));
    try {
      const read = [
        'python/conftest.py',
        'python/stubs.pyi',
        'python/src/pkg/mod.py',
        'python/src/pkg/mod.pyi',
        'python/tests/test_mod.py',
        'python/bench/measure.py',
      ];
      const skipped = [
        'python/.venv/lib/site.py',
        'python/build/lib/mod.py',
        'python/README.md',
        'python/src/pkg/__pycache__/mod.cpython-312.pyc',
        'python/tests/test_mod.py.orig',
      ];
      for (const path of [...read, ...skipped]) {
        mkdirSync(join(root, dirname(path)), { recursive: true });
        writeFileSync(join(root, path), `x = 1  # ${String.fromCharCode(0x2028)}\n`);
      }
      const offenders = separatorOffenders(pythonSourceFiles(root), root);
      expect([...offenders].sort()).toEqual(
        read.map((path) => `${path}:1: write the character as the escape \\u2028`).sort(),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('names an offending file with forward slashes on a platform that separates paths with backslashes', () => {
    const root = 'C:\\t';
    expect(relativePath(root, win32.join(root, 'python/src/pkg/mod.py'), win32)).toBe('python/src/pkg/mod.py');
  });
});
