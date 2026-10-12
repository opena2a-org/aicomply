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

import { readFileSync, readdirSync } from 'fs';
import { join, relative } from 'path';

const ROOT = join(__dirname, '..', '..');

/** Where the JavaScript and TypeScript sources live, besides the root config files. */
const SOURCE_DIRS = ['src', 'scripts', 'bench'];
const SOURCE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
/** Where the Python sources live. */
const PYTHON_DIRS = ['python/src', 'python/tests', 'python/bench'];
const PYTHON_FILE = /\.py$/;
const ESLINT_DIRECTIVE = /\beslint-(?:disable|enable|env)\b/;
const SEPARATOR = /[\u{2028}\u{2029}]/u;

function hasEslintConfig(): boolean {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  return (
    'eslintConfig' in pkg ||
    readdirSync(ROOT).some((name) => /^\.eslintrc(?:\..+)?$|^eslint\.config\.[cm]?[jt]s$/.test(name))
  );
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

function pythonSourceFiles(): string[] {
  return PYTHON_DIRS.flatMap((dir) => sourceFiles(join(ROOT, dir), PYTHON_FILE));
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
          .flatMap((line, i) => (ESLINT_DIRECTIVE.test(line) ? [`${relative(ROOT, file)}:${i + 1}`] : [])),
      );
    expect(offenders).toEqual([]);
  });

  it('carries no raw line or paragraph separator in a JavaScript, TypeScript or Python source, which many editors and tools show as a line break', () => {
    const scriptFiles = allSourceFiles();
    const pythonFiles = pythonSourceFiles();
    expect(scriptFiles.length).toBeGreaterThan(0);
    expect(pythonFiles.length).toBeGreaterThan(0);
    const offenders = [...scriptFiles, ...pythonFiles].flatMap((file) =>
      readFileSync(file, 'utf8')
        .split('\n')
        .flatMap((line, i) => {
          const found = SEPARATOR.exec(line);
          if (!found) return [];
          const escape = `\\u${found[0].charCodeAt(0).toString(16)}`;
          return [`${relative(ROOT, file)}:${i + 1}: write the character as the escape ${escape}`];
        }),
    );
    expect(offenders).toEqual([]);
  });
});
