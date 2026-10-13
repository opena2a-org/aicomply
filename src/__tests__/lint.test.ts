/**
 * Lint contract tests. `npm run lint` is `tsc --noEmit` and the repository has
 * no ESLint configuration, so an ESLint directive comment switches nothing off
 * and only suggests a linter that is not there. If ESLint is ever configured,
 * the directives mean something again and this check steps aside.
 *
 * A raw line or paragraph separator (U+2028, U+2029) in a JavaScript,
 * TypeScript or Python source file reads as a line break in many editors and
 * tools, so the sources write it as the escape instead.
 *
 * lint-windows-paths.test.ts runs the same helpers with a `path` module that
 * separates paths with backslashes, as on Windows.
 */

import fs from 'fs';
import { join, win32 } from 'path';
import {
  PYTHON_TREE,
  allSourceFiles,
  eslintOffenders,
  hasEslintConfig,
  pythonSourceFiles,
  relativePath,
  separatorOffenders,
  withSourceTree,
} from './lint-helpers';

/**
 * Each ESLint directive in the JavaScript and TypeScript sources. The lint
 * test files are read like any other: the directive patterns live in
 * lint-helpers.ts and are written so that they do not match themselves.
 */
function directiveOffenders(): string[] {
  return eslintOffenders(allSourceFiles());
}

/** A block comment opening, written in two parts so this file carries none of the comments it tests. */
const OPEN = ['/', '*'].join('');

/** The ESLint directives in `comment`, written as the second line of src/mod.ts under a temporary root. */
function offendersIn(comment: string): string[] {
  return withSourceTree(['src/mod.ts'], `const x = 1;\n${comment}\nconst y = 2;\n`, (root) =>
    eslintOffenders([join(root, 'src', 'mod.ts')], root),
  );
}

describe('lint', () => {
  it('carries no ESLint directive while the repository has no ESLint configuration', () => {
    if (hasEslintConfig()) return;
    expect(allSourceFiles().length).toBeGreaterThan(0);
    expect(directiveOffenders()).toEqual([]);
  });

  it('reads the lint test files themselves for an ESLint directive', () => {
    const names = ['lint.test.ts', 'lint-helpers.ts', 'lint-windows-paths.test.ts'];
    const lintFiles = names.map((name) => join(__dirname, name));
    const directive = ['eslint', 'disable'].join('-');
    const { readFileSync } = fs;
    const read = jest
      .spyOn(fs, 'readFileSync')
      .mockImplementation(((file: string, encoding: BufferEncoding) =>
        lintFiles.includes(file)
          ? `const x = 1;\n// ${directive} no-console\n`
          : readFileSync(file, encoding)) as typeof readFileSync);
    try {
      expect(directiveOffenders()).toEqual(expect.arrayContaining(names.map((name) => `src/__tests__/${name}:2`)));
    } finally {
      read.mockRestore();
    }
  });

  // ESLint reads each of these block comments as a directive that sets rules
  // or declares globals, so the check names the line it opens on.
  it.each([
    ['a rule setting', `${OPEN} eslint no-console: "off" */`],
    ['a rule setting without spaces', `${OPEN}eslint no-console:0*/`],
    ['a rule setting whose first word is on the next line', `${OPEN}\n  eslint no-console: "off"\n*/`],
    ['a global', `${OPEN} global window */`],
    ['globals', `${OPEN}globals window, document */`],
    ['an exported name', `${OPEN} exported main */`],
  ])('names a block comment that carries %s', (_kind, comment) => {
    expect(offendersIn(comment)).toEqual(['src/mod.ts:2']);
  });

  it.each([
    ['documentation', `${OPEN}* eslint no-console: "off" */`],
    ['a word that only starts like a directive', `${OPEN} globalThis is read here */`],
    ['the word later in its text', `${OPEN} see the eslint docs */`],
  ])('names no block comment that carries %s, which ESLint does not read as a directive', (_kind, comment) => {
    expect(offendersIn(comment)).toEqual([]);
  });

  it('carries no raw line or paragraph separator in a JavaScript, TypeScript or Python source, which many editors and tools show as a line break', () => {
    const scriptFiles = allSourceFiles();
    const pythonFiles = pythonSourceFiles();
    expect(scriptFiles.length).toBeGreaterThan(0);
    expect(pythonFiles.length).toBeGreaterThan(0);
    expect(separatorOffenders([...scriptFiles, ...pythonFiles])).toEqual([]);
  });

  it('reads a Python source or stub at the python/ root and under python/src, python/tests and python/bench, and no other directory or suffix there', () => {
    const { read, skipped } = PYTHON_TREE;
    const offenders = withSourceTree([...read, ...skipped], `x = 1  # ${String.fromCharCode(0x2028)}\n`, (root) =>
      separatorOffenders(pythonSourceFiles(root), root),
    );
    expect([...offenders].sort()).toEqual(
      read.map((path) => `${path}:1: write the character as the escape \\u2028`).sort(),
    );
  });

  it('names an offending file with forward slashes on a platform that separates paths with backslashes', () => {
    const root = 'C:\\t';
    expect(relativePath(root, win32.join(root, 'python/src/pkg/mod.py'), win32)).toBe('python/src/pkg/mod.py');
  });
});
