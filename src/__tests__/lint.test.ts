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
 * test files are read like any other: the directive pattern lives in
 * lint-helpers.ts and is written so that it does not match itself.
 */
function directiveOffenders(): string[] {
  return eslintOffenders(allSourceFiles());
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
