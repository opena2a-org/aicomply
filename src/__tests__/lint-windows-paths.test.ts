/**
 * The lint helpers run with a `path` module whose `relative` returns
 * backslash-separated paths and whose `sep` is a backslash, as on Windows, so
 * a place that names an offender without the forward-slash helper, or a
 * helper that splits on the wrong separator, fails here on Linux and macOS
 * too. The files themselves are still written and read with the platform's
 * own `join`.
 */

jest.mock('path', () => {
  const actual = jest.requireActual<typeof import('path')>('path');
  return {
    ...actual,
    sep: '\\',
    relative: (from: string, to: string) => actual.relative(from, to).split(actual.sep).join('\\'),
  };
});

import { join, relative, sep } from 'path';
import {
  PYTHON_TREE,
  allSourceFiles,
  eslintOffenders,
  pythonSourceFiles,
  separatorOffenders,
  withSourceTree,
} from './lint-helpers';

describe('lint, with paths separated by backslashes', () => {
  it('runs with a path module that separates paths with backslashes', () => {
    expect(sep).toBe('\\');
    expect(relative(__dirname, join(__dirname, 'a', 'b.py'))).toBe('a\\b.py');
  });

  it('names a Python offender with forward slashes', () => {
    const { read, skipped } = PYTHON_TREE;
    const offenders = withSourceTree([...read, ...skipped], `x = 1  # ${String.fromCharCode(0x2028)}\n`, (root) =>
      separatorOffenders(pythonSourceFiles(root), root),
    );
    expect([...offenders].sort()).toEqual(
      read.map((path) => `${path}:1: write the character as the escape \\u2028`).sort(),
    );
  });

  it('names a file that carries an ESLint directive with forward slashes', () => {
    const files = ['src/pkg/mod.ts', 'scripts/tool/run.mjs', 'bench/measure.ts'];
    const directive = ['eslint', 'disable'].join('-');
    const offenders = withSourceTree(files, `const x = 1;\n// ${directive} no-console\n`, (root) =>
      eslintOffenders(allSourceFiles(root), root),
    );
    expect([...offenders].sort()).toEqual(files.map((path) => `${path}:2`).sort());
  });
});
