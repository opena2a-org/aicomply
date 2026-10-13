/**
 * The lint helpers run with a `path` module that answers as on Windows where
 * an offender is named: `relative` returns backslash-separated paths, `sep` is
 * a backslash, and `posix.relative` is given backslash-separated paths, in
 * which it finds no separator. So a place that names an offender with one of
 * these and without the forward-slash helper, or a helper that splits on the
 * wrong separator, fails here on Linux and macOS too.
 *
 * Node hands out the same module under `node:path`, and `posix` and `win32`
 * on their own under `path/posix`, `node:path/posix`, `path/win32` and
 * `node:path/win32`. Jest keys a mock by the id as written, so each of those
 * ids is mocked too and answers with the module above.
 *
 * A place that names an offender without a `relative` of this module, by
 * cutting the root off the front of the file's path for example, is not
 * caught: the files themselves are still written and read with the
 * platform's own `join`, so their paths carry that platform's separator.
 */

jest.mock('path', () => {
  const actual = jest.requireActual<typeof import('path')>('path');
  const backslashed = (path: string) => path.split(actual.sep).join('\\');
  const platform = {
    ...actual,
    sep: '\\',
    relative: (from: string, to: string) => backslashed(actual.relative(from, to)),
  };
  const posix = {
    ...actual.posix,
    relative: (from: string, to: string) => actual.posix.relative(backslashed(from), backslashed(to)),
  };
  // `win32` already returns backslash-separated paths. It is copied so that
  // every way to `posix` from here, `win32.posix` included, is the one above.
  const win32 = { ...actual.win32 };
  for (const paths of [platform, posix, win32]) Object.assign(paths, { posix, win32 });
  return platform;
});
jest.mock('node:path', () => jest.requireMock<typeof import('path')>('path'));
jest.mock('path/posix', () => jest.requireMock<typeof import('path')>('path').posix);
jest.mock('node:path/posix', () => jest.requireMock<typeof import('path')>('path').posix);
jest.mock('path/win32', () => jest.requireMock<typeof import('path')>('path').win32);
jest.mock('node:path/win32', () => jest.requireMock<typeof import('path')>('path').win32);

import { posix as nodePosix, relative as nodeRelative, sep as nodeSep } from 'node:path';
import { join, posix, relative, sep, win32 } from 'path';
import { relative as nodePosixRelative } from 'node:path/posix';
import { posix as nodeWin32Posix } from 'node:path/win32';
import { relative as posixRelative } from 'path/posix';
import { posix as win32Posix } from 'path/win32';
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
    expect(nodeSep).toBe('\\');
    expect(nodeRelative(__dirname, join(__dirname, 'a', 'b.py'))).toBe('a\\b.py');
  });

  it('runs with a path.posix that finds no separator in the paths it is given', () => {
    const file = join(__dirname, 'a', 'b.py');
    expect(posix.sep).toBe('/');
    expect(posix.relative(__dirname, file)).toBe(`../${file.split('/').join('\\')}`);
  });

  it.each([
    ['relative', relative],
    ['posix.relative', posix.relative],
    ['win32.relative', win32.relative],
    ['posix.posix.relative', posix.posix.relative],
    ['win32.posix.relative', win32.posix.relative],
    ['relative of node:path', nodeRelative],
    ['posix.relative of node:path', nodePosix.relative],
    ['relative of path/posix', posixRelative],
    ['relative of node:path/posix', nodePosixRelative],
    ['posix.relative of path/win32', win32Posix.relative],
    ['posix.relative of node:path/win32', nodeWin32Posix.relative],
  ])('gives the name of no Python file through %s without the forward-slash helper', (_route, relativeTo) => {
    const { read } = PYTHON_TREE;
    const named = withSourceTree(read, 'x = 1\n', (root) =>
      pythonSourceFiles(root).map((file) => relativeTo(root, file)),
    );
    expect(named).toHaveLength(read.length);
    expect(named.filter((name) => read.includes(name))).toEqual([]);
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
