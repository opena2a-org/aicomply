/**
 * Lint contract tests. `npm run lint` is `tsc --noEmit` and the repository has
 * no ESLint configuration, so an ESLint directive comment switches nothing off
 * and only suggests a linter that is not there. If ESLint is ever configured,
 * the directives mean something again and this check steps aside.
 */

import { readFileSync, readdirSync } from 'fs';
import { join, relative } from 'path';

const ROOT = join(__dirname, '..', '..');

/** Where the JavaScript and TypeScript sources live, besides the root config files. */
const SOURCE_DIRS = ['src', 'scripts', 'bench'];
const SOURCE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const ESLINT_DIRECTIVE = /\beslint-(?:disable|enable|env)\b/;

function hasEslintConfig(): boolean {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  return (
    'eslintConfig' in pkg ||
    readdirSync(ROOT).some((name) => /^\.eslintrc(?:\..+)?$|^eslint\.config\.[cm]?[jt]s$/.test(name))
  );
}

function sourceFiles(dir: string, recurse = true): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return recurse ? sourceFiles(path) : [];
    return SOURCE_FILE.test(entry.name) ? [path] : [];
  });
}

describe('lint', () => {
  it('carries no ESLint directive while the repository has no ESLint configuration', () => {
    if (hasEslintConfig()) return;
    const files = [
      ...sourceFiles(ROOT, false),
      ...SOURCE_DIRS.flatMap((dir) => sourceFiles(join(ROOT, dir))),
    ];
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
});
