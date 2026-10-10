/**
 * Jest config contract tests. ts-jest compiles a project `.js` file only when
 * the tsconfig sets `allowJs`, and warns on every run when one reaches it
 * without that option. The plain CommonJS setup files need no transform, so
 * they must stay outside the ts-jest patterns, while the ESM-only packages that
 * `transformIgnorePatterns` lets through must still be routed to ts-jest.
 * The table checks read only the `transform` map in jest.config.js, and a
 * preset can add patterns of its own, so the warning is also checked where it
 * shows up: in the output of a real run on a cold transform cache.
 */

import { spawnSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');

type TransformValue = string | [string, Record<string, unknown>];

interface JestConfig {
  setupFiles: string[];
  transform: Record<string, TransformValue>;
  transformIgnorePatterns: string[];
}

const config: JestConfig = require(join(ROOT, 'jest.config.js'));

function resolveRootDir(p: string): string {
  return p.replace('<rootDir>', ROOT);
}

/** The transformer Jest picks for `file`: the first `transform` key whose regex matches. */
function transformerFor(file: string): string | undefined {
  for (const [pattern, value] of Object.entries(config.transform)) {
    if (new RegExp(pattern).test(file)) {
      return Array.isArray(value) ? value[0] : value;
    }
  }
  return undefined;
}

function isTransformIgnored(file: string): boolean {
  return config.transformIgnorePatterns.some((pattern) => new RegExp(pattern).test(file));
}

describe('jest.config.js', () => {
  it('keeps every setup file out of ts-jest, so no allowJs warning is printed', () => {
    expect(config.setupFiles.length).toBeGreaterThan(0);
    for (const setupFile of config.setupFiles) {
      expect({ setupFile, transformer: transformerFor(resolveRootDir(setupFile)) }).toEqual({
        setupFile,
        transformer: undefined,
      });
    }
  });

  it('keeps other project-level .js files out of ts-jest', () => {
    expect(transformerFor(join(ROOT, 'jest.config.js'))).toBeUndefined();
    expect(transformerFor(join(ROOT, 'scripts', 'smoke-test.mjs'))).toBeUndefined();
  });

  it('still routes the ESM-only @noble and @scure packages through ts-jest', () => {
    const files = [
      join(ROOT, 'node_modules', '@noble', 'post-quantum', 'ml-dsa.js'),
      join(ROOT, 'node_modules', '@noble', 'hashes', 'sha3.js'),
      join(ROOT, 'node_modules', '@scure', 'base', 'index.mjs'),
    ];
    for (const file of files) {
      expect({ file, ignored: isTransformIgnored(file) }).toEqual({ file, ignored: false });
      expect({ file, transformer: transformerFor(file) }).toEqual({ file, transformer: 'ts-jest' });
    }
  });

  it('still routes TypeScript sources through ts-jest', () => {
    expect(transformerFor(join(ROOT, 'src', 'index.ts'))).toBe('ts-jest');
    expect(transformerFor(join(ROOT, 'src', '__tests__', 'readme.test.ts'))).toBe('ts-jest');
  });
});

describe('jest runner output', () => {
  it('prints no ts-jest allowJs warning on a cold cache', () => {
    const cacheDirectory = mkdtempSync(join(tmpdir(), 'aicomply-jest-cache-'));
    try {
      const env = { ...process.env };
      delete env.JEST_WORKER_ID; // the child is a runner of its own, not a worker of this one
      delete env.TS_JEST_LOG; // keeps ts-jest warnings on stderr
      const run = spawnSync(
        process.execPath,
        [
          join(ROOT, 'node_modules', 'jest', 'bin', 'jest.js'),
          'src/__tests__/readme.test.ts',
          '--cacheDirectory',
          cacheDirectory,
        ],
        { cwd: ROOT, env, encoding: 'utf8' },
      );
      const output = `${run.stdout}\n${run.stderr}`;
      if (run.status !== 0) throw new Error(`jest exited with ${run.status}:\n${output}`);
      const warnings = output.split('\n').filter((line) => line.includes('ts-jest[ts-compiler] (WARN)'));
      expect(warnings).toEqual([]);
    } finally {
      rmSync(cacheDirectory, { recursive: true, force: true });
    }
  }, 180_000);
});
