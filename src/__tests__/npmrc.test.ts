/**
 * The repository .npmrc sets onnxruntime-node-install=skip. onnxruntime-node,
 * which @nanomind/daemon and hackmyagent install, otherwise downloads the CUDA
 * execution provider from api.nuget.org in its install script on linux/x64.
 * npm hands the key to scripts as npm_config_onnxruntime_node_install, and
 * npm 11.19.0 warns that a project key it does not know will stop working in
 * its next major version, so the hand-over is checked with the npm on the
 * PATH.
 *
 * Each installed install script is run with the platform reported as
 * linux/x64 and https.get and https.request replaced by a stub that records
 * the URL and exits: forcing the install shows the script would download,
 * and the .npmrc value shows it then exits without a request.
 */

import { spawnSync } from 'child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const KEY = 'onnxruntime-node-install';
const REQUEST_EXIT = 3;

/** The `key=value` settings of the repository .npmrc. */
function npmrc(): Map<string, string> {
  const settings = new Map<string, string>();
  for (const line of readFileSync(join(ROOT, '.npmrc'), 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    settings.set(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim());
  }
  return settings;
}

/**
 * This process's environment without npm settings or the install script's
 * own switches, so a value an npm that started the test passes down cannot
 * answer for the .npmrc.
 */
function cleanEnv(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        entry[1] !== undefined && !/^(npm_config_|ONNXRUNTIME_NODE_INSTALL)/i.test(entry[0]),
    ),
  );
}

const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8')) as {
  packages: Record<string, unknown>;
};

/** Lockfile path of every installed copy of onnxruntime-node. */
const onnxruntimeCopies = Object.keys(lock.packages).filter(
  (path) => path === 'node_modules/onnxruntime-node' || path.endsWith('/node_modules/onnxruntime-node'),
);

describe('.npmrc', () => {
  let scratch: string;
  let preload: string;

  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), 'npmrc-'));
    preload = join(scratch, 'linux-x64-no-requests.js');
    writeFileSync(
      preload,
      [
        "const os = require('os');",
        "const https = require('https');",
        "os.platform = () => 'linux';",
        "os.arch = () => 'x64';",
        'https.get = https.request = (url) => {',
        "  require('fs').writeSync(1, 'REQUEST ' + String(url && url.href ? url.href : url) + '\\n');",
        `  process.exit(${REQUEST_EXIT});`,
        '};',
        '',
      ].join('\n'),
    );
  });

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true });
  });

  it(`sets ${KEY} to skip`, () => {
    expect(npmrc().get(KEY)).toBe('skip');
  });

  it(`hands ${KEY} to the scripts npm runs in the repository`, () => {
    const run = spawnSync(
      'npm',
      ['exec', '--offline', '-c', 'node -p process.env.npm_config_onnxruntime_node_install'],
      { cwd: ROOT, env: cleanEnv(), encoding: 'utf8' },
    );
    expect(run.error).toBeUndefined();
    expect(run.status).toBe(0);
    expect(run.stdout.trim()).toBe('skip');
  });

  it('finds onnxruntime-node in package-lock.json', () => {
    expect(onnxruntimeCopies.length).toBeGreaterThan(0);
  });

  it.each(onnxruntimeCopies)('%s: the install script makes no request on linux/x64 with the .npmrc value', (path) => {
    const dir = join(ROOT, path);
    const install = (value: string) =>
      spawnSync(process.execPath, ['-r', preload, join(dir, 'script', 'install.js')], {
        cwd: dir,
        env: { ...cleanEnv(), npm_config_onnxruntime_node_install: value },
        encoding: 'utf8',
      });

    const forced = install('true');
    expect(forced.status).toBe(REQUEST_EXIT);
    expect(forced.stdout).toContain('REQUEST https://api.nuget.org/');

    const skipped = install(npmrc().get(KEY) ?? '');
    expect(skipped.stdout).not.toContain('REQUEST');
    expect(skipped.status).toBe(0);
  });
});
