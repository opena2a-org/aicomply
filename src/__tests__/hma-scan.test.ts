/**
 * `npm run hma:scan` runs `scripts/hma-scan.mjs`, the HackMyAgent scan of this
 * repository. The .hmaignore rule `package.json:AIM-001` is a `<path>:<check>`
 * rule, a form HackMyAgent reads from 0.33.0 on: HackMyAgent 0.30.0 to 0.32.0
 * take the whole line for a path that names no file and still report AIM-001
 * on package.json. These tests run a copy of the script beside a stand-in
 * `node_modules/hackmyagent`, so they pin which versions it refuses and the
 * command it runs, without running a scan.
 */

import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(__dirname, '..', '..');
const SCRIPT = join(ROOT, 'scripts', 'hma-scan.mjs');

/** The numeric `major.minor.patch` at the start of a version or a `^`/`~` range. */
function floor(version: string): number[] {
  const m = /^[\^~]?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!m) throw new Error(`not a version: ${version}`);
  return m.slice(1, 4).map(Number);
}

function compare(a: number[], b: number[]): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

const MINIMUM = [0, 33, 0];

describe('hma:scan', () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aicomply-hma-scan-'));
    mkdirSync(join(root, 'scripts'));
    copyFileSync(SCRIPT, join(root, 'scripts', 'hma-scan.mjs'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  /**
   * A stand-in hackmyagent package at `version` whose executable prints the
   * arguments and working directory it was given, then exits with
   * FAKE_HMA_EXIT.
   */
  function installHackMyAgent(version: string): void {
    const dir = join(root, 'node_modules', 'hackmyagent');
    mkdirSync(join(dir, 'dist'), { recursive: true });
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'hackmyagent', version, bin: { hackmyagent: 'dist/cli.js' } }),
    );
    writeFileSync(
      join(dir, 'dist', 'cli.js'),
      'process.stdout.write(JSON.stringify({ args: process.argv.slice(2), cwd: process.cwd() }));\n' +
        'process.exit(Number(process.env.FAKE_HMA_EXIT || 0));\n',
    );
  }

  function scan(args: string[] = [], exit = 0): { status: number | null; stdout: string; stderr: string } {
    const run = spawnSync(process.execPath, [join(root, 'scripts', 'hma-scan.mjs'), ...args], {
      encoding: 'utf8',
      env: { ...process.env, FAKE_HMA_EXIT: String(exit) },
    });
    return { status: run.status, stdout: run.stdout, stderr: run.stderr };
  }

  it('is the npm script that runs the scan', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.['hma:scan']).toBe('node scripts/hma-scan.mjs');
  });

  it('declares and installs a HackMyAgent dev dependency that reads `<path>:<check>` rules', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      devDependencies?: Record<string, string>;
    };
    const installed = JSON.parse(readFileSync(join(ROOT, 'node_modules', 'hackmyagent', 'package.json'), 'utf8')) as {
      version: string;
    };
    expect(compare(floor(pkg.devDependencies?.hackmyagent ?? ''), MINIMUM)).toBeGreaterThanOrEqual(0);
    expect(compare(floor(installed.version), MINIMUM)).toBeGreaterThanOrEqual(0);
  });

  it('refuses when no hackmyagent is installed in node_modules', () => {
    const { status, stdout, stderr } = scan();
    expect(status).toBe(2);
    expect(stdout).toBe('');
    expect(stderr).toContain('REFUSED no hackmyagent dev dependency is installed in node_modules');
    expect(stderr).toContain('npm ci');
  });

  it.each([['0.30.0'], ['0.31.0'], ['0.32.0'], ['0.32.9']])(
    'refuses hackmyagent %s, which reads the package.json:AIM-001 rule as a path',
    (version) => {
      installHackMyAgent(version);
      const { status, stdout, stderr } = scan();
      expect(status).toBe(2);
      expect(stdout).toBe('');
      expect(stderr).toContain(`REFUSED node_modules/hackmyagent is ${version};`);
      expect(stderr).toContain('read from 0.33.0 on');
      expect(stderr).toContain('npm ci');
    },
  );

  it.each([['0.33.0'], ['0.33.2'], ['0.34.0'], ['1.0.0']])(
    'runs `hackmyagent secure --ci .` at the repository root with hackmyagent %s',
    (version) => {
      installHackMyAgent(version);
      const { status, stdout, stderr } = scan();
      expect(stderr).toBe('');
      expect(status).toBe(0);
      const ran = JSON.parse(stdout) as { args: string[]; cwd: string };
      expect(ran.args).toEqual(['secure', '--ci', '.']);
      expect(realpathSync(ran.cwd)).toBe(realpathSync(root));
    },
  );

  it('appends its own arguments and exits with the scan exit code', () => {
    installHackMyAgent('0.33.2');
    const { status, stdout } = scan(['--json'], 1);
    expect(status).toBe(1);
    expect((JSON.parse(stdout) as { args: string[] }).args).toEqual(['secure', '--ci', '.', '--json']);
  });
});
