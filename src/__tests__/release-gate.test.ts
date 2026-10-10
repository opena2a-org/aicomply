/**
 * Release gate: `scripts/release-gate.mjs` is the check a publish runs after
 * the conformance suite. It must exit non-zero unless the conformance record
 * was written by this package version, against the pack the package ships,
 * with every case passing. These tests run the script itself, so they pin the
 * exit code a release workflow acts on.
 */

import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runConformance } from '../conformance';

const ROOT = join(__dirname, '..', '..');
const GATE = join(ROOT, 'scripts', 'release-gate.mjs');
const CASES_DIR = join(ROOT, 'pack', 'conformance');

describe('npm release gate', () => {
  // The record exactly as the conformance run writes it for this package.
  const record = runConformance(CASES_DIR);
  let root: string;

  /** A scratch package root carrying this package's package.json and pack. */
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aicomply-gate-'));
    mkdirSync(join(root, 'pack'));
    mkdirSync(join(root, 'conformance'));
    copyFileSync(join(ROOT, 'package.json'), join(root, 'package.json'));
    copyFileSync(join(ROOT, 'pack', 'patterns.json'), join(root, 'pack', 'patterns.json'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function writeRecord(value: unknown): void {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n';
    writeFileSync(join(root, 'conformance', 'typescript.json'), text);
  }

  function gate(args: string[] = ['--root', root]): { status: number | null; output: string } {
    const run = spawnSync(process.execPath, [GATE, ...args], { encoding: 'utf8' });
    return { status: run.status, output: run.stdout + run.stderr };
  }

  it('passes the record the conformance run writes for this package', () => {
    expect(record.cases).toBeGreaterThan(0);
    expect(record.passed).toBe(record.cases);
    writeRecord(record);
    const { status, output } = gate();
    expect(output).toContain('release gate: passed');
    expect(output).not.toContain('REFUSED');
    expect(status).toBe(0);
  });

  it('refuses when the shipped pack is not the pack the record was written against', () => {
    writeRecord(record);
    appendFileSync(join(root, 'pack', 'patterns.json'), '\n');
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain(`REFUSED packSha256: the record was written against pack "${record.packSha256}"`);
    expect(output).toContain('release gate: refused, do not publish');
    expect(output).not.toContain('release gate: passed');
  });

  it('refuses when a case failed', () => {
    writeRecord({ ...record, passed: record.cases - 1 });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain(`REFUSED passed: ${record.cases - 1} of ${record.cases} cases passed`);
    expect(output).toContain('fix: run `npm run conformance`');
  });

  it('refuses a record that ran no cases', () => {
    writeRecord({ ...record, cases: 0, passed: 0 });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED cases: the record ran no cases');
  });

  it("refuses the other runtime's record, which carries the same pack and case count", () => {
    writeRecord({ ...record, runtime: 'python' });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED runtime: the record is for "python", this gate publishes "typescript"');
  });

  it('refuses a record written by another version of the package', () => {
    writeRecord({ ...record, runtimeVersion: '0.0.0' });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain(
      `REFUSED runtimeVersion: the record was written by "0.0.0", this package is "${record.runtimeVersion}"`,
    );
  });

  it('refuses when there is no record', () => {
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toContain('REFUSED record: conformance/typescript.json does not exist');
    expect(output).toContain('fix: run `npm run conformance`');
  });

  it.each([
    ['text that is not JSON', '{', /REFUSED record: conformance\/typescript\.json is not a JSON object/],
    ['a JSON array', '[]', /REFUSED record: conformance\/typescript\.json is not a JSON object/],
    ['counts stored as strings', { cases: '12', passed: '12' }, /REFUSED cases: the record needs integer cases and passed, got "12" and "12"/],
    ['no passed count', { passed: undefined }, /REFUSED cases: the record needs integer cases and passed, got \d+ and missing/],
    ['more passed than cases', { passed: 1e9 }, /REFUSED passed: 1000000000 of \d+ cases passed/],
    ['no pack hash', { packSha256: undefined }, /REFUSED packSha256: the record was written against pack missing/],
  ])('refuses a record with %s', (_label, change, message) => {
    writeRecord(typeof change === 'string' ? change : { ...record, ...change });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output).toMatch(message);
    expect(output).not.toContain('release gate: passed');
  });

  it('prints every reason, not only the first', () => {
    writeRecord({ ...record, runtime: 'python', runtimeVersion: '0.0.0', packSha256: 'f'.repeat(64), passed: 0 });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(output.split('\n').filter((l) => l.startsWith('REFUSED ')).map((l) => l.split(':')[0])).toEqual([
      'REFUSED runtime',
      'REFUSED runtimeVersion',
      'REFUSED packSha256',
      'REFUSED passed',
    ]);
  });

  /** The REFUSED lines and the fix lines of a run, in order. */
  function refusedAndFixes(output: string): { refused: string[]; fixes: string[] } {
    const lines = output.split('\n');
    return {
      refused: lines.filter((l) => l.startsWith('REFUSED ')),
      fixes: lines.filter((l) => l.startsWith('fix: ')),
    };
  }

  it('names a missing pack and the fix for it', () => {
    writeRecord(record);
    rmSync(join(root, 'pack', 'patterns.json'));
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: [`REFUSED pack: pack/patterns.json does not exist in ${root}`],
      fixes: [
        'fix: restore pack/patterns.json from the commit being released: the package ships it and the record is compared against its bytes',
      ],
    });
    expect(output).not.toContain('ENOENT');
    expect(output).not.toContain('release gate: passed');
  });

  it('names a missing package.json and still checks the fields the record carries', () => {
    writeRecord({ ...record, runtime: 'python' });
    rmSync(join(root, 'package.json'));
    rmSync(join(root, 'pack', 'patterns.json'));
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: [
        `REFUSED package: package.json does not exist in ${root}`,
        `REFUSED pack: pack/patterns.json does not exist in ${root}`,
        'REFUSED runtime: the record is for "python", this gate publishes "typescript"',
      ],
      fixes: [
        'fix: pass --root the package directory, the one that holds package.json and pack/patterns.json',
        'fix: run `npm run conformance` on the commit being released, resolve every FAIL it prints, then run this gate again',
      ],
    });
    expect(output).not.toContain('ENOENT');
  });

  it('names every missing file when --root is an empty directory', () => {
    const empty = mkdtempSync(join(tmpdir(), 'aicomply-gate-empty-'));
    try {
      const { status, output } = gate(['--root', empty]);
      expect(status).toBe(1);
      expect(refusedAndFixes(output).refused).toEqual([
        `REFUSED package: package.json does not exist in ${empty}`,
        `REFUSED pack: pack/patterns.json does not exist in ${empty}`,
        'REFUSED record: conformance/typescript.json does not exist',
      ]);
      expect(output).not.toContain('ENOENT');
      expect(output).not.toContain('REFUSED gate:');
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  const ROOT_FIX = 'fix: pass --root the package directory, the one that holds package.json and pack/patterns.json';
  const RERUN_FIX =
    'fix: run `npm run conformance` on the commit being released, resolve every FAIL it prints, then run this gate again';
  const PACKAGE_FIX =
    'fix: restore package.json from the commit being released: the record is compared against its "version" string';
  const PACK_FIX =
    'fix: restore pack/patterns.json from the commit being released: the package ships it and the record is compared against its bytes';
  const RECORD_FIX = `fix: remove what stands in place of conformance/typescript.json, then ${RERUN_FIX.slice('fix: '.length)}`;

  it('names a --root that is a file instead of printing the system error', () => {
    const file = join(root, 'package.json');
    const { status, output } = gate(['--root', file]);
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: [
        `REFUSED package: package.json cannot be read, ${file} is not a directory`,
        `REFUSED pack: pack/patterns.json cannot be read, ${file} is not a directory`,
        `REFUSED record: conformance/typescript.json cannot be read, ${file} is not a directory`,
      ],
      fixes: [ROOT_FIX],
    });
    expect(output).not.toMatch(/ENOTDIR|REFUSED gate:/);
    expect(output).not.toContain('release gate: passed');
  });

  it('names a package.json and a pack that are directories, not missing files, and fixes each in place', () => {
    // The root holds a package.json entry, so --root is not the mistake.
    writeRecord(record);
    for (const file of [join(root, 'package.json'), join(root, 'pack', 'patterns.json')]) {
      rmSync(file);
      mkdirSync(file);
    }
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: [
        `REFUSED package: package.json in ${root} is a directory, not a file`,
        `REFUSED pack: pack/patterns.json in ${root} is a directory, not a file`,
      ],
      fixes: [PACKAGE_FIX, PACK_FIX],
    });
    expect(output).not.toMatch(/EISDIR|REFUSED gate:|does not exist/);
    expect(output).not.toContain(ROOT_FIX);
  });

  // Permission bits do not stop the superuser from reading, and Windows has none to clear.
  const permissionsApply = process.platform !== 'win32' && process.getuid?.() !== 0;
  (permissionsApply ? it : it.skip)(
    'fixes a package.json it has no permission to read in place, not with --root',
    () => {
      mkdirSync(join(root, 'conformance', 'typescript.json'));
      rmSync(join(root, 'pack', 'patterns.json'));
      chmodSync(join(root, 'package.json'), 0o000);
      const { status, output } = gate();
      expect(status).toBe(1);
      expect(refusedAndFixes(output)).toEqual({
        refused: [
          expect.stringMatching(/^REFUSED package: package\.json cannot be read \(EACCES: /),
          `REFUSED pack: pack/patterns.json does not exist in ${root}`,
          'REFUSED record: conformance/typescript.json is a directory, not a file',
        ],
        fixes: [PACKAGE_FIX, PACK_FIX, RECORD_FIX],
      });
      expect(output).not.toContain(ROOT_FIX);
      expect(output).not.toContain('release gate: passed');
    },
  );

  it('names the file that stands where the pack directory should be', () => {
    writeRecord(record);
    rmSync(join(root, 'pack'), { recursive: true });
    writeFileSync(join(root, 'pack'), '');
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: [`REFUSED pack: pack/patterns.json cannot be read, ${join(root, 'pack')} is not a directory`],
      fixes: [
        'fix: restore pack/patterns.json from the commit being released: the package ships it and the record is compared against its bytes',
      ],
    });
    expect(output).not.toMatch(/ENOTDIR|REFUSED gate:/);
  });

  it('names a record that is a directory, not a missing one', () => {
    mkdirSync(join(root, 'conformance', 'typescript.json'));
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: ['REFUSED record: conformance/typescript.json is a directory, not a file'],
      fixes: [RECORD_FIX],
    });
    expect(output).not.toMatch(/EISDIR|does not exist/);
  });

  it.each([
    ['no version', { name: 'x' }, 'missing'],
    ['a version that is not a string', { name: 'x', version: 2 }, '2'],
    ['an empty version', { name: 'x', version: '' }, '""'],
  ])('refuses a package.json with %s, even when the record names the same', (_label, pkg, shown) => {
    // A record without runtimeVersion would match a package without a version
    // if the gate compared the two, so the missing version refuses on its own.
    writeFileSync(join(root, 'package.json'), JSON.stringify(pkg));
    writeRecord({ ...record, runtimeVersion: (pkg as { version?: unknown }).version });
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output)).toEqual({
      refused: [`REFUSED package: package.json carries no version string, its version is ${shown}`],
      fixes: ['fix: restore package.json from the commit being released: the record is compared against its "version" string'],
    });
    expect(output).not.toContain('release gate: passed');
  });

  it('refuses on an error it did not foresee, here a package.json that is not JSON', () => {
    // The catch-all: whatever the checks throw, the gate refuses and never passes.
    writeRecord(record);
    writeFileSync(join(root, 'package.json'), '{');
    const { status, output } = gate();
    expect(status).toBe(1);
    expect(refusedAndFixes(output).refused).toEqual([expect.stringMatching(/^REFUSED gate: \S/)]);
    expect(output).toContain('release gate: refused, do not publish');
    expect(output).not.toContain('release gate: passed');
  });

  it('exits 2 on an argument it does not know', () => {
    const { status, output } = gate(['--skip']);
    expect(status).toBe(2);
    expect(output).toContain('usage: node scripts/release-gate.mjs [--root <dir>]');
  });

  it('is the release:gate npm script', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(pkg.scripts['release:gate']).toBe('node scripts/release-gate.mjs');
  });
});

/**
 * `npm publish` runs the package's prepublishOnly script before it packs
 * anything and stops when that script exits non-zero. These tests run this
 * package's own prepublishOnly through npm, so they pin that a publish cannot
 * get past a failing conformance run or a refusing gate.
 */
describe('npm publish lifecycle', () => {
  const NPM_RUN_TIMEOUT_MS = 60_000;
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
    scripts: Record<string, string | undefined>;
  };
  let root: string;

  /**
   * A scratch package whose prepublishOnly is this package's own. The two
   * scripts it calls are stand-ins that record their name and exit 1 when
   * told to, so a test sees which steps ran and what npm exits with.
   */
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aicomply-publish-'));
    writeFileSync(
      join(root, 'step.js'),
      [
        "const { appendFileSync } = require('node:fs');",
        "appendFileSync('steps.txt', process.argv[2] + '\\n');",
        'process.exit(process.env.FAILING_STEP === process.argv[2] ? 1 : 0);',
        '',
      ].join('\n'),
    );
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({
        name: 'publish-lifecycle-fixture',
        version: '0.0.0',
        private: true,
        scripts: {
          prepublishOnly: pkg.scripts.prepublishOnly,
          conformance: 'node step.js conformance',
          'release:gate': 'node step.js release:gate',
        },
      }),
    );
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function prepublish(failingStep = ''): { status: number | null; steps: string[] } {
    const run = spawnSync('npm run prepublishOnly', {
      cwd: root,
      env: { ...process.env, npm_config_update_notifier: 'false', FAILING_STEP: failingStep },
      shell: true,
      encoding: 'utf8',
    });
    const trace = join(root, 'steps.txt');
    const steps = existsSync(trace) ? readFileSync(trace, 'utf8').split('\n').filter((l) => l.length > 0) : [];
    return { status: run.status, steps };
  }

  it(
    'runs the conformance suite and then the release gate',
    () => {
      expect(prepublish()).toEqual({ status: 0, steps: ['conformance', 'release:gate'] });
    },
    NPM_RUN_TIMEOUT_MS,
  );

  it(
    'stops the publish, without reaching the gate, when the conformance suite fails',
    () => {
      expect(prepublish('conformance')).toEqual({ status: 1, steps: ['conformance'] });
    },
    NPM_RUN_TIMEOUT_MS,
  );

  it(
    'stops the publish when the release gate refuses',
    () => {
      expect(prepublish('release:gate')).toEqual({ status: 1, steps: ['conformance', 'release:gate'] });
    },
    NPM_RUN_TIMEOUT_MS,
  );

  it('measures the build it is about to pack', () => {
    expect(pkg.scripts.conformance).toBe('npm run build && node scripts/conformance.mjs');
  });

  /**
   * The workflow's uncommented lines as the shell gets them: `\`-continued
   * lines joined, and the lines YAML folds into one joined too, whether a `>`
   * block scalar or a plain scalar carried onto deeper-indented lines. A blank
   * line ends a folded paragraph, and a `|` block keeps its lines.
   */
  function workflowLines(workflow: string): string[] {
    const lines: string[] = [];
    // Column of the key whose scalar is being folded, when one is.
    let foldedUnder: number | null = null;
    for (const line of workflow.replace(/\\\r?\n\s*/g, ' ').split(/\r?\n/)) {
      if (/^\s*#/.test(line)) continue;
      const indent = line.search(/\S/);
      if (foldedUnder !== null && (indent === -1 || indent > foldedUnder)) {
        if (indent === -1) lines.push('');
        else lines[lines.length - 1] += ` ${line.trim()}`;
        continue;
      }
      const key = /^(\s*(?:-\s+)?)[\w-]+:\s+(\S.*)$/.exec(line);
      foldedUnder = key !== null && !key[2].startsWith('|') ? key[1].length : null;
      lines.push(key !== null && /^>[+-]?\d?\s*$/.test(key[2]) ? line.slice(0, -key[2].length) : line);
    }
    return lines;
  }

  /** The `npm publish` flags that take the next word as their value. */
  const VALUE_FLAGS = ['--access', '--tag', '--registry', '--otp'];

  /**
   * What each `npm publish` on `line` is handed to publish. npm skips
   * prepublishOnly for a tarball and publishes another folder under that
   * folder's own scripts, and a variable or a command substitution can expand
   * to either, so the workflow's publish must name nothing.
   */
  function publishTargets(line: string): string[] {
    const targets: string[] = [];
    for (const [, rest] of line.matchAll(/\bnpm publish\b([^;&|#]*)/g)) {
      const words = rest.split(/\s+/).filter((w) => w !== '');
      for (let i = 0; i < words.length; i++) {
        if (!words[i].startsWith('-')) targets.push(words[i]);
        else if (VALUE_FLAGS.includes(words[i])) i++;
      }
    }
    return targets;
  }

  /**
   * The names npm accepts for `npm ci` and `npm install`: `clean-install`,
   * `install-clean`, `ic` and the misspelling `isntall-clean` for the one, and
   * `add`, `i`, the shortened spellings `in` to `instal` and the misspellings
   * `isnt` to `isntall` for the other. `install-test`, `install-ci-test` and
   * their aliases are not here: they go on to run the test script.
   */
  const INSTALL_COMMANDS = [
    'ci', 'clean-install', 'install-clean', 'ic', 'isntall-clean',
    'install', 'add', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall',
  ];

  /** `npm` and one of the names in `INSTALL_COMMANDS`. */
  const AN_INSTALL = new RegExp(String.raw`\bnpm\s+(?:${INSTALL_COMMANDS.join('|')})(?![\w-])`, 'g');

  /**
   * `line` without `--ignore-scripts` where it is the flag of an install,
   * which then runs no script and so starts no other npm command: the setting
   * stops there. `npm run`, `npm test`, `npm exec` and the like still run the
   * script or command they name, and every npm command that starts inherits
   * the setting, so the flag on any command not listed in `INSTALL_COMMANDS`
   * is left in. Each command between `;`, `&` and `|` is read once, left to
   * right, so a long line takes time in proportion to its length.
   */
  function withoutInstallFlags(line: string): string {
    return line
      .split(/([;&|])/)
      .map((command) => {
        const flag = /\s--ignore-scripts\b/g;
        let kept = '';
        let from = 0;
        for (const install of command.matchAll(AN_INSTALL)) {
          if (install.index < from) continue;
          flag.lastIndex = install.index + install[0].length;
          const found = flag.exec(command);
          // No later install in this command has the flag after it either.
          if (found === null) break;
          kept += command.slice(from, found.index);
          from = flag.lastIndex;
        }
        return kept + command.slice(from);
      })
      .join('');
  }

  /**
   * What would switch prepublishOnly off for the workflow's publish. npm skips
   * it when the publish is handed something to publish (see `publishTargets`)
   * and under ignore-scripts, which reaches the publish as a flag on it, as an
   * `npm_config_ignore_scripts` environment setting, through `npm config set`
   * or `npm set`, and as a line in an .npmrc, the repository's or one a step
   * writes. So every line that mentions it is refused, except where it is the
   * flag on an install, such as `npm ci --ignore-scripts`.
   */
  function scriptsSwitchedOff(workflow: string, npmrc: string | null): string[] {
    const found = workflowLines(workflow).filter(
      (l) => publishTargets(l).length > 0 || /ignore[-_]scripts/i.test(withoutInstallFlags(l)),
    );
    const rc = (npmrc ?? '')
      .split('\n')
      .filter((l) => /^\s*ignore[-_]scripts\b/i.test(l) && !/=\s*false\s*$/i.test(l))
      .map((l) => `.npmrc: ${l.trim()}`);
    return [...found.map((l) => l.trim()), ...rc];
  }

  const PUBLISH = '      - run: npm publish --provenance --access public';

  it.each([
    ['a hardened install step', ['      - run: npm ci --ignore-scripts', PUBLISH], null],
    ['a hardened npm install step', ['      - run: npm install --ignore-scripts', PUBLISH], null],
    ['a hardened npm clean-install step', ['      - run: npm clean-install --ignore-scripts', PUBLISH], null],
    ['a hardened npm install-clean step', ['      - run: npm install-clean --ignore-scripts', PUBLISH], null],
    ['a hardened npm ic step', ['      - run: npm ic --ignore-scripts', PUBLISH], null],
    ['a hardened npm isntall step', ['      - run: npm isntall --ignore-scripts', PUBLISH], null],
    ['a hardened npm instal step', ['      - run: npm instal --ignore-scripts', PUBLISH], null],
    ['a hardened install chained before it', ['      - run: npm ci --ignore-scripts && npm publish --provenance --access public'], null],
    ['a comment that mentions the flag', ['      # never npm publish --ignore-scripts', PUBLISH], null],
    ['an .npmrc that leaves scripts on', [PUBLISH], 'ignore-scripts=false\n; ignore-scripts=true\n'],
    ['flags that take a value', ['      - run: npm publish --provenance --access public --tag next'], null],
    ['its flags folded onto the next line', ['        run: >', '          npm publish --provenance', '          --access public'], null],
  ])('lets a publish through with %s', (_label, lines, npmrc) => {
    expect(scriptsSwitchedOff(lines.join('\n'), npmrc)).toEqual([]);
  });

  it.each([
    ['--ignore-scripts on the publish', ['      - run: npm publish --ignore-scripts'], null],
    ['the flag on a publish chained after an install', ['      - run: npm ci && npm publish --ignore-scripts'], null],
    ['the flag on the npm run that starts the publish', ['      - run: npm run release --ignore-scripts'], null],
    ['the flag on an npm run-script', ['      - run: npm run-script release --ignore-scripts'], null],
    ['the flag on npm test', ['      - run: npm ci --ignore-scripts && npm test --ignore-scripts'], null],
    ['the flag on npm exec', ['      - run: npm exec --ignore-scripts -- publish-release'], null],
    ['the flag on npm x', ['      - run: npm x --ignore-scripts publish-release'], null],
    ['the flag on a command that only starts like an install', ['      - run: npm ci-release --ignore-scripts'], null],
    ['the flag on an install that runs the tests', ['      - run: npm install-test --ignore-scripts'], null],
    ['the flag on a clean install that runs the tests', ['      - run: npm clean-install-test --ignore-scripts'], null],
    ['the flag on npm cit', ['      - run: npm cit --ignore-scripts'], null],
    ['the flag on npm it', ['      - run: npm it --ignore-scripts'], null],
    ['the flag on npm sit', ['      - run: npm sit --ignore-scripts'], null],
    ['the flag on npm install-ci-test', ['      - run: npm install-ci-test --ignore-scripts'], null],
    ['a tarball handed to the publish', ['      - run: npm publish ./aicomply-2.2.3.tgz'], null],
    ['a tarball named by a command substitution', ['      - run: npm publish "$(npm pack | tail -1)"'], null],
    ['a tarball named by a variable', ['      - run: npm publish "$TARBALL"'], null],
    ['a tarball after a flag that takes a value', ['      - run: npm publish --access public "$TARBALL"'], null],
    ['the flag on a continued publish line', ['        run: |', '          npm publish --access public \\', '            --ignore-scripts'], null],
    ['the flag on the next line of a folded scalar', ['        run: >', '          npm publish --provenance --access public', '          --ignore-scripts'], null],
    ['a tarball on the next line of a folded scalar', ['      - run: >-', '          npm publish --provenance --access public', '          "$TARBALL"'], null],
    ['a tarball on the next line of a plain scalar', ['      - run: npm publish --provenance --access public', '          "$TARBALL"'], null],
    ['an environment setting', ['    env:', "      NPM_CONFIG_IGNORE_SCRIPTS: 'true'", PUBLISH], null],
    ['an environment file line', ['      - run: echo "npm_config_ignore_scripts=true" >> "$GITHUB_ENV"', PUBLISH], null],
    ['npm config set', ['      - run: npm config set ignore-scripts true', PUBLISH], null],
    ['npm config set with a location flag', ['      - run: npm config set --global ignore-scripts true', PUBLISH], null],
    ['npm set', ['      - run: npm set ignore-scripts true', PUBLISH], null],
    ['a line a step appends to .npmrc', ['      - run: echo "ignore-scripts=true" >> .npmrc', PUBLISH], null],
    ['an .npmrc line', [PUBLISH], 'registry=https://registry.npmjs.org/\nignore-scripts=true\n'],
  ])('refuses a publish with %s', (_label, lines, npmrc) => {
    expect(scriptsSwitchedOff(lines.join('\n'), npmrc)).not.toEqual([]);
  });

  it('reads a long line of installs in time that grows with its length', () => {
    const installs = 'npm ci '.repeat(60000);
    const started = Date.now();
    expect(scriptsSwitchedOff(`      - run: ${installs}--ignore-scripts`, null)).toEqual([]);
    expect(scriptsSwitchedOff(`      - run: ${installs}&& npm test --ignore-scripts`, null)).not.toEqual([]);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('reads the lines YAML folds as the one line the shell gets', () => {
    const workflow = [
      '      - run: >',
      '          npm publish',
      '          # a comment is not a line',
      '          --provenance',
      '',
      '          echo done',
      '      - run: |',
      '          npm ci',
      '          npm test',
      '      - run: npm pack',
      '          --dry-run',
      '        env:',
      '          CI: true',
    ];
    expect(workflowLines(workflow.join('\n')).map((l) => l.trim().replace(/\s+/g, ' '))).toEqual([
      '- run: npm publish --provenance',
      'echo done',
      '- run: |',
      'npm ci',
      'npm test',
      '- run: npm pack --dry-run',
      'env:',
      'CI: true',
    ]);
  });

  it('is not switched off where the release workflow publishes', () => {
    const workflow = readFileSync(join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
    const npmrcPath = join(ROOT, '.npmrc');
    const npmrc = existsSync(npmrcPath) ? readFileSync(npmrcPath, 'utf8') : null;
    expect(workflowLines(workflow).filter((l) => /\bnpm publish\b/.test(l))).not.toEqual([]);
    expect(scriptsSwitchedOff(workflow, npmrc)).toEqual([]);
  });
});
