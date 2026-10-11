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

  /** A `key:` line: its indentation and any `- ` before the key, then its value. */
  const KEY = /^(\s*(?:-\s+)?)[\w-]+:(?:\s+(.*))?$/;

  /** `value` without the tags and anchors that may stand before its text. */
  function withoutProperties(value: string): string {
    return value.replace(/^(?:[!&]\S*(?:\s+|$))*/, '');
  }

  /** Whether `value`, past its tags and anchors, opens a quote that it does not close. */
  function quoteOpen(value: string): boolean {
    return /^(?:"(?:[^"\\]|\\[\s\S])*\\?|'(?:[^']|'')*)$/.test(withoutProperties(value));
  }

  /** How the lines of a value are read: kept apart, folded into one, or not known yet. */
  type ValueStyle = 'literal' | 'folded' | 'pending';

  /**
   * How a value whose text, past its tags and anchors, starts with `value`
   * reads its lines, and the column a `>` block's lines start at (see
   * `workflowLines`), for a value under a key at `column`. A `>` header
   * carries a chomping indicator and an indentation indicator in either
   * order, and may end in a comment.
   */
  function openedValue(value: string, column: number): [ValueStyle, number | null | undefined] {
    if (value.startsWith('|')) return ['literal', null];
    const header = /^>(?:[+-]?(\d)?|(\d)[+-])\s*(?:#.*)?$/.exec(value);
    if (header === null) return ['folded', null];
    const indicator = header[1] ?? header[2];
    return ['folded', indicator === undefined ? undefined : column + Number(indicator)];
  }

  /**
   * The workflow's uncommented lines as the shell gets them: `\`-continued
   * lines joined, and the lines YAML folds into one joined too, whether a `>`
   * block scalar or a plain scalar carried onto deeper-indented lines. A blank
   * line ends a folded paragraph, and a `|` block keeps its lines. So does a
   * `>` block for a line indented deeper than the block's own lines, and for
   * the line after it, as YAML folds no line break next to such a line. A
   * `#` line inside a `>` block is text to YAML: its text is left out here,
   * but it counts as a line for the block's indentation and for the line
   * after it. A tag or an anchor may stand before a `|` or `>` header.
   *
   * A key with nothing after its colon, or only tags, anchors or a comment,
   * takes its value from the deeper-indented lines after it: a mapping or a
   * sequence when the first of them is a key or a `- ` entry, a block scalar
   * when it is a `|` or `>` header, and otherwise a scalar folded onto the
   * key's line.
   *
   * A `\` that ends a line joins the next line onto it only when that line
   * belongs to the same value: at any indentation while a quote that the
   * value opens on the line it starts on, its key's line or the first line
   * of a scalar under its key, is still open on the lines joined so far, as
   * js-yaml and PyYAML read a quoted value on to its closing quote, and
   * otherwise when it is indented deeper than the key of its step, as YAML
   * ends a plain or block value at the first non-blank line that is not. A
   * blank line between the two ends the join, except a single one in a plain
   * or quoted scalar, or in a `>` block when neither line is indented deeper
   * than the block's own lines and the blank line is no longer than that
   * indentation (YAML reads a longer one as a more-indented line): YAML folds
   * the line break before the blank line away there and keeps one, which the
   * shell joins across. A `|` block keeps both line breaks, as does a `>`
   * block next to a more-indented line, and two or more blank lines keep two
   * or more. In a double-quoted value the `\` is YAML's own escape instead,
   * and parsers differ on the blank lines after it: js-yaml drops them,
   * joining the lines, and PyYAML keeps each one as a line break, which ends
   * the command. The join there reads one blank line the first way and two
   * or more the second. A `#` line takes no part in a join: the shell ends a
   * comment at the line break, so its `\` continues nothing. Nor does a key's
   * line whose value, past its tags and anchors, starts with `#`: YAML reads
   * that as a comment, which is no part of the value.
   * The shell joins a `\`-continued line onto the word the `\` ends only when
   * the next line keeps no indentation; in a `|` block, and on a more-indented
   * line of a `>` block, YAML keeps the indentation and the shell gets two
   * words. Where the `\` follows a word it is kept in the joined line, followed
   * by a space, for `withoutInstallFlags` and `publishTargets` to see; after a
   * space it is joined with a space. In a `>` block, the last of the lines
   * joined decides whether the line after them is kept apart.
   */
  function workflowLines(workflow: string): string[] {
    const raw = workflow.split(/\r?\n/);
    const lines: string[] = [];
    // Column of the key whose value the lines indented deeper than it belong
    // to, when one is.
    let under: number | null = null;
    // How that value reads its lines; pending until the line it starts on.
    let style: ValueStyle = 'folded';
    // Column the lines of a `>` block start at: the header's indentation
    // indicator past the key's column, or else the column of the block's
    // first line. Undefined until that line, null for any other scalar.
    let blockIndent: number | null | undefined = null;
    // Whether the last line was indented deeper than its `>` block.
    let afterDeeper = false;
    for (let i = 0; i < raw.length; i++) {
      const comment = /^\s*#/.test(raw[i]);
      const indent = raw[i].search(/\S/);
      // Where a value starts on this line, on a key's line or on the first
      // line of a scalar under its key, to see whether a quote it opens is
      // still open on the lines joined to it.
      let valueAt: number | null = null;
      if (under !== null && style === 'pending' && (indent === -1 || indent > under)) {
        // Blank lines, comments, tags and anchors come before the value.
        if (indent === -1 || comment) continue;
        const value = withoutProperties(raw[i].trim());
        if (value === '') continue;
        if (/^\s*(?:-|[\w-]+:)(?:\s|$)/.test(raw[i])) under = null;
        else {
          [style, blockIndent] = openedValue(value, under);
          afterDeeper = false;
          // A header line carries no text; a scalar's first line is folded below.
          if (style === 'literal' || blockIndent !== null) continue;
          valueAt = indent;
        }
      }
      const valueKey = under !== null && (indent === -1 || indent > under) ? under : null;
      const head = valueKey === null ? KEY.exec(raw[i]) : null;
      const stepKey = valueKey ?? (head !== null ? head[1].length : indent);
      // A comment on a key's line, past its tags and anchors, is no part of
      // the value, so a `\` that ends it joins nothing.
      const keyComment = head !== null && withoutProperties(head[2] ?? '').startsWith('#');
      if (head !== null) valueAt = raw[i].length - (head[2] ?? '').length;
      // How deep a `\` line and the line after one blank line may be indented,
      // and how long that blank line may be, for the join to cross it: any
      // depth in a plain or quoted scalar, the block's own indentation in a
      // `>` block, and null where a blank line ends the join.
      let foldDepth: number | null = null;
      if (valueKey !== null && style === 'folded') foldDepth = blockIndent === null ? Infinity : (blockIndent ?? indent);
      else if (head !== null && /^[^|>#]/.test(withoutProperties(head[2] ?? ''))) foldDepth = Infinity;
      let line = raw[i];
      let lastIndent = indent;
      while (!comment && !keyComment && line.endsWith('\\')) {
        const at = foldDepth !== null && lastIndent <= foldDepth && i + 2 < raw.length &&
          raw[i + 1].search(/\S/) === -1 && raw[i + 1].length <= foldDepth &&
          raw[i + 2].search(/\S/) <= foldDepth ? i + 2 : i + 1;
        // The column the next line must pass to belong to the value: none
        // while a quote that the value opens on this line is still open on
        // the lines joined so far.
        const floor = valueAt !== null && quoteOpen(line.slice(valueAt)) ? -1 : stepKey;
        if (at >= raw.length || /^\s*#/.test(raw[at]) || raw[at].search(/\S/) <= floor) break;
        i = at;
        const next = raw[i];
        line = /(?<!\S)\\$/.test(line) ? `${line.slice(0, -1)} ${next.trimStart()}` : `${line} ${next.trimStart()}`;
        lastIndent = next.search(/\S/);
      }
      if (valueKey !== null && style === 'literal') {
        if (!comment) lines.push(line);
        continue;
      }
      if (valueKey !== null) {
        if (indent === -1) {
          lines.push('');
          continue;
        }
        if (comment && blockIndent === null) continue;
        if (blockIndent === undefined) blockIndent = indent;
        const deeper = blockIndent !== null && indent > blockIndent;
        if (deeper || afterDeeper) lines.push(comment ? '' : line);
        else if (!comment) lines[lines.length - 1] += ` ${line.trim()}`;
        afterDeeper = blockIndent !== null && lastIndent > blockIndent;
        continue;
      }
      if (comment) continue;
      const key = KEY.exec(line);
      afterDeeper = false;
      if (key === null) {
        under = null;
        blockIndent = null;
        lines.push(line);
        continue;
      }
      under = key[1].length;
      const text = key[2] ?? '';
      const value = withoutProperties(text);
      if (value === '' || value.startsWith('#')) [style, blockIndent] = ['pending', null];
      else [style, blockIndent] = openedValue(value, under);
      // The key's line keeps a plain or quoted value and a `|` header, and
      // leaves out a `>` header and anything that is not yet the value.
      const kept = style === 'pending' || blockIndent !== null ? line.slice(0, line.length - text.length).trimEnd() : line;
      lines.push(kept);
    }
    return lines;
  }

  /** What each YAML double-quoted escape stands for, other than `\x`, `\u` and `\U`. */
  const YAML_ESCAPES: Record<string, string> = {
    '0': '\0', a: '\x07', b: '\b', t: '\t', '\t': '\t', n: '\n', v: '\v', f: '\f', r: '\r', e: '\x1b',
    ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\x85', _: '\xa0', L: ' ', P: ' ',
  };

  /** `line` with each YAML double-quoted escape replaced by what it stands for. */
  function yamlUnescaped(line: string): string {
    return line.replace(
      /\\(?:x([\da-fA-F]{2})|u([\da-fA-F]{4})|U([\da-fA-F]{8})|([\s\S]))/g,
      (escape, x?: string, u?: string, big?: string, c?: string) => {
        const hex = x ?? u ?? big;
        if (hex === undefined) return YAML_ESCAPES[c ?? ''] ?? escape;
        const point = parseInt(hex, 16);
        return point <= 0x10ffff ? String.fromCodePoint(point) : escape;
      },
    );
  }

  /** `line` without shell quotes and `\` escapes, a `\` before a line break joining the two lines. */
  function shellUnquoted(line: string): string {
    return line.replace(/\\\n|\\([\s\S])|["']/g, (_quote, c?: string) => c ?? '');
  }

  /**
   * The ways the shell may get `line`: as written and with YAML's
   * double-quoted escapes decoded, which is what a `run:` value in double
   * quotes is, and each of those with the shell's quotes and `\` escapes
   * removed, split at the line breaks the decoding makes. A word a quote or an
   * escape hides from one reading is plain in another.
   */
  function readings(line: string): string[] {
    const decoded = yamlUnescaped(line);
    const all = [line, shellUnquoted(line), decoded, shellUnquoted(decoded)];
    return [...new Set(all.flatMap((reading) => reading.split('\n')))];
  }

  /** The `npm publish` flags that take the next word as their value. */
  const VALUE_FLAGS = ['--access', '--tag', '--registry', '--otp'];

  /**
   * What each `npm publish` on `line` is handed to publish. npm skips
   * prepublishOnly for a tarball and publishes another folder under that
   * folder's own scripts, and a variable or a command substitution can expand
   * to either, so the workflow's publish must name nothing. npm options may
   * stand between `npm` and `publish`, each with a word after it; that word
   * counts as a target unless the option is one in `VALUE_FLAGS`, so a
   * workspace named there is one.
   */
  function publishTargets(line: string): string[] {
    const targets: string[] = [];
    for (const [, before, after] of line.matchAll(/\bnpm\\?((?:\s+-\S+(?:\s+[^-\s]\S*)?)*)\s+publish\b([^;&|#]*)/g)) {
      const words = `${before} ${after}`.split(/\s+/).filter((w) => w !== '');
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

  /**
   * `npm` and one of the names in `INSTALL_COMMANDS` at the start of a
   * command: after the `run:` key and the quote that opens its value where
   * the command opens a step, and after any `time` and `NAME=value` words. A
   * value is read only while it is letters, digits and `_.,:/@%+=~-`, as a
   * quote, `$` or `\` can carry the rest of the command into the setting, as in
   * `X='a npm ci' npm publish`. Any other word before `npm`, such as `env`,
   * `sudo` or `time -p`, leaves the flag on the command counted.
   */
  const AN_INSTALL = new RegExp(
    String.raw`^\s*(?:(?:-\s+)?run:\s+["']?)?(?:(?:time|[A-Za-z_]\w*=[\w.,:/@%+=~-]*)\s+)*npm\s+(?:${INSTALL_COMMANDS.join('|')})(?![\w-])`,
  );

  /**
   * `line` without `--ignore-scripts` where it is the flag of an install,
   * which then runs no script and so starts no other npm command: the setting
   * stops there. `npm run`, `npm test`, `npm exec` and the like still run the
   * script or command they name, and every npm command that starts inherits
   * the setting, so the flag on any command not listed in `INSTALL_COMMANDS`
   * is left in. The flag is the install's only when `npm <install>` begins
   * the command it is in (see `AN_INSTALL`), and only the first flag in that
   * command is taken out. `;`, `&`, `|`, a parenthesis (so also `$(`) and a
   * backtick each end one command and start the next.
   *
   * Quotes, escapes and redirections are not decoded, so the flag is left in
   * wherever they could make the split wrong: on a command the split starts
   * while a `"` or `'` opened earlier on the line is still open (the quote
   * that opens a quoted YAML value counts, so only its first command is
   * read), on a command the split starts at an `&` or `|` directly after `<`
   * or `>`, as in the redirections `>&`, `<&` and `>|`, which name a file and
   * end no command, and on every flag a `\` stands before anywhere on the
   * line, as the shell escapes the character after it, YAML decodes it in a
   * double-quoted value and a `\` that ends a line joins the next line onto
   * its word. A quote left open on an earlier line is not seen. Each command
   * is read once, so a long line takes time in proportion to its length.
   */
  function withoutInstallFlags(line: string): string {
    const parts = line.split(/([;&|()`])/);
    // The quote the text before the command leaves open, if any.
    let open = '';
    // Whether a `\` stands in the text before the command.
    let escaped = false;
    for (let i = 0; i < parts.length; i += 2) {
      const command = parts[i];
      const redirected = i > 0 && /[&|]/.test(parts[i - 1]) && /[<>]$/.test(parts[i - 2]);
      const flag = /\s--ignore-scripts\b/.exec(command);
      if (
        flag !== null && open === '' && !redirected && !escaped &&
        !command.slice(0, flag.index).includes('\\') && AN_INSTALL.test(command)
      ) {
        parts[i] = command.slice(0, flag.index) + command.slice(flag.index + flag[0].length);
      }
      for (const c of command) {
        if (c === '\\') escaped = true;
        else if (open === '' && (c === '"' || c === "'")) open = c;
        else if (c === open) open = '';
      }
    }
    return parts.join('');
  }

  /**
   * What would switch prepublishOnly off for the workflow's publish. npm skips
   * it when the publish is handed something to publish (see `publishTargets`)
   * and under ignore-scripts, which reaches the publish as a flag on it, as an
   * `npm_config_ignore_scripts` environment setting, through `npm config set`
   * or `npm set`, and as a line in an .npmrc, the repository's or one a step
   * writes. So every line that mentions it is refused, except where the
   * command it stands in begins with an install, such as
   * `npm ci --ignore-scripts`, and `withoutInstallFlags` finds no quote,
   * redirection or `\` that could put it on another command. A line is
   * refused when any of its `readings` is.
   */
  function scriptsSwitchedOff(workflow: string, npmrc: string | null): string[] {
    const found = workflowLines(workflow).filter((l) =>
      readings(l).some((r) => publishTargets(r).length > 0 || /ignore[-_]scripts/i.test(withoutInstallFlags(r))),
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
    ['a hardened install in a double-quoted scalar', ['      - run: "npm ci --ignore-scripts"', PUBLISH], null],
    ['a hardened install in a single-quoted scalar', ["      - run: 'npm ci --ignore-scripts'", PUBLISH], null],
    ['a hardened install after an environment setting', ['      - run: NODE_ENV=production npm ci --ignore-scripts', PUBLISH], null],
    ['a hardened install that is timed', ['      - run: time npm ci --ignore-scripts', PUBLISH], null],
    ['a hardened install on its own line of a | block', ['        run: |', '          npm ci --ignore-scripts', '          npm publish --provenance --access public'], null],
    ['a hardened install after cd and &&', ['      - run: cd pkg && npm ci --ignore-scripts', PUBLISH], null],
    ['a hardened install after a run: key with no dash', ['        run: npm ci --ignore-scripts', PUBLISH], null],
    ['hardened installs on two consecutive lines', ['        run: |', '          npm ci --ignore-scripts', '          npm ci --ignore-scripts', PUBLISH], null],
    ['a comment that mentions the flag', ['      # never npm publish --ignore-scripts', PUBLISH], null],
    ['an .npmrc that leaves scripts on', [PUBLISH], 'ignore-scripts=false\n; ignore-scripts=true\n'],
    ['flags that take a value', ['      - run: npm publish --provenance --access public --tag next'], null],
    ['its flags folded onto the next line', ['        run: >', '          npm publish --provenance', '          --access public'], null],
    ['a flag folded under an indentation indicator', ['      - run: >2', '          npm ci', '          --ignore-scripts', PUBLISH], null],
    ['a hardened install continued onto the next line', ['        run: |', '          npm ci --ignore-scripts \\', '            --no-audit', PUBLISH], null],
    ['a hardened install after a quote that closes', ['      - run: echo "a; b" && npm ci --ignore-scripts', PUBLISH], null],
    ['a hardened install after a redirection', ['      - run: npm run build > build.log && npm ci --ignore-scripts', PUBLISH], null],
    ['a hardened install in a value that starts after its key', ['      - run:', '          npm ci --ignore-scripts', PUBLISH], null],
    ['the registry named between npm and the publish', ['      - run: npm --registry https://registry.npmjs.org/ publish --provenance --access public'], null],
    ['a blank line that ends a continued line of a | block', ['      - run: |', '          npm publish --provenance --access \\', '', '          public ./x.tgz'], null],
    ['two blank lines that end a continued line of a plain scalar', ['      - run: npm publish --provenance --access \\', '', '', '          public ./x.tgz'], null],
    ['a blank line and a more-indented line after a continued line of a folded scalar', ['      - run: >', '          npm publish --provenance --access \\', '', '            public ./x.tgz'], null],
    ['a blank line after a continued more-indented line of a folded scalar', ['      - run: >', '          echo start', '            npm publish --provenance --access \\', '', '          public ./x.tgz'], null],
    ['a line of spaces longer than the indentation of a folded scalar after a continued line', ['      - run: >', '          npm publish --provenance --access \\', ' '.repeat(14), '          public ./x.tgz'], null],
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
    ['the flag on a publish after an install and ;', ['      - run: npm ci; npm publish --ignore-scripts'], null],
    ['the flag on a publish after an install and ||', ['      - run: npm ci || npm publish --ignore-scripts'], null],
    ['the flag on a publish an install pipes into', ['      - run: npm ci | npm publish --ignore-scripts'], null],
    ['the flag on a publish after a hardened install', ['      - run: npm ci --ignore-scripts $(npm publish --ignore-scripts)'], null],
    ['the flag on a publish an install-led command runs on', ['      - run: npm ci --ignore-scripts npm publish --ignore-scripts'], null],
    ['an install wrapping a publish', ['      - run: npm ci $(npm publish --ignore-scripts)'], null],
    ['an install wrapping a publish in backticks', ['      - run: npm ci `npm publish --ignore-scripts`'], null],
    ['the flag on an npm run that names an install', ['      - run: npm run release npm ci --ignore-scripts'], null],
    ['the flag on an npm run after an install it substitutes', ['      - run: npm run release $(npm ci) --ignore-scripts'], null],
    ['the flag on a publish after an install quoted into a setting', ["      - run: X='a npm ci' npm publish --ignore-scripts"], null],
    ['the flag on a publish after an install expanded into a setting', ['      - run: X=${X:- npm ci} npm publish --ignore-scripts'], null],
    ['the flag on a publish after an install the shell quotes', ['        run: |', "          'npm ci' npm publish --ignore-scripts"], null],
    ['the flag on a more-indented line of a folded scalar', ['      - run: >', '          npm ci', '            npm publish --ignore-scripts'], null],
    ['the flag on the line after a more-indented line of a folded scalar', ['      - run: >', '          echo start', '            npm ci', '          npm publish --ignore-scripts'], null],
    ['the flag after a folded scalar whose first line is more indented', ['      - run: >2', '           npm ci', '          npm publish --ignore-scripts'], null],
    ['the flag in a folded scalar with its indicators the other way round', ['      - run: >2-', '          echo; npm ci', '            npm publish --ignore-scripts'], null],
    ['the flag in a folded scalar with a comment on its first line', ['      - run: > # publish', '          echo; npm ci', '            npm publish --ignore-scripts'], null],
    ['the flag after an install and a YAML line break escape', ['      - run: "npm ci\\nnpm publish --ignore-scripts"'], null],
    ['the flag after a command, an install and a YAML line break escape', ['      - run: "echo ok; npm ci\\nnpm publish --ignore-scripts"'], null],
    ['the flag after an install and a YAML escape of ;', ['      - run: "npm ci\\x3bnpm publish --ignore-scripts"'], null],
    ['the flag on an npm run after a set install and YAML escapes of &&', ['      - run: "X=1 npm ci\\x26\\x26 npm run release --ignore-scripts"'], null],
    ['the flag after a timed install and a YAML line break escape under a run: key with no dash', ['        run: "time npm ci\\u000anpm publish --ignore-scripts"'], null],
    ['the flag on an install name a YAML escaped line break completes', ['      - run: "npm i\\', '          t --ignore-scripts"'], null],
    ['the flag on the line after a more-indented comment line of a folded scalar', ['      - run: >', '          npm ci', '            # note', '          npm publish --ignore-scripts'], null],
    ['the flag after a folded scalar whose first line is a comment', ['      - run: >', '          # note', '            npm ci', '          npm publish --ignore-scripts'], null],
    ['the flag in a tagged literal scalar', ['      - run: !!str |', '          npm ci', '          npm publish --ignore-scripts'], null],
    ['the flag in a tagged folded scalar', ['      - run: !!str >', '          echo; npm ci', '            npm publish --ignore-scripts'], null],
    ['the flag in an anchored folded scalar', ['      - run: &a >', '          echo; npm ci', '            npm publish --ignore-scripts'], null],
    ['the flag on an npm run after an install in double quotes', ['      - run: npm run release "x; npm ci" --ignore-scripts'], null],
    ['the flag on an npm run after an install in single quotes', ["      - run: npm run release 'x; X=1 npm ci' --ignore-scripts"], null],
    ['the flag on an npm run after an install that only names a file', ['      - run: npm run release >& npm ci --ignore-scripts'], null],
    ['the flag on an npm run after a set install that only names a file', ['      - run: npm run release >& X=1 npm ci --ignore-scripts'], null],
    ['the flag on an npm run after an install that only names a clobbered file', ['      - run: npm run release >| npm ci --ignore-scripts'], null],
    ['the flag on an install name a continued line completes', ['        run: |', '          npm i\\', '          t --ignore-scripts'], null],
    ['a tarball after a new key ends a more-indented line', ['      - run: >', '          echo a', '            echo b', '      - run: npm publish --provenance --access public', '          "$TARBALL"'], null],
    ['a tarball after npm and a continued publish on a more-indented line', ['      - run: |', '          npm\\', '            publish ./aicomply-2.2.3.tgz'], null],
    ['a tarball on the line after a comment that ends in a backslash', ['      - run: |', '          # note \\', '          npm publish ./x.tgz'], null],
    ['a tarball on the line after a continued last line of a | block', ['      - run: |', '          npm test \\', '      - run: npm publish --provenance --access public', '          "$TARBALL"'], null],
    ['a tarball on the line after a continued last line of a > block', ['      - run: >', '          # note', '            npm test \\', '      - run: npm publish --provenance --access public', '          "$TARBALL"'], null],
    ['a tarball on the second line of a value that starts after its key', ['      - run:', '          npm publish --provenance --access public', '          "$TARBALL"'], null],
    ['a tarball handed to a double-quoted npm', ['      - run: |', '          "npm" publish ./x.tgz'], null],
    ['a tarball handed to a single-quoted npm', ['      - run: |', "          'npm' publish ./x.tgz"], null],
    ['a tarball handed to an npm with an escaped letter', ['      - run: |', '          n\\pm publish ./x.tgz'], null],
    ['a tarball after a YAML line break escape', ['      - run: "echo ok\\nnpm publish ./x.tgz"'], null],
    ['a tarball after a YAML escape of ;', ['      - run: "echo ok\\x3bnpm publish ./x.tgz"'], null],
    ['a tarball handed to a publish after an npm option that takes a value', ['      - run: npm --registry https://registry.npmjs.org/ publish ./x.tgz'], null],
    ['a tarball handed to a publish after a workspace option', ['      - run: npm -w pkg publish ./x.tgz'], null],
    ['the flag under a tag whose block header is on the next line', ['      - run: !!str', '          |', '          npm ci', '          npm publish --ignore-scripts'], null],
    ['a workspace named between npm and the publish', ['      - run: npm -w pkg publish'], null],
    ['the flag spelled with a YAML escape', ['      - run: "npm publish --ignore\\x2dscripts"'], null],
    ['the flag split by shell quotes', ["      - run: npm publish --ignore'-'scripts"], null],
    ['the flag on the line after a continued line that ends more indented in a folded scalar', ['      - run: >', '          npm ci \\', '            echo x', '          npm publish --ignore-scripts'], null],
    ['a tarball one blank line after a continued line of a plain scalar', ['      - run: npm publish --provenance --access \\', '', '          public ./x.tgz'], null],
    ['a tarball one blank line after a continued line of a folded scalar', ['      - run: >', '          npm publish --provenance --access \\', '', '          public ./x.tgz'], null],
    ['a tarball one blank line after a continued line of a value that starts after its key', ['      - run:', '          npm publish --provenance --access \\', '', '          public ./x.tgz'], null],
    ['a tarball on a more-indented line one blank line after a continued line of a value that starts after its key', ['      - run:', '          npm publish --provenance --access \\', '', '            public ./x.tgz'], null],
    ['a tarball on the line after a key whose value is a comment that ends in a backslash', ['      - run: # note \\', '          npm publish ./x.tgz'], null],
    ['the flag on the line after a key whose value is a comment that ends in a backslash', ['      - run: # note \\', '          npm publish --ignore-scripts'], null],
    ['a tarball on the line after a tagged key whose value is a comment that ends in a backslash', ['      - run: !!str # note \\', '          npm publish ./x.tgz'], null],
    ['a tarball on a continued line of a double-quoted value indented no deeper than its key', ['      - run: "npm publish --provenance --access \\', '        public ./x.tgz"'], null],
    ['a tarball on a continued line of a single-quoted value indented no deeper than its key', ["      - run: 'npm publish --provenance\\", "        public ./x.tgz'"], null],
    ['a tarball on a continued line of a tagged double-quoted value indented no deeper than its key', ['      - run: !!str "npm publish --provenance --access \\', '        public ./x.tgz"'], null],
    ['a tarball on a continued line of a double-quoted value that starts after its key, indented no deeper than the key', ['      - run:', '          "npm publish --provenance --access \\', '        public ./x.tgz"'], null],
    ['a tarball on a continued line of a double-quoted value with an escaped quote, indented no deeper than its key', ['      - run: "echo \\"ok\\" && npm publish --provenance --access \\', '        public ./x.tgz"'], null],
    ['a tarball on a continued line of a single-quoted value with an escaped quote, indented no deeper than its key', ["      - run: 'echo ''ok'' && npm publish --provenance\\", "        public ./x.tgz'"], null],
  ])('refuses a publish with %s', (_label, lines, npmrc) => {
    expect(scriptsSwitchedOff(lines.join('\n'), npmrc)).not.toEqual([]);
  });

  it('reads a long line of installs in time that grows with its length', () => {
    const installs = 'npm ci --ignore-scriptz '.repeat(60000);
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

  it('keeps the lines of a > block indented deeper than the block as lines of their own', () => {
    const workflow = [
      '      - run: >',
      '          echo start',
      '            npm ci',
      '            npm test',
      '          npm publish',
      '          --provenance',
      '      - run: >2-',
      '           npm ci',
      '          npm publish',
    ];
    expect(workflowLines(workflow.join('\n')).map((l) => l.trim().replace(/\s+/g, ' '))).toEqual([
      '- run: echo start',
      'npm ci',
      'npm test',
      'npm publish --provenance',
      '- run:',
      'npm ci',
      'npm publish',
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
