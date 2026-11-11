// The pack gate is this package's prepack script, so `npm pack` and
// `npm publish` both run it. This suite runs the same command, with the same
// arguments, in two scratch packages in one run: one planted with one line per
// expression the gate refuses, which must be refused with exactly those three
// hits, and one carrying near misses, which must pass. A third test runs the
// third expression's line function on the recall near miss alone, which must
// pass, and with one more row carrying a percentage under the F1 column, which
// must be refused on that row, so the near miss passes on the column rule and
// not on a withdrawal notice. Every planted line is assembled at run time from
// fragments, so no line of this file carries a shape the gate refuses. It also
// runs the gate script with the runtime's version set below Node 23 by a
// preload, where the gate must print one line naming that requirement and
// exit 2, the status for a gate that could not run.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { pathToFileURL } from 'node:url';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const GATE_COMMAND = 'node scripts/pack-gate.mjs';
// The command and the module it imports the expressions from.
const GATE_FILES = ['pack-gate.mjs', 'pack-gate-expressions.mjs'];

const scratchRoots: string[] = [];
afterAll(() => {
  for (const root of scratchRoots) fs.rmSync(root, { recursive: true, force: true });
});

function makeTemp(prefix: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  scratchRoots.push(root);
  return root;
}

const glue = (...parts: string[]): string => parts.join('');
const MEASURE = glue('F', '1');

// One file per expression: a bracketed role tag, a vendor named as the
// reviewer, and an accuracy figure in a table with no withdrawal notice.
const PLANTED: Record<string, string> = {
  'role.txt': `${glue('[', 'CHI', 'EF-', 'XX]')} planted\n`,
  'vendor.txt': `${glue('reviewed', ' by ', 'Cla', 'ude')}\n`,
  'figures.md': [`| Configuration | ${MEASURE} |`, '|---|---|', `| planted | ${glue('82', '.9', '%')} |`, ''].join('\n'),
};

// Near misses the gate must pass: an expanded abbreviation, a vendor-named
// crawler as the object of a sentence, a recall figure beside an F1 cell that
// carries no figure, in a file with no withdrawal notice, so the column rule
// decides it, and an accuracy figure in a file that states the withdrawal at
// its top.
const CLEAN: Record<string, string> = {
  'near-misses.txt': ['certificate authority (CA)', 'the ClaudeBot crawler, named as the object of a sentence', ''].join('\n'),
  'recall.md': [`| Scanner | Recall | ${MEASURE} |`, '|---|---|---|', `| planted | ${glue('71', '.1', '%')} | n/a |`, ''].join('\n'),
  'notice.md': [
    `${MEASURE} and precision on this corpus are withdrawn.`,
    '',
    `| Configuration | ${MEASURE} |`,
    '|---|---|',
    `| planted | ${glue('82', '.9', '%')} |`,
    '',
  ].join('\n'),
};

function prepackOf(root: string): unknown {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  return manifest.scripts?.prepack;
}

// A scratch package carrying `files`, whose prepack script is this
// repository's prepack script verbatim, beside a copy of the gate it runs.
function scratchPackage(name: string, files: Record<string, string>): string {
  const root = makeTemp(`pack-gate-${name}-`);
  const prepack = prepackOf(REPO_ROOT);
  const manifest = {
    name: `pack-gate-${name}`,
    version: '0.0.0',
    files: Object.keys(files),
    scripts: prepack === undefined ? {} : { prepack },
  };
  fs.writeFileSync(path.join(root, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const [rel, content] of Object.entries(files)) fs.writeFileSync(path.join(root, rel), content);
  fs.mkdirSync(path.join(root, 'scripts'));
  for (const gateFile of GATE_FILES) {
    const source = path.join(REPO_ROOT, 'scripts', gateFile);
    if (fs.existsSync(source)) fs.copyFileSync(source, path.join(root, 'scripts', gateFile));
  }
  return root;
}

// `npm pack --dry-run --json` in `cwd`, which runs the prepack script. The npm
// is the one running this suite when an npm run started it, else the one on
// the PATH; the calling run's npm_config_ variables are not passed on.
function dryRunPack(cwd: string): { status: number | null; stdout: string; stderr: string } {
  const execpath = process.env.npm_execpath;
  const viaCli = execpath !== undefined && path.basename(execpath) === 'npm-cli.js' && fs.existsSync(execpath);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^npm_config_/i.test(key)));
  const args = ['pack', '--dry-run', '--json'];
  const run = spawnSync(viaCli ? process.execPath : 'npm', viaCli ? [execpath as string, ...args] : args, {
    cwd,
    env,
    encoding: 'utf8',
  });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

// The refusal lines of a gate run: `<file>:<line>: <expression>: <guidance>`.
const refusals = (stderr: string): string[] =>
  stderr
    .split('\n')
    .map((line) => /^([^\s:]+):(\d+): (PATTERN|VENDOR|FIGURES): \S/.exec(line))
    .filter((match): match is RegExpExecArray => match !== null)
    .map((match) => `${match[1]}:${match[2]} ${match[3]}`);

// The 1-based numbers of the lines of `content` that the third expression
// refuses: figureLines, from the module the gate imports its expressions from,
// run on `content` split at each newline, as the gate splits a packed file.
// The module is an ES module and ts-jest compiles this suite to CommonJS, so a
// child Node process imports it.
function figureLinesOf(content: string): number[] {
  const expressions = pathToFileURL(path.join(REPO_ROOT, 'scripts', 'pack-gate-expressions.mjs')).href;
  const source = [
    "import { readFileSync } from 'node:fs';",
    `import { figureLines } from ${JSON.stringify(expressions)};`,
    "process.stdout.write(JSON.stringify(figureLines(readFileSync(0, 'utf8').split('\\n'))));",
  ].join('\n');
  const run = spawnSync(process.execPath, ['--input-type=module', '--eval', source], { input: content, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`figureLines exited ${run.status}: ${run.stderr}`);
  return JSON.parse(run.stdout);
}

// The lines a gate run prints when it could not run (exit 2), each ending with
// `; the pack is refused`. On a runtime older than Node 23 it is the line that
// names that requirement.
const couldNotRun = (stderr: string): string[] =>
  stderr.split('\n').filter((line) => /^pack gate: .*; the pack is refused$/.test(line));

// The version the preload below gives the runtime: older than Node 23, so the
// gate's old-runtime path runs on whichever runtime runs this suite.
const OLD_NODE = '22.0.0';

describe('the pack gate refuses a planted pack and passes a clean one', () => {
  it('the prepack script is the gate command, so npm pack, npm publish and this suite run the same arguments', () => {
    expect(prepackOf(REPO_ROOT)).toBe(GATE_COMMAND);
  });

  it(
    'a scratch pack planted with one line per expression is refused with exactly three hits, and a clean scratch pack passes, in one run',
    () => {
      const planted = dryRunPack(scratchPackage('planted', PLANTED));
      expect(planted.status).not.toBe(0);
      // A gate that could not run prints its reason in place of the three
      // refusals, so on a runtime older than Node 23 this comparison shows the
      // line naming that requirement.
      expect({ refusals: refusals(planted.stderr).sort(), couldNotRun: couldNotRun(planted.stderr) }).toEqual({
        refusals: ['figures.md:3 FIGURES', 'role.txt:1 PATTERN', 'vendor.txt:1 VENDOR'],
        couldNotRun: [],
      });

      const clean = dryRunPack(scratchPackage('clean', CLEAN));
      expect(clean.stderr).not.toMatch(/: (PATTERN|VENDOR|FIGURES): /);
      expect(clean.status).toBe(0);
      expect(refusals(clean.stderr)).toEqual([]);
      expect(clean.stderr).toMatch(/pack gate: pack-gate-clean: \d+ packed files read, 0 skipped, 0 hits/);
      // The gate writes nothing to standard output, so the JSON npm prints parses.
      expect(JSON.parse(clean.stdout)[0].name).toBe('pack-gate-clean');
    },
    120_000,
  );

  it('the recall near miss reaches the column rule: it passes, and the same table with one more row carrying a percentage under the F1 column is refused on that row alone', () => {
    const lines = CLEAN['recall.md'].split('\n');
    // The fixture ends with a newline, so its last line is empty. The extra row
    // takes that empty line's place, so its 1-based number is lines.length.
    expect(lines[lines.length - 1]).toBe('');
    const extra = `| other | ${glue('1', '%')} | ${glue('99', '.9', '%')} |`;
    const withExtra = [...lines.slice(0, -1), extra, ''].join('\n');

    expect(figureLinesOf(CLEAN['recall.md'])).toEqual([]);
    expect(figureLinesOf(withExtra)).toEqual([lines.length]);
  });

  it(
    'on a runtime older than Node 23 the gate prints one line naming the requirement, with no stack trace, and exits 2',
    () => {
      const root = scratchPackage('old-runtime', PLANTED);
      const preload = path.join(root, 'old-node.cjs');
      fs.writeFileSync(preload, `Object.defineProperty(process.versions, 'node', { value: '${OLD_NODE}' });\n`);
      const run = spawnSync(process.execPath, ['--require', preload, path.join('scripts', 'pack-gate.mjs')], {
        cwd: root,
        encoding: 'utf8',
      });
      expect({ status: run.status, stdout: run.stdout, stderr: run.stderr }).toEqual({
        status: 2,
        stdout: '',
        stderr: `pack gate: Node ${OLD_NODE} cannot compile the first expression, which needs Node 23 or newer; the pack is refused\n`,
      });
    },
    30_000,
  );
});
