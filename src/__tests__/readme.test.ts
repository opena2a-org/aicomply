/**
 * README contract tests. The README is the first thing a visitor runs, so the
 * top of it is pinned: the OpenA2A family header, the npm / license / tests
 * badges, the try-it section ahead of every other section with its scan output
 * fence opening by line 28, and a sample output that is what the CLI actually
 * prints for the documented input. LICENSE, which the license badge vouches
 * for, is pinned to the canonical Apache-2.0 text. Every `nanomind-daemon`
 * command the READMEs show names a subcommand the installed daemon lists. The
 * CommonJS sample runs as a CommonJS file, and the README names the one build
 * the package ships.
 */

import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { compileFunction } from 'vm';
import * as pkg from '../index';
import { comply } from '../index';
import { renderHuman } from '../cli';
import * as regexLayer from '../classifier/regex';
import * as guardAdapter from '../classifier/guard-client/nanomind-adapter';

const ROOT = join(__dirname, '..', '..');
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');
const LINES = README.split('\n');

/** SHA-256 and line count of https://www.apache.org/licenses/LICENSE-2.0.txt. */
const APACHE_2_0_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';
const APACHE_2_0_LINES = 202;
const APACHE_2_0_COPYRIGHT_TEMPLATE = '   Copyright [yyyy] [name of copyright owner]';

/** 1-based line number of the first line matching `re`, or -1. */
function lineOf(re: RegExp, from = 1): number {
  for (let i = from - 1; i < LINES.length; i++) {
    if (re.test(LINES[i])) return i + 1;
  }
  return -1;
}

/** The README's piped `scan` example and the output fence that follows it. */
function scanExample(): { input: string; fenceLine: number; output: string } {
  const cmdLine = lineOf(/^echo ".*" \| npx @opena2a\/aicomply scan$/);
  expect(cmdLine).toBeGreaterThan(0);
  const input = /^echo "(.*)" \|/.exec(LINES[cmdLine - 1])![1];

  const closeLine = lineOf(/^```$/, cmdLine + 1);
  const fenceLine = lineOf(/^```$/, closeLine + 1);
  const endLine = lineOf(/^```$/, fenceLine + 1);
  expect(fenceLine).toBeGreaterThan(0);
  expect(endLine).toBeGreaterThan(fenceLine);
  const output = LINES.slice(fenceLine, endLine - 1).join('\n');
  return { input, fenceLine, output };
}

/** What the README says about `violations[i].value`, from that token to the end of its blockquote. */
function valueClaim(): string {
  const token = '`violations[i].value`';
  const at = LINES.findIndex((l) => l.startsWith('>') && l.includes(token));
  expect(at).toBeGreaterThanOrEqual(0);
  const parts = [LINES[at].slice(LINES[at].indexOf(token))];
  for (let i = at + 1; i < LINES.length && LINES[i].startsWith('>'); i++) {
    parts.push(LINES[i].replace(/^>\s?/, ''));
  }
  return parts.join(' ');
}

/** The body of the README's CommonJS sample, the fence that opens with `require`. */
function commonJsSample(): string {
  const requireLine = lineOf(/^const \{ comply \} = require\('@opena2a\/aicomply'\);$/);
  expect(requireLine).toBeGreaterThan(1);
  expect(LINES[requireLine - 2]).toBe('```javascript');
  const endLine = lineOf(/^```$/, requireLine + 1);
  expect(endLine).toBeGreaterThan(requireLine);
  return LINES.slice(requireLine - 1, endLine - 1).join('\n');
}

/**
 * The lines of the README's validatePolicyConfig() sample, from the one after
 * its import to the end of the fence.
 */
function validatePolicyConfigSample(): string[] {
  const importLine = lineOf(/^import \{ validatePolicyConfig \} from '@opena2a\/aicomply';$/);
  expect(importLine).toBeGreaterThan(1);
  const endLine = lineOf(/^```$/, importLine + 1);
  expect(endLine).toBeGreaterThan(importLine);
  return LINES.slice(importLine, endLine - 1);
}

/**
 * Each example in `sample`, the lines of a validatePolicyConfig() sample, with
 * the pack its `validatePolicyConfig(...)` call passes and the array its `//`
 * comment shows. An example is a call on one line and its comment on the next.
 * Any other line that is not blank fails the test, so a call written over
 * several lines, or with its comment beside it, is not left out of the
 * comparison.
 */
function validatePolicyConfigExamples(sample: string[]): { call: string; pack: unknown; shown: unknown }[] {
  const examples: { call: string; pack: unknown; shown: unknown }[] = [];
  let i = 0;
  while (i < sample.length) {
    const line = sample[i];
    if (line.trim() === '') {
      i += 1;
      continue;
    }
    const call = /^validatePolicyConfig\((.*)\);$/.exec(line);
    expect({ line, oneLineCall: call !== null }).toEqual({ line, oneLineCall: true });
    const comment = /^\/\/ (.*)$/.exec(sample[i + 1] ?? '');
    expect({ call: line, comment: comment !== null }).toEqual({ call: line, comment: true });
    examples.push({ call: line, pack: literal(call![1]), shown: literal(comment![1]) });
    i += 2;
  }
  return examples;
}

/**
 * The value of a JavaScript literal as the README writes it. compileFunction()
 * is called without a `parsingContext`, so the value is built in Node's main
 * context, not in the one jest runs this file in. Its prototypes are the main
 * context's: `literal('[1]') instanceof Array` is false here, and
 * `toStrictEqual` fails on a value that `toEqual` accepts.
 * validatePolicyConfig() makes no `instanceof` or prototype-identity check on a
 * pack, so it returns for these values what it returns for a caller's. If such
 * a check is added to it, a README example can fail here on a pack that a
 * caller's own code passes, and the cause is this function, not the validator.
 */
function literal(source: string): unknown {
  return compileFunction(`return (${source});`)();
}

describe('README', () => {
  it('opens with the OpenA2A family header in lines 1-6', () => {
    const header = LINES.slice(0, 6);
    expect(
      header.some((l) => l.startsWith('> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: ')),
    ).toBe(true);
  });

  it('carries npm, license and tests badges above the first section', () => {
    const firstH2 = lineOf(/^## /);
    const top = LINES.slice(0, firstH2 - 1).join('\n');
    expect(top).toContain(
      '[![npm version](https://img.shields.io/npm/v/@opena2a/aicomply.svg)](https://www.npmjs.com/package/@opena2a/aicomply)',
    );
    expect(top).toContain('[![License: Apache-2.0]');

    // The tests badge must point at a workflow that exists and runs the test suite.
    const m = /\[!\[Tests\]\(https:\/\/github\.com\/opena2a-org\/aicomply\/actions\/workflows\/([\w.-]+\.yml)\/badge\.svg\)\]/.exec(top);
    expect(m).not.toBeNull();
    const workflow = join(ROOT, '.github', 'workflows', m![1]);
    expect(existsSync(workflow)).toBe(true);
    expect(readFileSync(workflow, 'utf8')).toMatch(/run: npm test\b/);
  });

  it('ships LICENSE as the canonical Apache-2.0 text apart from the copyright line', () => {
    // The license badge claims Apache-2.0, so LICENSE must be the published text,
    // after CRLF normalization and with the copyright line restored to its
    // template form. A substring check misses a re-wrapped paragraph or a dropped
    // blank line, so the whole file is hashed after those two steps. On a
    // mismatch, see what changed with:
    // curl -s https://www.apache.org/licenses/LICENSE-2.0.txt | diff - LICENSE
    const license = readFileSync(join(ROOT, 'LICENSE'), 'utf8').replace(/\r\n/g, '\n');
    expect((license.match(/\n/g) ?? []).length).toBe(APACHE_2_0_LINES);
    const template = license.replace(/^   Copyright .*$/m, APACHE_2_0_COPYRIGHT_TEMPLATE);
    expect(createHash('sha256').update(template).digest('hex')).toBe(APACHE_2_0_SHA256);
  });

  it('puts the try-it command before any other section', () => {
    expect(LINES[lineOf(/^## /) - 1]).toMatch(/^## Try it/);
  });

  it('shows the scan output fence by line 28', () => {
    expect(scanExample().fenceLine).toBeLessThanOrEqual(28);
  });

  it('shows the output the CLI actually prints for the documented input', async () => {
    const { input, output } = scanExample();
    // `echo` appends a newline; the CLI scans exactly what arrives on stdin.
    const content = `${input}\n`;
    const result = await comply({ content });

    const chunks: string[] = [];
    const spy = jest.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => {
      chunks.push(String(c));
      return true;
    });
    try {
      renderHuman([{ label: '(stdin)', content }], [result]);
    } finally {
      spy.mockRestore();
    }

    const printed = chunks.join('').replace(/^\n+/, '').replace(/\n+$/, '');
    expect(output).toBe(printed);
  });

  it('says violations[i].value is masked as comply returns it, naming only exported helpers', async () => {
    const claim = valueClaim();
    expect(claim).toMatch(/\bmasked\b/);
    expect(claim).not.toMatch(/\braw\b/);

    const ssn = '123-45-6789';
    const result = await comply({ content: `My SSN is ${ssn}.` });
    const value = result.violations[0].value;
    expect(value).not.toBe(ssn);
    expect(claim).toContain(`\`${value}\``);

    // A function the README points a reader to must be importable from the package.
    const named = [...claim.matchAll(/`([a-z][A-Za-z0-9]*)`/g)].map((m) => m[1]);
    for (const name of named) expect(Object.keys(pkg)).toContain(name);
  });

  it('says the detection layers run one after the other, in the order comply calls them', async () => {
    const at = lineOf(/\bdetection layers\b/);
    expect(at).toBeGreaterThan(0);
    const claim = LINES[at - 1];
    expect(claim).not.toMatch(/\b(in parallel|concurrently|simultaneously|at the same time)\b/i);
    expect(claim).toMatch(/\bone after the other\b/);
    expect(claim.indexOf('regex')).toBeGreaterThanOrEqual(0);
    expect(claim.indexOf('regex')).toBeLessThan(claim.indexOf('Guard'));

    // The regex scan is synchronous, so every call to it has returned before
    // the Guard request is issued.
    const regexSpy = jest.spyOn(regexLayer, 'classifyWithRegex');
    const guardSpy = jest.spyOn(guardAdapter, 'classifyWithNanoMindDaemon').mockResolvedValue(null);
    try {
      await comply({ content: 'My SSN is 123-45-6789.' });
      expect(regexSpy).toHaveBeenCalled();
      expect(guardSpy).toHaveBeenCalledTimes(1);
      expect(Math.max(...regexSpy.mock.invocationCallOrder)).toBeLessThan(
        guardSpy.mock.invocationCallOrder[0],
      );
    } finally {
      regexSpy.mockRestore();
      guardSpy.mockRestore();
    }
  });

  it('gives a sub-millisecond figure for the regex layer only, since a call that reaches the Guard adds its latency', () => {
    const claims = LINES.filter((l) => /\bsub-(ms|millisecond)\b/i.test(l));
    expect(claims.length).toBeGreaterThan(0);
    for (const claim of claims) {
      // A bullet is about the layer its bold lead names; prose is read one
      // sentence at a time.
      const subject = claim.startsWith('- ')
        ? (/\*\*([^*]+)\*\*/.exec(claim) ?? ['', ''])[1]
        : claim.split(/(?<=[.:])\s+/).find((s) => /\bsub-(ms|millisecond)\b/i.test(s))!;
      expect(subject).toMatch(/\bregex\b/i);
    }
  });

  it('lists only Government markings the regex layer reports as CUI', async () => {
    // Each comma-separated example in the Government row is scanned inside a
    // sentence and must come back as one CUI finding over the whole marking,
    // so the row cannot name a form (FOUO, bare CONTROLLED) that scans CLEAN.
    const rowLine = lineOf(/^\| Government\s*\|/, lineOf(/^### Regex layer/));
    expect(rowLine).toBeGreaterThan(0);
    const cell = LINES[rowLine - 1].split('|')[2].trim();
    const forms = cell.split(',').map((f) => f.trim().replace(/^`(.*)`$/, '$1'));
    expect(forms.length).toBeGreaterThan(0);

    const prefix = 'Record: ';
    for (const form of forms) {
      const result = await comply({ content: `${prefix}${form}.` });
      const whole = result.violations.filter(
        (v) => v.type === 'CUI' && v.start === prefix.length && v.end === prefix.length + form.length,
      );
      expect({ form, matched: whole.length }).toEqual({ form, matched: 1 });
    }
  });

  it('scopes the view field to pattern matches, as comply() returns it', async () => {
    // A policy finding is tagged `classifier: 'regex'` but is not a pattern
    // match, so it has no view; the README must not say every finding does.
    expect(README).not.toMatch(/Every finding carries a `view` field/);
    expect(README).toMatch(/Every pattern match carries a `view` field/);

    const result = await comply({ content: 'My SSN is 123-45-6789.', policyPack: 'default' });
    const views = result.violations.map((v) => ({ type: v.type, view: v.view }));
    expect(views).toEqual([
      { type: 'SSN', view: 'normalized' },
      { type: 'POLICY_DENY:pii-ssn', view: undefined },
    ]);
  });

  it('lists the finding types the default policy pack denies and warns on, and names the second-argument form', () => {
    const line = LINES[lineOf(/`'default'` is the only one/) - 1];
    expect(line).toBeDefined();
    const ticked = (text: string) => [...text.matchAll(/`([A-Z_]+)`/g)].map((m) => m[1]);
    const [, denied, warned] = line.match(/denies (.*?) findings and warns on (.*?)\./)!;
    const patterns = (action: string) =>
      pkg.loadPolicyPack('default').rules.filter((r) => r.action === action).flatMap((r) => r.patterns);

    expect(ticked(denied)).toEqual(patterns('DENY'));
    expect(ticked(warned)).toEqual(patterns('WARN'));
    expect(README).toContain('Pass your own pack as `policyPack` on the second argument');
  });

  it('shows validatePolicyConfig() messages as it returns them, for a rule named by index and one named by id', () => {
    // A rule with a non-empty string id is named by that id in quotes
    // (`Rule 'block-ssn': ...`), any other rule by its index (`Rule 0: ...`).
    const examples = validatePolicyConfigExamples(validatePolicyConfigSample());
    expect(examples.length).toBeGreaterThan(0);
    for (const { call, pack, shown } of examples) {
      expect({ call, returns: pkg.validatePolicyConfig(pack) }).toEqual({ call, returns: shown });
    }
    const messages = examples.flatMap(({ shown }) => shown as string[]);
    expect(messages.some((m) => /^Rule \d+: /.test(m))).toBe(true);
    expect(messages.some((m) => /^Rule '[^']+': /.test(m))).toBe(true);
  });

  it('fails on a validatePolicyConfig() example that is not a one-line call with its result on the next line', () => {
    const call = "validatePolicyConfig({ name: 'p', version: '1', rules: [] });";
    const result = "// ['not what it returns']";
    // The one-line form is read, so the test above compares it.
    expect(validatePolicyConfigExamples(['', call, result, ''])).toEqual([
      { call, pack: { name: 'p', version: '1', rules: [] }, shown: ['not what it returns'] },
    ]);

    const otherShapes = [
      ['validatePolicyConfig({', "  name: 'p', version: '1', rules: [] });", result],
      [`${call} ${result}`],
      [`  ${call}`, result],
      [`const problems = ${call}`, result],
      [call, '', result],
      [call, result, "// 'a second comment line'"],
    ];
    for (const sample of otherShapes) {
      let outcome: unknown = 'fails';
      try {
        outcome = validatePolicyConfigExamples(sample);
      } catch {
        // The walker failed on this shape, as it must.
      }
      expect({ sample, outcome }).toEqual({ sample, outcome: 'fails' });
    }
  });

  it('describes CLEAN as what the layers found, in the words the CLI prints', () => {
    // CLEAN is also the verdict for the inputs listed under "What this package
    // does NOT detect", so the README must not present it as safe to forward.
    const bulletLine = lineOf(/^- \*\*`CLEAN`\*\*:/);
    expect(bulletLine).toBeGreaterThan(0);
    expect(LINES[bulletLine - 1]).toContain('no findings from the layers that ran');
    expect(README).not.toMatch(/safe\s+to\s+forward/i);
  });

  it('names the one build the package ships', () => {
    // package.json has no ESM entry beside `main`; ESM reaches the CommonJS
    // build through Node's interop. Adding one means updating this README claim.
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    expect(pkg.type ?? 'commonjs').toBe('commonjs');
    expect(pkg.module).toBeUndefined();
    expect(pkg.exports).toBeUndefined();
    expect(README).toContain('The package is a CommonJS build');
    expect(README).not.toMatch(/ships\s+both/i);
  });

  it('runs the CommonJS sample as written in a CommonJS file', async () => {
    const logged: string[] = [];
    const calls: Promise<unknown>[] = [];
    const tracked = (...args: Parameters<typeof comply>) => {
      const call = comply(...args);
      calls.push(call);
      return call;
    };
    const sampleRequire = (id: string) => {
      if (id !== '@opena2a/aicomply') throw new Error(`the sample requires ${id}`);
      return { comply: tracked };
    };
    const sampleConsole = {
      log: (...args: unknown[]) => logged.push(args.map(String).join(' ')),
      error: (...args: unknown[]) => logged.push(args.map(String).join(' ')),
    };

    // Node compiles a .cjs file as the body of a function with these
    // parameters, so an `await` outside an async function throws the same
    // SyntaxError here that `node sample.cjs` prints.
    const run = compileFunction(
      commonJsSample(),
      ['exports', 'require', 'module', '__filename', '__dirname', 'console'],
      { filename: 'sample.cjs' },
    );
    const sampleModule = { exports: {} };
    run(sampleModule.exports, sampleRequire, sampleModule, 'sample.cjs', ROOT, sampleConsole);

    // Wait for every comply() call, including those started after an earlier one resolves.
    let settled = -1;
    while (settled !== calls.length) {
      settled = calls.length;
      await Promise.all(calls);
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(calls).toHaveLength(2);
    expect(logged).toEqual(['VIOLATION']);
  });
});

/**
 * The subcommands the installed `nanomind-daemon` lists in its usage text.
 * With no subcommand the CLI prints that usage and exits 0 without starting
 * anything, so a documented bare invocation leaves nothing listening.
 */
function daemonSubcommands(): string[] {
  const pkgPath = require.resolve('@nanomind/daemon/package.json');
  const bin = (JSON.parse(readFileSync(pkgPath, 'utf8')) as { bin: Record<string, string> }).bin[
    'nanomind-daemon'
  ];
  const run = spawnSync(process.execPath, [join(dirname(pkgPath), bin), 'help'], {
    encoding: 'utf8',
  });
  expect(run.status).toBe(0);
  return [...run.stdout.matchAll(/^\s+nanomind-daemon (\w+)/gm)].map((m) => m[1]);
}

/**
 * Every `nanomind-daemon` command a README shows, with the token after it.
 * Line breaks are folded first, so a command wrapped across two lines of prose
 * still reads as one command. Prose mentions of the daemon by name are not
 * commands and are not matched.
 */
function daemonInvocations(file: string): { text: string; arg: string | undefined }[] {
  const text = readFileSync(join(ROOT, file), 'utf8').replace(/\s+/g, ' ');
  return [...text.matchAll(/(?:^|`|&& |npx )nanomind-daemon(?: ([^\s`&|;]+))?/g)].map((m) => ({
    text: m[0].replace(/^`/, ''),
    arg: m[1],
  }));
}

describe('README nanomind-daemon commands', () => {
  const FILES = ['README.md', join('python', 'README.md')];

  it.each(FILES)('%s names a daemon subcommand in every nanomind-daemon command', (file) => {
    const subcommands = daemonSubcommands();
    expect(subcommands).toContain('start');
    const invocations = daemonInvocations(file);
    expect(invocations.length).toBeGreaterThan(0);
    const withoutSubcommand = invocations
      .filter(({ arg }) => arg === undefined || !subcommands.includes(arg))
      .map(({ text }) => text);
    expect(withoutSubcommand).toEqual([]);
  });

  it('starts the daemon in the command it says listens on the Guard address', () => {
    const line = lineOf(/nanomind-daemon.*# listens on http:\/\/127\.0\.0\.1:47200/);
    expect(line).toBeGreaterThan(0);
    expect(LINES[line - 1]).toMatch(/\bnanomind-daemon start\b/);
  });
});
