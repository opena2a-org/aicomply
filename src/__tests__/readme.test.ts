/**
 * README contract tests. The README is the first thing a visitor runs, so the
 * top of it is pinned: the OpenA2A family header, the npm / license / tests
 * badges, the try-it section ahead of every other section with its scan output
 * fence opening by line 28, and a sample output that is what the CLI actually
 * prints for the documented input. LICENSE, which the license badge vouches
 * for, is pinned to the canonical Apache-2.0 text. Every `nanomind-daemon`
 * command the READMEs show names a subcommand the installed daemon lists.
 */

import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
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
