/**
 * README contract tests. The README is the first thing a visitor runs, so the
 * top of it is pinned: the OpenA2A family header, the npm / license / tests
 * badges, the first command plus its output within the first 30 lines, and a
 * sample output that is what the CLI actually prints for the documented input.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { comply } from '../index';
import { renderHuman } from '../cli';

const ROOT = join(__dirname, '..', '..');
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');
const LINES = README.split('\n');

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
    // The badge claims Apache-2.0, so LICENSE must carry the canonical text, not a
    // paraphrase: the clause 6 and clause 9 wording checked here is what a
    // rewritten copy of the license altered before.
    const license = readFileSync(join(ROOT, 'LICENSE'), 'utf8');
    expect(license).toContain('Apache License');
    expect(license).toContain('Version 2.0, January 2004');
    expect(license).toContain(
      'except as required for reasonable and customary use in describing the\n' +
        '      origin of the Work and reproducing the content of the NOTICE file.',
    );
    expect(license).toContain('9. Accepting Warranty or Additional Liability.');
    expect(license).toContain('of your accepting any such warranty or additional liability.');

    // The tests badge must point at a workflow that exists and runs the test suite.
    const m = /\[!\[Tests\]\(https:\/\/github\.com\/opena2a-org\/aicomply\/actions\/workflows\/([\w.-]+\.yml)\/badge\.svg\)\]/.exec(top);
    expect(m).not.toBeNull();
    const workflow = join(ROOT, '.github', 'workflows', m![1]);
    expect(existsSync(workflow)).toBe(true);
    expect(readFileSync(workflow, 'utf8')).toMatch(/run: npm test\b/);
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
});
