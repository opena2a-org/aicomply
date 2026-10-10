/**
 * README contract tests. The README is the first thing a visitor runs, so the
 * top of it is pinned: the OpenA2A family header, the npm / license / tests
 * badges, the try-it section ahead of every other section with its scan output
 * fence opening by line 28, and a sample output that is what the CLI actually
 * prints for the documented input. LICENSE, which the license badge vouches
 * for, is pinned to the canonical Apache-2.0 text.
 */

import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { comply } from '../index';
import { renderHuman } from '../cli';

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
    // The license badge claims Apache-2.0, so LICENSE must be the published text
    // byte for byte. A substring check misses a re-wrapped paragraph or a dropped
    // blank line, so the whole file is hashed once the filled-in appendix
    // copyright line is put back to its template form. On a mismatch, see what
    // changed with: curl -s https://www.apache.org/licenses/LICENSE-2.0.txt | diff - LICENSE
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
});
