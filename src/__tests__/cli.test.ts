/**
 * CLI behavior tests. The CLI is the zero-integration try-path; these assert the
 * contract a consumer (or a CI gate) relies on: exit codes, masking, and output
 * shape. Detection accuracy itself is covered by the regex/dual-layer suites.
 */

import { execFileSync } from 'child_process';
import fs, { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'fs';
import { createServer, type Server } from 'net';
import { devNull, tmpdir } from 'os';
import { join } from 'path';
import { PassThrough } from 'stream';
import { filesGlob, locate, run } from '../cli';
import { PATTERN_TYPES } from '../classifier/regex/pack';

function capture(): { out: string[]; err: string[]; restore: () => void } {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = jest.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => {
    out.push(String(c));
    return true;
  });
  const errSpy = jest.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => {
    err.push(String(c));
    return true;
  });
  return { out, err, restore: () => { outSpy.mockRestore(); errSpy.mockRestore(); } };
}

const realFstatSync = fs.fstatSync;

/** fstat of descriptor 0 returns the stats of `path` until the mocks are restored. */
function stdinIs(path: string): void {
  jest
    .spyOn(fs, 'fstatSync')
    .mockImplementation(((fd: number, options?: fs.StatOptions) =>
      fd === 0 ? fs.statSync(path) : realFstatSync(fd, options)) as typeof fs.fstatSync);
}

let dir: string;
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'aicomply-cli-')); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });
// A scan of files named without `-` reads fstat of descriptor 0, so each test
// starts with /dev/null there rather than the stdin the test runner was given.
beforeEach(() => stdinIs(devNull));
afterEach(() => jest.restoreAllMocks());

function fixture(name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content, 'utf8');
  return p;
}

describe('aicomply CLI', () => {
  // The Guard preview caveat used to print ONLY when the Guard was inactive,
  // so it was shown when it was harmless and hidden the moment the Guard
  // started deciding verdicts. With a measured ~70% benign false-positive
  // rate, an unqualified `confidence 1.00` on plain English is the opposite
  // of empowering. Both directions are pinned here.
  function guardResult(classifier: 'guard' | 'regex') {
    return {
      verdict: 'VIOLATION' as const,
      violations: [{
        type: 'tool_misuse',
        value: 'some benign sentence',
        start: 0,
        end: 20,
        confidence: 1.0,
        classifier,
        view: 'normalized' as const,
      }],
      // Guard is ACTIVE in both cases. Only the finding's layer differs, so
      // the control cannot pass merely because the Guard was absent.
      classifierResults: { guard: { verdict: 'VIOLATION', violations: [] } },
    } as unknown as import('../types').ComplyResult;
  }

  it('discloses the preview caveat when a guard-layer finding is present', async () => {
    const { renderHuman } = await import('../cli');
    const cap = capture();
    try {
      renderHuman([{ label: 'x.txt', content: 'c' } as never], [guardResult('guard')]);
    } finally {
      cap.restore();
    }
    const text = cap.out.join('');
    expect(text).toMatch(/Semantic Guard layer: active \(preview\)/);
    expect(text).toMatch(/over-flags/);
    expect(text).toMatch(/advisory, not production gating/);
  });

  it('does not print the active caveat when every finding is regex-layer', async () => {
    // Control: the caveat must attach to guard findings, not to any violation.
    // Without this, the fix would spam the disclaimer on pure regex output.
    const { renderHuman } = await import('../cli');
    const cap = capture();
    try {
      renderHuman([{ label: 'x.txt', content: 'c' } as never], [guardResult('regex')]);
    } finally {
      cap.restore();
    }
    expect(cap.out.join('')).not.toMatch(/Semantic Guard layer: active/);
  });

  it('--version prints version and exits 0', async () => {
    const cap = capture();
    const code = await run(['--version']);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('')).toMatch(/^\d+\.\d+\.\d+/);
  });

  // Drift guard: the hardcoded CLI VERSION must match package.json. A version
  // bump that forgets the constant would otherwise ship a CLI reporting the
  // wrong version (caught at release 2.2.1).
  it('--version matches package.json version', async () => {
    const pkg = require('../../package.json') as { version: string };
    const cap = capture();
    await run(['--version']);
    cap.restore();
    expect(cap.out.join('').trim()).toBe(pkg.version);
  });

  it('--help exits 0 and documents the scan command', async () => {
    const cap = capture();
    const code = await run(['--help']);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('')).toContain('aicomply scan');
  });

  it('scan --help exits 0 and shows scan-specific help, not the generic banner', async () => {
    const cap = capture();
    const code = await run(['scan', '--help']);
    cap.restore();
    expect(code).toBe(0);
    const out = cap.out.join('');
    // The scan help must lead with a scan-scoped synopsis, not the top-level
    // "aicomply -- inline content classifier..." banner.
    expect(out.trimStart().startsWith('aicomply scan')).toBe(true);
    expect(out).toContain('--json');
    expect(out).toContain('--quiet');
    // Scan reads from files or stdin; the scan help must say so.
    expect(out.toLowerCase()).toContain('stdin');
  });

  it('top-level --help leads with the generic banner, not the scan synopsis', async () => {
    const cap = capture();
    await run(['--help']);
    cap.restore();
    const out = cap.out.join('');
    expect(out.trimStart().startsWith('aicomply --')).toBe(true);
  });

  it('no command exits 2 (usage)', async () => {
    const cap = capture();
    const code = await run([]);
    cap.restore();
    expect(code).toBe(2);
  });

  it('unknown command exits 2 with guidance', async () => {
    const cap = capture();
    const code = await run(['frobnicate']);
    cap.restore();
    expect(code).toBe(2);
    expect(cap.err.join('')).toContain("unknown command 'frobnicate'");
  });

  it('missing file exits 2', async () => {
    const cap = capture();
    const code = await run(['scan', join(dir, 'does-not-exist.txt')]);
    cap.restore();
    expect(code).toBe(2);
  });

  // A directory used to get the missing-file message, "check the path",
  // though the path exists.
  it('says a directory argument is a directory and prints the glob for the files in it', async () => {
    const d = join(dir, 'adir');
    mkdirSync(d);
    writeFileSync(join(d, 'clean.txt'), 'The weather is nice today.', 'utf8');
    // The temporary path holds no character the glob would quote.
    expect(d).toMatch(/^[A-Za-z0-9_@%+=:,./-]+$/);
    for (const arg of [d, `${d}/`]) {
      const cap = capture();
      const code = await run(['scan', arg]);
      cap.restore();
      expect({ arg, code, err: cap.err.join('') }).toEqual({
        arg,
        code: 2,
        err:
          `aicomply: '${arg}' is a directory, and directories are not scanned. Name the files in it:\n` +
          `  aicomply scan ${d}/*.txt\n`,
      });
    }

    // The printed glob, expanded by a shell, names the file in the directory,
    // and scanning it exits 0.
    const files = execFileSync('/bin/sh', ['-c', `printf '%s\\n' ${filesGlob(d)}`], { encoding: 'utf8' })
      .split('\n')
      .filter(Boolean);
    expect(files).toEqual([join(d, 'clean.txt')]);
    const cap = capture();
    const code = await run(['scan', ...files]);
    cap.restore();
    expect(code).toBe(0);
  });

  // The glob is pasted into a shell, so the shell has to read the directory's
  // name back out of it.
  it('writes the glob for a directory as one shell word that names the directory', () => {
    const cases: Array<[string, string]> = [
      ['adir', 'adir'],
      ['adir//', 'adir'],
      ["it's a dir", "it's a dir"],
      ['$HOME and `x`', '$HOME and `x`'],
      ['-dash dir', './-dash dir'],
    ];
    for (const [name, read] of cases) {
      // set -f stops the shell expanding the glob, so it prints the word itself.
      const word = execFileSync('/bin/sh', ['-c', `set -f; printf '%s\\n' ${filesGlob(name)}`], {
        encoding: 'utf8',
      });
      expect({ name, word }).toEqual({ name, word: `${read}/*.txt\n` });
    }
    expect(filesGlob('/')).toBe('/*.txt');
  });

  // `--` ends the options (POSIX utility syntax guideline 10), so a file whose
  // name starts with - can be scanned. It used to be an unknown option.
  describe('-- ends the options', () => {
    function inDir<T>(fn: () => Promise<T>): Promise<T> {
      const cwd = process.cwd();
      process.chdir(dir);
      return fn().finally(() => process.chdir(cwd));
    }

    it('scans the file named after --', async () => {
      const f = fixture('after-dashes.txt', 'The weather is nice today.');
      const cap = capture();
      const code = await run(['scan', '--', f]);
      cap.restore();
      expect({ code, err: cap.err.join('') }).toEqual({ code: 0, err: '' });
      expect(cap.out.join('')).toContain(`CLEAN      ${f}`);
    });

    it('reads each argument after -- as a file, even one that starts with -', async () => {
      fixture('-dash.txt', 'The weather is nice today.');
      fixture('--json', 'SSN 078-05-1120');
      const cap = capture();
      const code = await inDir(() => run(['scan', '--', '-dash.txt', '--json']));
      cap.restore();
      expect({ code, err: cap.err.join('') }).toEqual({ code: 1, err: '' });
      // Human output, so the --json after -- was a file and not the option.
      const out = cap.out.join('');
      expect(out).toMatch(/^ {2}CLEAN {6}-dash\.txt /m);
      expect(out).toMatch(/^ {2}VIOLATION {2}--json /m);
    });

    it('keeps the options given before --', async () => {
      fixture('-dash.txt', 'The weather is nice today.');
      const cap = capture();
      const code = await inDir(() => run(['scan', '--json', '--', '-dash.txt']));
      cap.restore();
      expect(code).toBe(0);
      expect(JSON.parse(cap.out.join(''))).toMatchObject([{ source: '-dash.txt', verdict: 'CLEAN' }]);
    });

    it('reads a second -- as a file name', async () => {
      const cap = capture();
      const code = await inDir(() => run(['scan', '--', '--']));
      cap.restore();
      expect({ code, err: cap.err.join('') }).toEqual({
        code: 2,
        err: "aicomply: cannot read '--' (check the path). Try 'aicomply --help'.\n",
      });
    });

    it('without --, still reads an argument that starts with - as an option', async () => {
      fixture('-dash.txt', 'The weather is nice today.');
      const cap = capture();
      const code = await inDir(() => run(['scan', '-dash.txt']));
      cap.restore();
      expect({ code, err: cap.err.join('') }).toEqual({ code: 2, err: "aicomply: unknown option '-dash.txt'\n" });
    });

    it('is documented in --help and scan --help', async () => {
      for (const argv of [['--help'], ['scan', '--help']]) {
        const cap = capture();
        await run(argv);
        cap.restore();
        expect(cap.out.join('')).toContain(
          '  --            Ends the options; each later argument is an input, so a file\n' +
            '                name can start with - (aicomply scan -- -notes.txt)\n',
        );
      }
    });
  });

  it('clean content exits 0', async () => {
    const f = fixture('clean.txt', 'The weather is nice today.');
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('')).toContain('CLEAN');
  });

  // CLEAN states what the layers that ran found. It is also the verdict for an
  // input the README lists as not detected, so it must never read as a
  // statement that the content is safe.
  it('words a CLEAN verdict as what was checked', async () => {
    const f = fixture('clean-verdict.txt', 'The weather is nice today.');
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    expect(code).toBe(0);
    expect(cap.out.join('').trimEnd().split('\n').pop()).toBe(
      'Verdict: CLEAN  ·  no findings from the layers that ran.',
    );
  });

  it('does not call an SSN split by a soft hyphen safe', async () => {
    const f = fixture('soft-hyphen.txt', 'SSN 12­3-45-6789\n');
    const cap = capture();
    await run(['scan', f]);
    cap.restore();
    const verdictLine = cap.out.join('').trimEnd().split('\n').pop() ?? '';
    expect(verdictLine.startsWith('Verdict: ')).toBe(true);
    expect(verdictLine).not.toMatch(/safe/i);
  });

  // The pattern pack has no class for an email address, a phone number, a
  // postal address, a date or a name, so content holding only those is CLEAN.
  // The per-input line names what was checked, not "no PII".
  it('words a CLEAN input as the pattern classes checked, not as no PII', async () => {
    const email = ['jane.doe', 'example.com'].join('@');
    const phone = '(303) 555-0142';
    const f = fixture('contact.txt', `Reach me at ${email} or ${phone}\n`);
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    expect(code).toBe(0);
    const line = cap.out.join('').split('\n').find((l) => l.includes(f)) ?? '';
    expect(line).toContain('CLEAN');
    expect(line).not.toContain('PII');
    expect(line).toContain(` ${PATTERN_TYPES.length} pattern classes `);
    expect(line).not.toMatch(/\bsafe\b/i);
  });

  it('--help and scan --help name the pattern classes and link what is not detected', async () => {
    for (const argv of [['--help'], ['scan', '--help']]) {
      const cap = capture();
      await run(argv);
      cap.restore();
      const out = cap.out.join('');
      expect(out).toContain('docs/detection.md');
      expect(out).not.toContain('Detects PII,');
      expect(out).not.toContain('(PII, credentials, regulated data)');
    }
    // The per-input CLEAN line says `aicomply --help` lists the classes.
    const cap = capture();
    await run(['--help']);
    cap.restore();
    const out = cap.out.join('');
    for (const type of PATTERN_TYPES) {
      expect({ type, listed: new RegExp(`^  ${type} +\\S`, 'm').test(out) }).toEqual({ type, listed: true });
    }
    expect(out).toMatch(/e-?mail addresses/i);
    expect(out).toMatch(/phone numbers/i);
  });

  it('--help and scan --help describe exit code 0 as what was checked', async () => {
    for (const argv of [['--help'], ['scan', '--help']]) {
      const cap = capture();
      await run(argv);
      cap.restore();
      const out = cap.out.join('');
      expect(out).toContain('  0  CLEAN          no findings from the layers that ran\n');
      expect(out).not.toMatch(/\bsafe\b/i);
    }
  });

  it('PII content exits 1 and masks the value (never prints the full secret)', async () => {
    const f = fixture('pii.txt', 'My SSN is 123-45-6789 please update.');
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    const text = cap.out.join('');
    expect(code).toBe(1);
    expect(text).toContain('SSN');
    expect(text).toContain('•'); // masked
    expect(text).not.toContain('123-45-6789'); // full value never leaks
  });

  it('--json emits structured findings with maskedValue', async () => {
    const f = fixture('cred.txt', 'aws key AKIAIOSFODNN7EXAMPLE here');
    const cap = capture();
    const code = await run(['scan', f, '--json']);
    cap.restore();
    expect(code).toBe(1);
    const payload = JSON.parse(cap.out.join(''));
    expect(Array.isArray(payload)).toBe(true);
    expect(payload[0].verdict).toBe('VIOLATION');
    expect(payload[0].findings[0]).toHaveProperty('maskedValue');
    expect(payload[0].findings[0].maskedValue).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(payload[0].findings[0].view).toBe('normalized');
  });

  it('--json prints a null view for a finding that has none', async () => {
    // A Guard finding does not come from a content view. The JSON used to
    // default it to 'normalized', claiming a canonicalization that never ran.
    const { renderJson } = await import('../cli');
    const guard = guardResult('guard');
    delete (guard.violations[0] as { view?: unknown }).view;
    const cap = capture();
    try {
      renderJson([{ label: 'x.txt', content: 'c' } as never], [guard]);
    } finally {
      cap.restore();
    }
    const payload = JSON.parse(cap.out.join(''));
    expect(payload[0].findings[0]).toHaveProperty('view', null);
  });

  it('prints no characters of a detected value', async () => {
    // A 7-character passport or record number used to print 6 of its 7
    // characters (A123•••56) and an SSN 5 of its 9 digits (123-•••89).
    const f = fixture('short.txt', 'Passport: A123456\nMRN: 1234567\nSSN 123-45-6789\n');
    const cap = capture();
    const code = await run(['scan', f]);
    cap.restore();
    const text = cap.out.join('');
    expect(code).toBe(1);
    expect(text).toMatch(/ {4}PASSPORT {5}••• {16}confidence/);
    expect(text).toMatch(/ {4}MRN {10}••• {16}confidence/);
    expect(text).toMatch(/ {4}SSN {10}••• {16}confidence/);
    for (const fragment of ['A123', '56 ', '1234', '67 ', '123-', '89 ']) {
      expect(text).not.toContain(fragment);
    }

    const capJson = capture();
    await run(['scan', f, '--json']);
    capJson.restore();
    const payload = JSON.parse(capJson.out.join(''));
    const masked = Object.fromEntries(
      payload[0].findings.map((x: { type: string; maskedValue: string }) => [x.type, x.maskedValue]),
    );
    expect(masked).toEqual({ PASSPORT: '•••', MRN: '•••', SSN: '•••' });
  });

  it('--quiet prints only the verdict word', async () => {
    const f = fixture('pii2.txt', 'SSN 078-05-1120');
    const cap = capture();
    const code = await run(['scan', f, '--quiet']);
    cap.restore();
    expect(code).toBe(1);
    expect(cap.out.join('').trim()).toBe('VIOLATION');
  });

  it('multi-file scan surfaces the worst verdict and exits 1 if any input is dirty', async () => {
    const clean = fixture('a.txt', 'nothing here');
    const dirty = fixture('b.txt', 'card 4111111111111111');
    const cap = capture();
    const code = await run(['scan', clean, dirty, '--quiet']);
    cap.restore();
    expect(code).toBe(1);
    expect(cap.out.join('').trim()).toBe('VIOLATION');
  });

  // With files named and no `-` among them, stdin is not scanned. The CLI
  // learns what stdin holds from fstat of descriptor 0, never by reading it,
  // so each test reports a real path's stats for descriptor 0: a FIFO (a shell
  // pipe), a socket (a Node child's pipe), /dev/null, or a regular file.
  describe('stdin when files are named without -', () => {
    const NOT_READ = 'aicomply: stdin not read because files were named; add - to scan it too\n';
    // mkfifo and a Unix socket path are POSIX-only.
    const posixIt = process.platform === 'win32' ? it.skip : it;
    let fifo: string;
    let socketPath: string;
    let server: Server | undefined;

    beforeAll(async () => {
      if (process.platform === 'win32') return;
      fifo = join(dir, 'stdin.fifo');
      execFileSync('mkfifo', [fifo]);
      socketPath = join(dir, 'stdin.sock');
      const listening = createServer();
      await new Promise<void>((resolve) => listening.listen(socketPath, resolve));
      server = listening;
    });
    afterAll(async () => {
      if (server) await new Promise<void>((resolve) => server?.close(() => resolve()));
    });

    posixIt.each([['human', []], ['--json', ['--json']], ['--quiet', ['--quiet']]])(
      'does not open a pipe and says so in one stderr line (%s output)',
      async (_mode, flags) => {
        const clean = fixture('named-clean.txt', 'The weather is nice today.');
        stdinIs(fifo);
        const stdinGet = jest.spyOn(process, 'stdin', 'get');
        const cap = capture();
        const code = await run(['scan', clean, ...(flags as string[])]);
        cap.restore();
        expect(code).toBe(0);
        expect(cap.err.join('')).toBe(NOT_READ);
        expect(stdinGet).not.toHaveBeenCalled();
      },
    );

    posixIt('keeps the exit code of the files with a socket on stdin', async () => {
      const dirty = fixture('named-dirty.txt', 'SSN 078-05-1120\n');
      stdinIs(socketPath);
      const stdinGet = jest.spyOn(process, 'stdin', 'get');
      const cap = capture();
      const code = await run(['scan', dirty, '--quiet']);
      cap.restore();
      expect(code).toBe(1);
      expect(cap.out.join('')).toBe('VIOLATION\n');
      expect(cap.err.join('')).toBe(NOT_READ);
      expect(stdinGet).not.toHaveBeenCalled();
    });

    it('refuses a file with content on stdin and names the combined form', async () => {
      const clean = fixture('named-clean.txt', 'The weather is nice today.');
      stdinIs(fixture('stdin-content.txt', 'SSN 078-05-1120\n'));
      const stdinGet = jest.spyOn(process, 'stdin', 'get');
      for (const flags of [[], ['--json'], ['--quiet']]) {
        const cap = capture();
        const code = await run(['scan', clean, ...flags]);
        cap.restore();
        expect({ flags, code, out: cap.out.join('') }).toEqual({ flags, code: 2, out: '' });
        expect(cap.err.join('')).toContain('\n  aicomply scan - <files>\n');
      }
      expect(stdinGet).not.toHaveBeenCalled();
    });

    it.each([
      ['/dev/null', () => devNull],
      ['an empty file', () => fixture('stdin-empty.txt', '')],
    ])('prints nothing about stdin when it is %s', async (_name, path) => {
      const clean = fixture('named-clean.txt', 'The weather is nice today.');
      stdinIs(path());
      const cap = capture();
      const code = await run(['scan', clean]);
      cap.restore();
      expect(code).toBe(0);
      expect(cap.err.join('')).toBe('');
    });

    it('reads stdin as before when - is among the files', async () => {
      const clean = fixture('named-clean.txt', 'The weather is nice today.');
      stdinIs(fixture('stdin-content.txt', 'SSN 078-05-1120\n'));
      const piped = new PassThrough();
      piped.end('SSN 078-05-1120\n');
      jest.spyOn(process, 'stdin', 'get').mockReturnValue(piped as unknown as typeof process.stdin);
      const cap = capture();
      const code = await run(['scan', '-', clean, '--quiet']);
      cap.restore();
      expect(code).toBe(1);
      expect(cap.out.join('')).toBe('VIOLATION\n');
      expect(cap.err.join('')).toBe('');
    });
  });

  // The value is masked, so a finding's location is the only thing a user can
  // search for in a long log or a staged diff. Line and column are 1-based
  // positions in the original content of the input.
  describe('finding location', () => {
    const line3 = 'ticket: SSN 078-05-1120 on file';
    const content = `line one\nline two\n${line3}\n`;
    const column = line3.indexOf('078-05-1120') + 1;

    it('locate: a match at index 0 is line 1 col 1', () => {
      expect(locate('078-05-1120', 0)).toEqual({ line: 1, column: 1 });
    });

    it('locate: a match after two newlines is on line 3', () => {
      const start = content.indexOf('078-05-1120');
      expect(locate(content, start)).toEqual({ line: 3, column });
    });

    it('locate: only \\n ends a line, so \\r stays on the previous line', () => {
      const crlf = `line one\r\nline two\r\n${line3}\r\n`;
      expect(locate(crlf, crlf.indexOf('078-05-1120'))).toEqual({ line: 3, column });
      // A match on the \r itself is the last character of line 1.
      expect(locate(crlf, crlf.indexOf('\r'))).toEqual({ line: 1, column: 'line one'.length + 1 });
    });

    it('locate: no original position gives no location', () => {
      expect(locate(content, undefined)).toBeUndefined();
    });

    it('ends the finding line with the line and column of the match', async () => {
      const f = fixture('located.txt', content);
      const cap = capture();
      const code = await run(['scan', f]);
      cap.restore();
      expect(code).toBe(1);
      const findingLine = cap.out.join('').split('\n').find((l) => l.startsWith('    SSN '));
      expect(findingLine).toMatch(/^ {4}SSN {10}••• {16}confidence /);
      expect(findingLine?.endsWith(`layer regex  line 3 col ${column}`)).toBe(true);
    });

    it('--json gives each finding a line and column after view', async () => {
      const f = fixture('located-json.txt', content);
      const cap = capture();
      await run(['scan', f, '--json']);
      cap.restore();
      const finding = JSON.parse(cap.out.join(''))[0].findings[0];
      expect(finding).toMatchObject({ type: 'SSN', view: 'normalized', line: 3, column });
      expect(Object.keys(finding)).toEqual([
        'type', 'maskedValue', 'confidence', 'classifier', 'view', 'line', 'column',
      ]);
    });

    it('locates a decoded-base64 finding at its encoded token', async () => {
      const encoded = Buffer.from('My SSN is 078-05-1120').toString('base64');
      const f = fixture('located-b64.txt', `note\n${encoded}\n`);
      const cap = capture();
      await run(['scan', f, '--json']);
      cap.restore();
      const finding = JSON.parse(cap.out.join(''))[0].findings[0];
      expect(finding).toMatchObject({ type: 'SSN', view: 'decoded-base64', line: 2, column: 1 });
    });

    it('prints no location for a finding without original positions', async () => {
      const { renderHuman, renderJson } = await import('../cli');
      const guard = guardResult('guard');
      delete (guard.violations[0] as { view?: unknown }).view;
      const sources = [{ label: 'x.txt', content: 'line one\nline two\n' }];

      const cap = capture();
      try {
        renderHuman(sources, [guard]);
      } finally {
        cap.restore();
      }
      const findingLine = cap.out.join('').split('\n').find((l) => l.startsWith('    tool_misuse '));
      expect(findingLine?.endsWith('layer guard')).toBe(true);

      const capJson = capture();
      try {
        renderJson(sources, [guard]);
      } finally {
        capJson.restore();
      }
      const finding = JSON.parse(capJson.out.join(''))[0].findings[0];
      expect(finding).toHaveProperty('line', null);
      expect(finding).toHaveProperty('column', null);
    });
  });
});
