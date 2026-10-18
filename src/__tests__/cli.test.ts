/**
 * CLI behavior tests. The CLI is the zero-integration try-path; these assert the
 * contract a consumer (or a CI gate) relies on: exit codes, masking, and output
 * shape. Detection accuracy itself is covered by the regex/dual-layer suites.
 */

import { execFileSync, spawn, spawnSync } from 'child_process';
import fs, { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { createServer, type Server } from 'net';
import { devNull, tmpdir } from 'os';
import { join } from 'path';
import { PassThrough, Readable } from 'stream';
import { decodeInput, filesGlob, locate, run } from '../cli';
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

/** Serve `data` as stdin from a pipe, not a terminal; afterEach restores it. */
function pipeStdin(data: string | Buffer): void {
  const stream = Readable.from(data.length === 0 ? [] : [Buffer.from(data)]);
  jest.spyOn(process, 'stdin', 'get').mockReturnValue(stream as unknown as typeof process.stdin);
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

  // Drift guard: --version must match package.json (a CLI reporting the wrong
  // version was caught at release 2.2.1).
  it('--version matches package.json version', async () => {
    const pkg = require('../../package.json') as { version: string };
    const cap = capture();
    await run(['--version']);
    cap.restore();
    expect(cap.out.join('').trim()).toBe(pkg.version);
  });

  // package.json is the one version source: `npm version` bumps only that file,
  // so --version must follow it rather than a literal in the CLI source.
  it('--version reports the version package.json holds at run time', async () => {
    const realRead = fs.readFileSync;
    const readSpy = jest
      .spyOn(fs, 'readFileSync')
      .mockImplementation(((path: fs.PathOrFileDescriptor, options?: unknown) =>
        typeof path === 'string' && path.endsWith('package.json')
          ? JSON.stringify({ name: '@opena2a/aicomply', version: '9.8.7' })
          : realRead(path, options as BufferEncoding)) as typeof fs.readFileSync);
    const cap = capture();
    try {
      await run(['--version']);
    } finally {
      cap.restore();
      readSpy.mockRestore();
    }
    expect(cap.out.join('').trim()).toBe('9.8.7');
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

    // A run whose named files are all 0 bytes ends with no input before any
    // report, and the pipe it left unread can hold the content meant for it.
    posixIt.each([['human', []], ['--json', ['--json']], ['--quiet', ['--quiet']]])(
      'adds the line after no input when every named file is 0 bytes (%s output)',
      async (_mode, flags) => {
        const empty = fixture('named-empty.txt', '');
        stdinIs(fifo);
        const stdinGet = jest.spyOn(process, 'stdin', 'get');
        const cap = capture();
        const code = await run(['scan', empty, ...(flags as string[])]);
        cap.restore();
        expect({ code, out: cap.out.join('') }).toEqual({ code: 2, out: '' });
        expect(cap.err.join('')).toBe(`aicomply: no input: ${empty} is 0 bytes\n${NOT_READ}`);
        expect(stdinGet).not.toHaveBeenCalled();
      },
    );

    posixIt('names each file of 0 bytes, then the line, with a socket on stdin', async () => {
      const a = fixture('named-empty-a.txt', '');
      const b = fixture('named-empty-b.txt', '');
      stdinIs(socketPath);
      const stdinGet = jest.spyOn(process, 'stdin', 'get');
      const cap = capture();
      const code = await run(['scan', a, b, '--quiet']);
      cap.restore();
      expect({ code, out: cap.out.join('') }).toEqual({ code: 2, out: '' });
      expect(cap.err.join('')).toBe(
        `aicomply: no input: ${a} is 0 bytes, ${b} is 0 bytes\n${NOT_READ}`,
      );
      expect(stdinGet).not.toHaveBeenCalled();
    });

    it.each([
      ['/dev/null', () => devNull],
      ['an empty file', () => fixture('stdin-empty.txt', '')],
    ])('gives only no input when every named file is 0 bytes and stdin is %s', async (_name, path) => {
      const empty = fixture('named-empty.txt', '');
      stdinIs(path());
      const cap = capture();
      const code = await run(['scan', empty]);
      cap.restore();
      expect(code).toBe(2);
      expect(cap.err.join('')).toBe(`aicomply: no input: ${empty} is 0 bytes\n`);
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

  // comply() runs no layer on empty content and returns CLEAN, so a stdin that
  // was never connected, or an empty file, must not pass the gate as CLEAN.
  describe('input of 0 bytes', () => {
    const MODES = [[], ['--json'], ['--quiet']];

    it('exits 2 with no input on stderr and nothing on stdout when stdin delivers 0 bytes', async () => {
      for (const mode of MODES) {
        pipeStdin('');
        const cap = capture();
        const code = await run(['scan', ...mode]);
        cap.restore();
        expect({ mode, code, out: cap.out.join(''), err: cap.err.join('') }).toEqual({
          mode,
          code: 2,
          out: '',
          err: 'aicomply: no input: (stdin) delivered 0 bytes\n',
        });
      }
    });

    it('exits 2 with no input on stderr and nothing on stdout for a file of 0 bytes', async () => {
      const f = fixture('empty.txt', '');
      for (const mode of MODES) {
        const cap = capture();
        const code = await run(['scan', f, ...mode]);
        cap.restore();
        expect({ mode, code, out: cap.out.join(''), err: cap.err.join('') }).toEqual({
          mode,
          code: 2,
          out: '',
          err: `aicomply: no input: ${f} is 0 bytes\n`,
        });
      }
    });

    it('names each input when none of them carried a byte', async () => {
      const a = fixture('empty-a.txt', '');
      const b = fixture('empty-b.txt', '');
      pipeStdin('');
      const cap = capture();
      const code = await run(['scan', a, '-', b]);
      cap.restore();
      expect(code).toBe(2);
      expect(cap.out.join('')).toBe('');
      expect(cap.err.join('')).toBe(
        `aicomply: no input: ${a} is 0 bytes, ${b} is 0 bytes, (stdin) delivered 0 bytes\n`,
      );
    });

    it('scans an input of whitespace only, and --json gives its bytes and layers', async () => {
      pipeStdin('\n');
      const cap = capture();
      const code = await run(['scan', '--json']);
      cap.restore();
      expect(code).toBe(0);
      expect(cap.err.join('')).toBe('');
      const [entry] = JSON.parse(cap.out.join(''));
      expect(Object.keys(entry)).toEqual([
        'source', 'bytes', 'verdict', 'guardActive', 'layers', 'findings',
      ]);
      expect(entry).toEqual({
        source: '(stdin)',
        bytes: 1,
        verdict: 'CLEAN',
        guardActive: false,
        layers: ['normalize', 'regex'],
        findings: [],
      });
    });

    it('reports an input of 0 bytes beside others, and the scanned inputs decide the exit', async () => {
      const empty = fixture('empty-beside.txt', '');
      const clean = fixture('clean-beside.txt', 'nothing here');
      const dirty = fixture('dirty-beside.txt', 'card 4111111111111111');

      const cap = capture();
      const code = await run(['scan', empty, clean]);
      cap.restore();
      expect(code).toBe(0);
      const lines = cap.out.join('').trimEnd().split('\n');
      expect(lines).toContain(`  EMPTY      ${empty}   0 bytes, nothing to classify`);
      expect(lines.pop()).toBe('Verdict: CLEAN  ·  no findings from the layers that ran.');

      const capJson = capture();
      const jsonCode = await run(['scan', empty, clean, '--json']);
      capJson.restore();
      expect(jsonCode).toBe(0);
      const [emptyEntry, cleanEntry] = JSON.parse(capJson.out.join(''));
      expect(emptyEntry).toMatchObject({ source: empty, bytes: 0, layers: [], findings: [] });
      expect(cleanEntry).toMatchObject({
        source: clean,
        bytes: 'nothing here'.length,
        layers: ['normalize', 'regex'],
      });

      const capQuiet = capture();
      const dirtyCode = await run(['scan', empty, dirty, '--quiet']);
      capQuiet.restore();
      expect(dirtyCode).toBe(1);
      expect(capQuiet.out.join('')).toBe('VIOLATION\n');
    });

    it('--help and scan --help give the exit code for no input', async () => {
      for (const argv of [['--help'], ['scan', '--help']]) {
        const cap = capture();
        await run(argv);
        cap.restore();
        expect(cap.out.join('')).toContain(
          '  2  usage error, or no input: stdin is a terminal or every input is 0 bytes\n',
        );
      }
    });
  });

  // The value is masked, so a finding's location is the only thing a user can
  // search for in a long log or a staged diff. Line and column are 1-based
  // positions in the original content of the input.
  // Text that starts with a UTF-32 or UTF-16 byte order mark is decoded in
  // that encoding without the mark. Decoded as UTF-8 it reached the patterns
  // with NUL characters between its letters and was reported CLEAN.
  describe('input with a UTF-16 or UTF-32 byte order mark', () => {
    const text = 'Customer SSN 078-05-1120 on file\n';
    const utf16be = (s: string) => Buffer.from(s, 'utf16le').swap16();
    const utf32 = (s: string, le: boolean) => {
      const cps = [...s].map((c) => c.codePointAt(0) as number);
      const b = Buffer.alloc(cps.length * 4);
      cps.forEach((cp, i) => (le ? b.writeUInt32LE(cp, i * 4) : b.writeUInt32BE(cp, i * 4)));
      return b;
    };
    const INPUTS: Array<[string, Buffer]> = [
      ['utf-16-le', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')])],
      ['utf-16-be', Buffer.concat([Buffer.from([0xfe, 0xff]), utf16be(text)])],
      ['utf-32-le', Buffer.concat([Buffer.from([0xff, 0xfe, 0, 0]), utf32(text, true)])],
      ['utf-32-be', Buffer.concat([Buffer.from([0, 0, 0xfe, 0xff]), utf32(text, false)])],
    ];

    it('decodeInput drops the mark and returns the text', () => {
      for (const [name, data] of INPUTS) {
        expect({ name, text: decodeInput(data) }).toEqual({ name, text });
      }
    });

    it.each(INPUTS)('reports the SSN in a %s file and on stdin', async (name, data) => {
      const p = join(dir, `${name}.txt`);
      writeFileSync(p, data);
      for (const [source, args] of [[p, [p]], ['(stdin)', []]] as Array<[string, string[]]>) {
        if (args.length === 0) pipeStdin(data);
        const cap = capture();
        const code = await run(['scan', ...args, '--json']);
        cap.restore();
        expect(cap.err.join('')).toBe('');
        expect(code).toBe(1);
        const [entry] = JSON.parse(cap.out.join(''));
        expect(entry).toMatchObject({ source, bytes: data.length, verdict: 'VIOLATION' });
        expect(entry.findings.map((f: { type: string; line: number; column: number }) => [f.type, f.line, f.column]))
          .toEqual([['SSN', 1, 14]]);
      }
    });

    // UTF-32LE: a surrogate unit, a unit above U+10FFFF and 2 bytes left over;
    // UTF-16BE: a lone high surrogate and 1 byte left over. Each becomes one
    // U+FFFD, as in the Python CLI.
    it('turns units that do not decode into one U+FFFD each', () => {
      const ssn = 'SSN 078-05-1120 ';
      const u32 = Buffer.concat([
        Buffer.from([0xff, 0xfe, 0, 0, 0x00, 0xd8, 0, 0, 0xff, 0xff, 0x11, 0]),
        utf32(ssn, true),
        Buffer.from([0x5a, 0]),
      ]);
      const u16 = Buffer.concat([Buffer.from([0xfe, 0xff, 0xd8, 0x00]), utf16be(ssn), Buffer.from([0x5a])]);
      expect(decodeInput(u32)).toBe(`��${ssn}�`);
      expect(decodeInput(u16)).toBe(`�${ssn}�`);
    });

    it('keeps decoding other input as UTF-8, a UTF-8 mark included', () => {
      expect(decodeInput(Buffer.from('\u{FEFF}SSN', 'utf8'))).toBe('\u{FEFF}SSN');
      expect(decodeInput(Buffer.from([0x62, 0xff, 0xfe]))).toBe('b��');
    });
  });

  describe('finding location', () => {
    const line3 ='ticket: SSN 078-05-1120 on file';
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

    // The column counts code points, as the Python CLI does. A character
    // outside the Basic Multilingual Plane is two UTF-16 code units of a JS
    // string and one code point.
    const emoji = '\u{1F600}';

    it('locate: a character outside the BMP before the match is one column', () => {
      const text = `${emoji}${emoji} SSN 078-05-1120`;
      expect(locate(text, text.indexOf('078-05-1120'))).toEqual({ line: 1, column: 8 });
    });

    it('locate: a character outside the BMP on an earlier line leaves the column alone', () => {
      const text = `${emoji}${emoji}\nSSN 078-05-1120`;
      expect(locate(text, text.indexOf('078-05-1120'))).toEqual({ line: 2, column: 5 });
    });

    it('locate: a lone surrogate is one code point', () => {
      // A lone high surrogate, then one that pairs with the low surrogate after it.
      const text = `\uD83D${emoji} SSN 078-05-1120`;
      expect(locate(text, text.indexOf('078-05-1120'))).toEqual({ line: 1, column: 8 });
    });

    it('prints the column in code points when a character outside the BMP precedes the match', async () => {
      const f = fixture('located-emoji.txt', `${emoji}${emoji} SSN 078-05-1120\n`);
      const capJson = capture();
      await run(['scan', f, '--json']);
      capJson.restore();
      const finding = JSON.parse(capJson.out.join(''))[0].findings[0];
      expect(finding).toMatchObject({ type: 'SSN', line: 1, column: 8 });

      const cap = capture();
      await run(['scan', f]);
      cap.restore();
      const findingLine = cap.out.join('').split('\n').find((l) => l.startsWith('    SSN '));
      expect(findingLine?.endsWith('layer regex  line 1 col 8')).toBe(true);
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
      const sources = [{ label: 'x.txt', content: 'line one\nline two\n', bytes: 18 }];

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

  // The bin wrapper exits the process, so it runs only when cli.ts is the main
  // module. These tests start the source in a child process, with a preloaded
  // hook that transpiles each .ts file as it is required: the release workflow
  // runs `npm test` before `npm run build`, and a local dist/ can be stale.
  const CLI = join(__dirname, '..', 'cli.ts');
  const HOOK = `const { readFileSync } = require('fs');
const ts = require(${JSON.stringify(require.resolve('typescript'))});
require.extensions['.ts'] = (module, filename) => {
  const { outputText } = ts.transpileModule(readFileSync(filename, 'utf8'), {
    fileName: filename,
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
  });
  module._compile(outputText, filename);
};
`;
  // Warnings from the Node.js runtime would land on the stderr these tests read.
  const ENV = { ...process.env, NODE_NO_WARNINGS: '1' };

  describe('output through a pipe', () => {
    // 3,000 findings take both output formats far past a 64 KiB pipe buffer.
    const content = Array.from(
      { length: 3000 },
      (_, i) => `ticket ${i + 1}: SSN 078-05-1120 on file\n`,
    ).join('');
    let hook: string;
    let log: string;

    beforeAll(() => {
      hook = fixture('transpile-hook.js', HOOK);
      log = fixture('many.log', content);
    });

    function start(args: string[]) {
      return spawn(process.execPath, ['-r', hook, CLI, ...args], {
        env: ENV,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    }

    /** The child's exit code and stderr, once it has exited and its pipes have closed. */
    function finished(child: ReturnType<typeof start>): Promise<{ code: number | null; stderr: string }> {
      let stderr = '';
      child.stderr.setEncoding('utf8').on('data', (c: string) => (stderr += c));
      return new Promise((resolve, reject) => {
        child.on('error', reject);
        child.on('close', (code) => resolve({ code, stderr }));
      });
    }

    /**
     * What the CLI writes when its stdout is a regular file. Without `input`,
     * stdin is /dev/null, as start() gives it: a pipe on stdin beside a named
     * file adds the CLI's "stdin not read" line to stderr.
     */
    function outputToFile(args: string[], input?: string): Buffer {
      const path = join(dir, 'stdout.txt');
      const fd = openSync(path, 'w');
      try {
        const child = spawnSync(process.execPath, ['-r', hook, CLI, ...args], {
          env: ENV,
          input,
          stdio: [input === undefined ? 'ignore' : 'pipe', fd, 'pipe'],
        });
        expect({ status: child.status, stderr: child.stderr.toString() }).toEqual({ status: 1, stderr: '' });
      } finally {
        closeSync(fd);
      }
      return readFileSync(path);
    }

    /**
     * Runs the CLI with stdout as a pipe that is left unread until the child
     * exits or `holdMs` passes, whichever comes first. A CLI that exits with
     * output still queued loses what the pipe did not hold, however small each
     * of its writes is.
     */
    async function cliIntoHeldPipe(
      args: string[],
      holdMs: number,
    ): Promise<{ code: number | null; stderr: string; stdout: Buffer }> {
      const child = start(args);
      const done = finished(child);
      const chunks: Buffer[] = [];
      let reading = false;
      const read = () => {
        if (reading) return;
        reading = true;
        clearTimeout(timer);
        child.stdout.on('data', (c: Buffer) => chunks.push(c));
      };
      const timer = setTimeout(read, holdMs);
      child.on('exit', read);
      return { ...(await done), stdout: Buffer.concat(chunks) };
    }

    it('--json from stdin to a pipe is byte for byte the output written to a file', () => {
      // `cat transcript.log | npx @opena2a/aicomply scan --json`, as the README shows it.
      const expected = outputToFile(['scan', '--json'], content);
      const piped = spawnSync(process.execPath, ['-r', hook, CLI, 'scan', '--json'], {
        env: ENV,
        input: content,
        maxBuffer: 16 * 1024 * 1024,
      });
      expect({ status: piped.status, stderr: piped.stderr.toString() }).toEqual({ status: 1, stderr: '' });
      expect(piped.stdout.length).toBe(expected.length);
      expect(piped.stdout.equals(expected)).toBe(true);
      expect(JSON.parse(piped.stdout.toString('utf8'))[0].findings).toHaveLength(3000);
    }, 60_000);

    it('human-readable output to a pipe keeps its last lines when the reader lags behind', async () => {
      const expected = outputToFile(['scan', log]);
      const piped = await cliIntoHeldPipe(['scan', log], 2000);
      expect({ code: piped.code, stderr: piped.stderr }).toEqual({ code: 1, stderr: '' });
      expect(piped.stdout.length).toBe(expected.length);
      expect(piped.stdout.equals(expected)).toBe(true);
      expect(piped.stdout.toString('utf8').trimEnd().split('\n').pop()).toMatch(
        /^Verdict: VIOLATION {2}· {2}3000 findings across 1 input\. /,
      );
    }, 60_000);

    it('exits with the verdict code and no error output when the reader closes the pipe early', async () => {
      // Like `aicomply scan many.log --json | head -c 1`.
      const child = start(['scan', log, '--json']);
      const done = finished(child);
      child.stdout.once('data', () => child.stdout.destroy());
      expect(await done).toEqual({ code: 1, stderr: '' });
    }, 60_000);
  });

  describe('input of many megabytes', () => {
    // A scan of a 77 MB file ended with "JavaScript heap out of memory" and
    // exit 134: normalization held an array entry, and in the compact view an
    // object, for each character. Before the change, the scan below ran out
    // of heap with a 512 MB limit.
    let hook: string;
    let large: string;

    beforeAll(() => {
      hook = fixture('transpile-hook.js', HOOK);
      large = fixture(
        'large.txt',
        'filler line with nothing sensitive in it at all\n'.repeat(333_333) +
          'Customer SSN 078-05-1120 on file\n',
      );
    });

    it('reports the finding in a 16 MB file with a 128 MB heap limit', () => {
      expect(fs.statSync(large).size).toBe(16_000_017);
      const child = spawnSync(
        process.execPath,
        ['--max-old-space-size=128', '-r', hook, CLI, 'scan', large, '--quiet'],
        { env: ENV, stdio: ['ignore', 'pipe', 'pipe'] },
      );
      expect({
        status: child.status,
        stdout: child.stdout.toString(),
        stderr: child.stderr.toString(),
      }).toEqual({ status: 1, stdout: 'VIOLATION\n', stderr: '' });
    }, 60_000);
  });
});
