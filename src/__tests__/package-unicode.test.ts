/**
 * Package unicode tests. The tarball `npm pack` builds carries no .hmaignore,
 * so a HackMyAgent scan of the installed package reads every shipped file with
 * its UNICODE-STEGO checks on. A zero-width space (UNICODE-STEGO-001) or a
 * Cyrillic look-alike letter (UNICODE-STEGO-005) written literally into a
 * shipped Markdown example is then reported against the package, so the docs
 * name such a character by its code point (for example U+200B) instead. These
 * tests run the unicode check of the HackMyAgent dev dependency over a copy of
 * the packed files.
 */

import { execFileSync } from 'child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';

const ROOT = join(__dirname, '..', '..');

interface StegoFinding {
  checkId: string;
  file?: string;
  line?: number;
}

interface UnicodeScanner {
  checkUnicodeSteganography(targetDir: string, autoFix: boolean): Promise<StegoFinding[]>;
}

/**
 * HackMyAgent's scanner, loaded by its path beside the package entry point:
 * the entry point also loads an ESM-only dependency that jest does not
 * transform.
 */
const { HardeningScanner } = require(join(dirname(require.resolve('hackmyagent')), 'hardening', 'scanner.js')) as {
  HardeningScanner: new () => UnicodeScanner;
};

/** Every path `npm pack` would put in the tarball, relative to the package root. */
function packedFiles(): string[] {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const [pack] = JSON.parse(out) as Array<{ files: Array<{ path: string }> }>;
  return pack.files.map((f) => f.path);
}

/** The UNICODE-STEGO findings HackMyAgent reports on `dir`, each as `file:line checkId`. */
async function stegoFindings(dir: string): Promise<string[]> {
  const findings = await new HardeningScanner().checkUnicodeSteganography(dir, false);
  return findings.map((f) => `${f.file}:${f.line} ${f.checkId}`).sort();
}

describe('package unicode', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aicomply-pack-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('ships no file in which HackMyAgent reports an invisible or look-alike character', async () => {
    const packed = packedFiles();
    for (const file of packed) {
      mkdirSync(dirname(join(dir, file)), { recursive: true });
      cpSync(join(ROOT, file), join(dir, file));
    }
    expect(packed).toEqual(expect.arrayContaining(['README.md', 'SECURITY.md', 'docs/detection.md']));
    expect(packed).not.toContain('.hmaignore');
    expect(await stegoFindings(dir)).toEqual([]);
  }, 60_000);

  it('reports a zero-width space and a Cyrillic look-alike written into a shipped Markdown file', async () => {
    mkdirSync(join(dir, 'docs'));
    writeFileSync(
      join(dir, 'docs', 'detection.md'),
      [
        '# Detection',
        '',
        `- Stripped: \`1${String.fromCodePoint(0x200b)}2\` becomes \`12\`.`,
        `- Not folded: Cyrillic \`${String.fromCodePoint(0x0430)}\` vs Latin \`a\`.`,
        '- Named instead: a zero-width space, U+200B, and the Cyrillic small letter a at U+0430.',
        '',
      ].join('\n'),
    );
    expect(await stegoFindings(dir)).toEqual(['docs/detection.md:3 UNICODE-STEGO-001', 'docs/detection.md:4 UNICODE-STEGO-005']);
  });
});
