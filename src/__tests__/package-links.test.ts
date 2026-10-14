/**
 * Package link tests. An installed copy of the package holds only the files
 * `npm pack` puts in the tarball, so a relative link in a Markdown file the
 * package ships must point at a file the tarball also carries; a link to
 * content that stays in the repository, such as the corpus or the Python
 * package, names its GitHub URL instead.
 */

import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { join, posix } from 'path';

const ROOT = join(__dirname, '..', '..');

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

/** Inline links and images, with an optional title, and reference definitions. */
const INLINE_LINK = /\]\(\s*<?([^\s)>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const REFERENCE_LINK = /^ {0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?/gm;
const FENCED_CODE = /^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$/gm;

/**
 * The relative links in `text`, the Markdown of `file`, whose target is not
 * in `packed`, each as `file:line (target)`. A target is in `packed` when it
 * names a packed file or a directory that holds one. URLs, `mailto:` and
 * same-page anchors are left alone, as is anything inside a fenced code block.
 */
function unshippedLinks(file: string, text: string, packed: readonly string[]): string[] {
  const prose = text.replace(FENCED_CODE, (block) => block.replace(/[^\n]/g, ' '));
  const shipped = (path: string) =>
    path === '.' || packed.some((p) => p === path || p.startsWith(`${path}/`));
  return [...prose.matchAll(INLINE_LINK), ...prose.matchAll(REFERENCE_LINK)]
    .filter((m) => {
      const target = m[1];
      if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('//') || target.startsWith('#')) {
        return false;
      }
      const path = posix
        .normalize(posix.join(posix.dirname(file), target.replace(/[?#].*$/, '')))
        .replace(/\/$/, '');
      return path === '..' || path.startsWith('../') || !shipped(path);
    })
    .sort((a, b) => (a.index ?? 0) - (b.index ?? 0))
    .map((m) => `${file}:${text.slice(0, m.index).split('\n').length} (${m[1]})`);
}

describe('package links', () => {
  it('ships every file a relative link in its Markdown points at', () => {
    const packed = packedFiles();
    const markdown = packed.filter((p) => p.endsWith('.md'));
    const offenders = markdown.flatMap((file) =>
      unshippedLinks(file, readFileSync(join(ROOT, file), 'utf8'), packed),
    );
    expect(offenders).toEqual([]);
    expect(markdown).toEqual(expect.arrayContaining(['README.md', 'SECURITY.md', 'docs/semantic-guard.md']));
  }, 60_000);

  it('flags a link to a path outside the tarball and leaves URLs, anchors and shipped targets alone', () => {
    const packed = ['README.md', 'SECURITY.md', 'docs/verdicts.md', 'docs/detection.md'];
    const text = [
      'See [verdicts](docs/verdicts.md) and [checklist](./SECURITY.md#hardening-checklist).',
      'Docs live in [docs/](docs/), the source on [GitHub](https://github.com/opena2a-org/aicomply).',
      'Jump to [usage](#usage) or write to [us](mailto:security@example.com).',
      'The [corpus](bench/corpus) and [Python](python/ "Python package") stay in the repository.',
      '```',
      'not a link: list[0](x)',
      '```',
      '[ref]: ../outside.md',
    ].join('\n');
    expect(unshippedLinks('README.md', text, packed)).toEqual([
      'README.md:4 (bench/corpus)',
      'README.md:4 (python/)',
      'README.md:8 (../outside.md)',
    ]);
    expect(unshippedLinks('docs/detection.md', '[back](../SECURITY.md) and [up](../../x.md)', packed)).toEqual([
      'docs/detection.md:1 (../../x.md)',
    ]);
  });
});
