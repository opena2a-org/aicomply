/**
 * Development dependency advisory floors. `npm audit` reported the advisories
 * below against packages in the development dependency tree, and the
 * lockfile was updated to resolve every copy of each package outside the
 * advisories' ranges; each floor is the lowest version outside them, whether
 * or not that version was published. A lockfile regenerated from an
 * older branch can bring the earlier versions back without any change to
 * package.json, so each copy in package-lock.json is checked here.
 *
 * braces and micromatch are checked to be absent instead: the braces advisory
 * (GHSA-vfj7-8cjw-p6xm) has no fixed release to set a floor at, micromatch is
 * reported only through braces, and the Jest 30 tree installs neither.
 *
 * Two packages keep advisories that no version in reach fixes. Every copy of
 * each is installed only as a development dependency, which is why
 * `npm audit --omit=dev` reports none of them, and the last block of tests
 * pins where each copy is loaded:
 *
 * - sprintf-js, GHSA-hp3w-g68c-fv3c (denial of service through unbounded
 *   precision specifiers), range <=1.1.3, which holds its latest release.
 *   One copy is reached through argparse 1, which js-yaml 3 requires only in
 *   its command-line entry point, bin/js-yaml.js; Jest reaches js-yaml
 *   through @istanbuljs/load-nyc-config, which calls the library. The other
 *   is reached through roarr and global-agent 3, which onnxruntime-node
 *   1.24.3 requires only in its install script.
 * - adm-zip 0.5.18, eight advisories about reading crafted ZIP files, all
 *   fixed in 0.6.1, outside the ^0.5.16 range of onnxruntime-node 1.24.3,
 *   the version @nanomind/daemon 0.3.0 pins. onnxruntime-node requires it
 *   only in its install script, which opens a ZIP file only after
 *   downloading a package from NuGet, and the repository .npmrc makes that
 *   script exit before the download (npmrc.test.ts).
 */

import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');

interface LockEntry {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8')) as {
  packages: Record<string, LockEntry>;
};

/** `[lockfile path, version]` of every installed copy of `name`. */
function copiesOf(name: string): Array<[string, string]> {
  return Object.entries(lock.packages)
    .filter(([path]) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`))
    .map(([path, entry]) => [path, entry.version ?? '']);
}

/**
 * The copy of `name` the package at `from` loads: the nearest node_modules
 * folder that holds it, from `from` outward, as Node resolves a require.
 */
function resolveFrom(from: string, name: string): string | undefined {
  let base = from;
  for (;;) {
    const candidate = base === '' ? `node_modules/${name}` : `${base}/node_modules/${name}`;
    if (candidate in lock.packages) return candidate;
    if (base === '') return undefined;
    const up = base.lastIndexOf('/node_modules/');
    base = up < 0 ? '' : base.slice(0, up);
  }
}

/** Lockfile path of every package whose dependencies resolve to `copy`. */
function requirersOf(copy: string): string[] {
  const name = copy.slice(copy.lastIndexOf('node_modules/') + 'node_modules/'.length);
  return Object.entries(lock.packages)
    .filter(([path, entry]) => {
      const dependencies = { ...entry.dependencies, ...entry.optionalDependencies };
      return name in dependencies && resolveFrom(path, name) === copy;
    })
    .map(([path]) => path);
}

/** JavaScript files of the installed package at `dir`, outside its own node_modules. */
function scriptFiles(dir: string, rel = ''): string[] {
  return readdirSync(join(dir, rel), { withFileTypes: true }).flatMap((entry) => {
    const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : scriptFiles(dir, path);
    return entry.isFile() && /\.[cm]?js$/.test(entry.name) ? [path] : [];
  });
}

/** Files of the installed package at `copy` that require `name`. */
function filesRequiring(copy: string, name: string): string[] {
  const dir = join(ROOT, copy);
  const call = new RegExp(`require\\(\\s*['"]${name}['"]\\s*\\)`);
  return scriptFiles(dir)
    .filter((file) => call.test(readFileSync(join(dir, file), 'utf8')))
    .sort();
}

function parseVersion(version: string): [number, number, number] {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) throw new Error(`not a version: "${version}"`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function atLeast(version: string, floor: string): boolean {
  const a = parseVersion(version);
  const b = parseVersion(floor);
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

describe('development dependency advisories in package-lock.json', () => {
  it.each([
    ['handlebars', '4.7.10', 'GHSA-8r5x-fm3f-whwj, GHSA-p8wg-vrv2-v86f, GHSA-xw65-4hp5-5hc7'],
    ['@babel/core', '7.29.1', 'GHSA-4x5r-pxfx-6jf8'],
    ['brace-expansion', '1.1.21', 'GHSA-q2hr-2g5m-vwhr and five earlier ones'],
    ['browserslist', '4.28.7', 'GHSA-c83g-rgw3-j3cx, GHSA-73wf-gq98-2v4g'],
    ['baseline-browser-mapping', '2.11.0', 'GHSA-w5vr-8v7q-w6rv'],
    ['js-yaml', '3.15.2', 'GHSA-2883-xcg3-v3hh and three earlier ones'],
  ])('resolves every copy of %s at %s or later (%s)', (name, floor) => {
    const copies = copiesOf(name);
    expect(copies.length).toBeGreaterThan(0);
    expect(copies.filter(([, version]) => !atLeast(version, floor))).toEqual([]);
  });

  it.each(['braces', 'micromatch'])('installs no copy of %s', (name) => {
    expect(copiesOf(name)).toEqual([]);
  });
});

describe('development dependency advisories with no fix in reach', () => {
  it('installs only the recorded copies of sprintf-js, which has no release outside GHSA-hp3w-g68c-fv3c', () => {
    expect(copiesOf('sprintf-js').map(([path]) => path).sort()).toEqual([
      'node_modules/roarr/node_modules/sprintf-js',
      'node_modules/sprintf-js',
    ]);
  });

  it('installs only the recorded copy of adm-zip below 0.6.1', () => {
    expect(copiesOf('adm-zip').filter(([, version]) => !atLeast(version, '0.6.1'))).toEqual([
      ['node_modules/adm-zip', '0.5.18'],
    ]);
  });

  it.each(['node_modules/sprintf-js', 'node_modules/roarr/node_modules/sprintf-js', 'node_modules/adm-zip'])(
    'installs %s only as a development dependency',
    (copy) => {
      expect(lock.packages[copy].dev).toBe(true);
    },
  );

  it.each([
    ['node_modules/sprintf-js', ['node_modules/argparse']],
    ['node_modules/argparse', ['node_modules/js-yaml']],
    ['node_modules/js-yaml', ['node_modules/@istanbuljs/load-nyc-config']],
    ['node_modules/roarr/node_modules/sprintf-js', ['node_modules/roarr']],
    ['node_modules/roarr', ['node_modules/global-agent']],
    ['node_modules/global-agent', ['node_modules/onnxruntime-node']],
    ['node_modules/adm-zip', ['node_modules/onnxruntime-node']],
    ['node_modules/onnxruntime-node', ['node_modules/@nanomind/daemon']],
  ])('has %s required only by %j', (copy, requirers) => {
    expect(requirersOf(copy)).toEqual(requirers);
  });

  it.each([
    ['node_modules/js-yaml', 'argparse', ['bin/js-yaml.js']],
    ['node_modules/onnxruntime-node', 'global-agent', ['script/install.js']],
    ['node_modules/onnxruntime-node', 'adm-zip', ['script/install-utils.js']],
  ])('finds %s requiring %s only in %j', (copy, name, files) => {
    expect(filesRequiring(copy, name)).toEqual(files);
  });
});
