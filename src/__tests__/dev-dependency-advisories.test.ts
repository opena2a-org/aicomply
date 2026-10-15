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
 */

import { readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');

interface LockEntry {
  version?: string;
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
