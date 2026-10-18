import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * The package version, read from package.json so that `npm version` is the
 * only place a release bump has to touch. From `src/` (tests) and from
 * `dist/` (the published package) one level up is the package root, which
 * carries package.json.
 */
export function packageVersion(): string {
  const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as {
    version?: unknown;
  };
  if (typeof pkg.version !== 'string' || pkg.version === '') {
    throw new Error('aicomply: package.json has no version');
  }
  return pkg.version;
}
