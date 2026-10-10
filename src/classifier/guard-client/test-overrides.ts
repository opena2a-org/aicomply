/**
 * Test and development overrides for the Guard endpoints.
 *
 * `MOCK_NANOMIND_URL` and `MOCK_GUARD_SOCKET` redirect every classified
 * input to another endpoint, so they are honoured only when `NODE_ENV`
 * is `test` or `development`. In any other environment (`production`,
 * or `NODE_ENV` unset) they are ignored and the default endpoint is
 * used. To reach a daemon on a non-default address in production, pass
 * `baseUrl` / `socketPath` explicitly.
 */

export type TestOverrideName = 'MOCK_NANOMIND_URL' | 'MOCK_GUARD_SOCKET';

const OVERRIDE_ENVIRONMENTS: ReadonlySet<string> = new Set(['test', 'development']);

export function readTestOverride(name: TestOverrideName): string | undefined {
  const nodeEnv = process.env.NODE_ENV;
  if (nodeEnv === undefined || !OVERRIDE_ENVIRONMENTS.has(nodeEnv)) return undefined;
  return process.env[name];
}
