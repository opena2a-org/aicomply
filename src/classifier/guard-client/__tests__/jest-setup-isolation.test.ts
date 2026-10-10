/**
 * jest.setup.js isolates every test from a nanomind-daemon a developer is
 * running locally by pinning MOCK_NANOMIND_URL to a closed port. The pin
 * only takes effect when NODE_ENV is `test` or `development`, and Jest
 * sets NODE_ENV=test only when the shell leaves it unset. These tests
 * re-run the setup file under the NODE_ENV values a developer's shell
 * might export and check that the pin still holds.
 */

import { join } from 'node:path';
import { readTestOverride } from '../test-overrides';

const SETUP_FILE = join(__dirname, '..', '..', '..', '..', 'jest.setup.js');
const CLOSED_PORT_URL = 'http://127.0.0.1:1';

describe('jest.setup.js daemon isolation pin', () => {
  const prevNodeEnv = process.env.NODE_ENV;
  const prevMockUrl = process.env.MOCK_NANOMIND_URL;

  afterEach(() => {
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevMockUrl === undefined) delete process.env.MOCK_NANOMIND_URL;
    else process.env.MOCK_NANOMIND_URL = prevMockUrl;
  });

  it.each([['production'], ['staging'], [undefined]])(
    'keeps MOCK_NANOMIND_URL in effect when the shell exports NODE_ENV=%s',
    (nodeEnv) => {
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      delete process.env.MOCK_NANOMIND_URL;

      jest.isolateModules(() => {
        require(SETUP_FILE);
      });

      expect(process.env.NODE_ENV).toBe('test');
      expect(readTestOverride('MOCK_NANOMIND_URL')).toBe(CLOSED_PORT_URL);
    },
  );
});
