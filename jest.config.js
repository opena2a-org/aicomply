/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  // Isolate every test from any nanomind daemon a developer happens to
  // be running locally. Tests that specifically want the adapter to
  // succeed point baseUrl at their own mock server via options.
  setupFiles: ['<rootDir>/jest.setup.js'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/__tests__/**',
    '!src/**/types.ts',
  ],
  // @noble packages are ESM-only, need transformation
  transformIgnorePatterns: [
    'node_modules/(?!(@noble|@scure)/)',
  ],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
    '^.+\\.m?jsx?$': ['ts-jest', { useESM: false }],
  },
  // Map ESM subpath exports to their actual .js files for CJS resolution
  moduleNameMapper: {
    '^@noble/post-quantum/ml-dsa(\\.js)?$': '<rootDir>/node_modules/@noble/post-quantum/ml-dsa.js',
    '^@noble/post-quantum/(.*)$': '<rootDir>/node_modules/@noble/post-quantum/$1',
    '^@noble/hashes/(.*)$': '<rootDir>/node_modules/@noble/hashes/$1',
  },
};
