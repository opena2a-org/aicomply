/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
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
    '^@noble/post-quantum/ml-dsa$': '<rootDir>/node_modules/@noble/post-quantum/ml-dsa.js',
    '^@noble/post-quantum/(.*)$': '<rootDir>/node_modules/@noble/post-quantum/$1',
    '^@noble/hashes/(.*)$': '<rootDir>/node_modules/@noble/hashes/$1',
  },
};
