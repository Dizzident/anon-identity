module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/src/agent/activity/**/*.test.ts', '!**/src/agent/activity/activity-logger.test.ts'],
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 44,
      functions: 47,
      lines: 49,
      statements: 48
    }
  },
  collectCoverageFrom: [
    'src/agent/activity/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/*.d.ts',
    '!src/test/**/*',
    '!src/examples/**/*',
    '!src/agent/activity/activity-logger.ts',
    '!src/agent/activity/ipfs-*.ts'
  ],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        module: 'ESNext',
        target: 'ES2020'
      }
    }]
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@noble|jose|multibase|multicodec|@mattrglobal|jsonld|@ipld|uint8arrays|multiformats)/)'
  ],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '#(.*)': '<rootDir>/node_modules/$1'
  },
  setupFilesAfterEnv: ['<rootDir>/src/test/jest.setup.ts']
};