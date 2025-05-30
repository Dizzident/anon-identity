module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/__tests__/**/*.ts', '**/*.test.ts'],
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