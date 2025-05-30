/**
 * Jest setup file for ES module compatibility
 */

// Mock problematic ES modules that cause Jest issues
jest.mock('@noble/ed25519', () => ({
  getPublicKey: jest.fn().mockResolvedValue(new Uint8Array(32)),
  sign: jest.fn().mockResolvedValue(new Uint8Array(64)),
  verify: jest.fn().mockResolvedValue(true),
  utils: {
    randomPrivateKey: jest.fn().mockReturnValue(new Uint8Array(32))
  }
}));

jest.mock('jose', () => ({
  SignJWT: jest.fn().mockImplementation(() => ({
    setProtectedHeader: jest.fn().mockReturnThis(),
    setIssuedAt: jest.fn().mockReturnThis(),
    setExpirationTime: jest.fn().mockReturnThis(),
    setIssuer: jest.fn().mockReturnThis(),
    setSubject: jest.fn().mockReturnThis(),
    sign: jest.fn().mockResolvedValue('mock.jwt.token')
  })),
  jwtVerify: jest.fn().mockResolvedValue({
    payload: { sub: 'test', iss: 'test' },
    protectedHeader: { alg: 'EdDSA' }
  }),
  importJWK: jest.fn().mockResolvedValue('mock-key'),
  exportJWK: jest.fn().mockResolvedValue({ kty: 'OKP', crv: 'Ed25519' })
}));

jest.mock('@mattrglobal/bbs-signatures', () => ({
  generateBls12381G2KeyPair: jest.fn().mockResolvedValue({
    publicKey: new Uint8Array(48),
    secretKey: new Uint8Array(32)
  }),
  blsSign: jest.fn().mockResolvedValue(new Uint8Array(112)),
  blsVerify: jest.fn().mockResolvedValue(true),
  blsCreateProof: jest.fn().mockResolvedValue(new Uint8Array(128)),
  blsVerifyProof: jest.fn().mockResolvedValue(true)
}));

// Increase timeout for async operations
jest.setTimeout(30000);

// Global test utilities
(global as any).TestUtils = {
  mockDID: 'did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd',
  mockPrivateKey: new Uint8Array(32),
  mockPublicKey: new Uint8Array(32),
  mockSignature: new Uint8Array(64)
};