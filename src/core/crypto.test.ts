import { CryptoService } from './crypto';

describe('CryptoService', () => {
  describe('generateKeyPair', () => {
    it('should generate a valid Ed25519 key pair', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey.length).toBe(32);
      expect(keyPair.privateKey.length).toBe(32);
    });
    
    it('should generate different key pairs each time', async () => {
      const keyPair1 = await CryptoService.generateKeyPair();
      const keyPair2 = await CryptoService.generateKeyPair();
      
      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });
  });
  
  describe('sign and verify', () => {
    it('should sign and verify a message correctly', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const message = new TextEncoder().encode('Hello, World!');
      
      const signature = await CryptoService.sign(message, keyPair.privateKey);
      const isValid = await CryptoService.verify(signature, message, keyPair.publicKey);
      
      expect(isValid).toBe(true);
    });
    
    it('should fail verification with wrong public key', async () => {
      const keyPair1 = await CryptoService.generateKeyPair();
      const keyPair2 = await CryptoService.generateKeyPair();
      const message = new TextEncoder().encode('Hello, World!');
      
      const signature = await CryptoService.sign(message, keyPair1.privateKey);
      const isValid = await CryptoService.verify(signature, message, keyPair2.publicKey);
      
      expect(isValid).toBe(false);
    });
    
    it('should fail verification with tampered message', async () => {
      const keyPair = await CryptoService.generateKeyPair();
      const message = new TextEncoder().encode('Hello, World!');
      const tamperedMessage = new TextEncoder().encode('Hello, World!!');
      
      const signature = await CryptoService.sign(message, keyPair.privateKey);
      const isValid = await CryptoService.verify(signature, tamperedMessage, keyPair.publicKey);
      
      expect(isValid).toBe(false);
    });
  });
  
  describe('hex conversion', () => {
    it('should convert bytes to hex and back', () => {
      const bytes = new Uint8Array([1, 2, 3, 255, 0, 128]);
      const hex = CryptoService.bytesToHex(bytes);
      const bytesBack = CryptoService.hexToBytes(hex);
      
      expect(bytesBack).toEqual(bytes);
    });
  });
});