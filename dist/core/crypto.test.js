"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
describe('CryptoService', () => {
    describe('generateKeyPair', () => {
        it('should generate a valid Ed25519 key pair', async () => {
            const keyPair = await crypto_1.CryptoService.generateKeyPair();
            expect(keyPair.publicKey).toBeDefined();
            expect(keyPair.privateKey).toBeDefined();
            expect(keyPair.publicKey.length).toBe(32);
            expect(keyPair.privateKey.length).toBe(32);
        });
        it('should generate different key pairs each time', async () => {
            const keyPair1 = await crypto_1.CryptoService.generateKeyPair();
            const keyPair2 = await crypto_1.CryptoService.generateKeyPair();
            expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
            expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
        });
    });
    describe('sign and verify', () => {
        it('should sign and verify a message correctly', async () => {
            const keyPair = await crypto_1.CryptoService.generateKeyPair();
            const message = new TextEncoder().encode('Hello, World!');
            const signature = await crypto_1.CryptoService.sign(message, keyPair.privateKey);
            const isValid = await crypto_1.CryptoService.verify(signature, message, keyPair.publicKey);
            expect(isValid).toBe(true);
        });
        it('should fail verification with wrong public key', async () => {
            const keyPair1 = await crypto_1.CryptoService.generateKeyPair();
            const keyPair2 = await crypto_1.CryptoService.generateKeyPair();
            const message = new TextEncoder().encode('Hello, World!');
            const signature = await crypto_1.CryptoService.sign(message, keyPair1.privateKey);
            const isValid = await crypto_1.CryptoService.verify(signature, message, keyPair2.publicKey);
            expect(isValid).toBe(false);
        });
        it('should fail verification with tampered message', async () => {
            const keyPair = await crypto_1.CryptoService.generateKeyPair();
            const message = new TextEncoder().encode('Hello, World!');
            const tamperedMessage = new TextEncoder().encode('Hello, World!!');
            const signature = await crypto_1.CryptoService.sign(message, keyPair.privateKey);
            const isValid = await crypto_1.CryptoService.verify(signature, tamperedMessage, keyPair.publicKey);
            expect(isValid).toBe(false);
        });
    });
    describe('hex conversion', () => {
        it('should convert bytes to hex and back', () => {
            const bytes = new Uint8Array([1, 2, 3, 255, 0, 128]);
            const hex = crypto_1.CryptoService.bytesToHex(bytes);
            const bytesBack = crypto_1.CryptoService.hexToBytes(hex);
            expect(bytesBack).toEqual(bytes);
        });
    });
});
//# sourceMappingURL=crypto.test.js.map