"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureStorage = void 0;
const crypto_1 = require("./crypto");
const crypto = __importStar(require("crypto"));
class SecureStorage {
    static async storeKeyPair(keyPair, passphrase, identifier = 'default') {
        const salt = crypto.randomBytes(32);
        const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encryptedPrivateKey = Buffer.concat([
            cipher.update(keyPair.privateKey),
            cipher.final()
        ]);
        const authTag = cipher.getAuthTag();
        const storedData = {
            publicKey: crypto_1.CryptoService.bytesToHex(keyPair.publicKey),
            encryptedPrivateKey: Buffer.concat([authTag, encryptedPrivateKey]).toString('base64'),
            salt: salt.toString('base64'),
            iv: iv.toString('base64')
        };
        this.storage.set(`keypair:${identifier}`, storedData);
    }
    static async retrieveKeyPair(passphrase, identifier = 'default') {
        const storedData = this.storage.get(`keypair:${identifier}`);
        if (!storedData)
            return null;
        try {
            const salt = Buffer.from(storedData.salt, 'base64');
            const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
            const iv = Buffer.from(storedData.iv, 'base64');
            const encryptedData = Buffer.from(storedData.encryptedPrivateKey, 'base64');
            const authTag = encryptedData.slice(0, 16);
            const encryptedPrivateKey = encryptedData.slice(16);
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(authTag);
            const privateKey = Buffer.concat([
                decipher.update(encryptedPrivateKey),
                decipher.final()
            ]);
            return {
                publicKey: crypto_1.CryptoService.hexToBytes(storedData.publicKey),
                privateKey: new Uint8Array(privateKey)
            };
        }
        catch (error) {
            console.error('Failed to decrypt key pair:', error);
            return null;
        }
    }
    static store(key, value) {
        this.storage.set(key, value);
    }
    static retrieve(key) {
        return this.storage.get(key);
    }
    static delete(key) {
        return this.storage.delete(key);
    }
    static clear() {
        this.storage.clear();
    }
}
exports.SecureStorage = SecureStorage;
SecureStorage.storage = new Map();
//# sourceMappingURL=storage.js.map