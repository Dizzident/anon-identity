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
exports.verifyData = exports.signData = exports.generateKeyPair = exports.CryptoService = void 0;
const ed = __importStar(require("@noble/ed25519"));
const sha512_1 = require("@noble/hashes/sha512");
const crypto_1 = require("crypto");
// @ts-ignore
if (!globalThis.crypto)
    globalThis.crypto = crypto_1.webcrypto;
// Configure ed25519 to use sha512
ed.etc.sha512Sync = (...m) => (0, sha512_1.sha512)(ed.etc.concatBytes(...m));
class CryptoService {
    static async generateKeyPair() {
        const privateKey = ed.utils.randomPrivateKey();
        const publicKey = await ed.getPublicKey(privateKey);
        return {
            privateKey,
            publicKey
        };
    }
    static async getPublicKeyFromPrivate(privateKey) {
        return await ed.getPublicKey(privateKey);
    }
    static async sign(message, privateKey) {
        return await ed.sign(message, privateKey);
    }
    static async verify(signature, message, publicKey) {
        return await ed.verify(signature, message, publicKey);
    }
    static bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    static hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }
}
exports.CryptoService = CryptoService;
// Helper functions for backward compatibility
exports.generateKeyPair = CryptoService.generateKeyPair;
const signData = (data, privateKey) => {
    const message = new TextEncoder().encode(data);
    const signature = ed.sign(message, privateKey);
    return CryptoService.bytesToHex(signature);
};
exports.signData = signData;
const verifyData = async (signature, data, publicKey) => {
    const message = new TextEncoder().encode(data);
    const sig = CryptoService.hexToBytes(signature);
    return CryptoService.verify(sig, message, publicKey);
};
exports.verifyData = verifyData;
//# sourceMappingURL=crypto.js.map