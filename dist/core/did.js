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
exports.DIDService = void 0;
const multibase = __importStar(require("multibase"));
class DIDService {
    static createDIDKey(publicKey) {
        // Add multicodec prefix for Ed25519 public key
        const multicodecPrefixed = new Uint8Array(2 + publicKey.length);
        multicodecPrefixed[0] = this.ED25519_MULTICODEC;
        multicodecPrefixed[1] = 0x01; // varint encoding for Ed25519
        multicodecPrefixed.set(publicKey, 2);
        // Encode with multibase (base58btc)
        const multibaseEncoded = multibase.encode('base58btc', multicodecPrefixed);
        // Convert to string
        const encodedString = new TextDecoder().decode(multibaseEncoded);
        // Create did:key identifier
        const did = `did:key:${encodedString}`;
        return {
            id: did,
            publicKey
        };
    }
    static getPublicKeyFromDID(didKey) {
        if (!didKey.startsWith('did:key:')) {
            throw new Error('Invalid did:key format');
        }
        // Extract the multibase encoded part
        const multibaseEncoded = didKey.substring('did:key:'.length);
        // Convert string to Uint8Array
        const encodedBytes = new TextEncoder().encode(multibaseEncoded);
        // Decode multibase
        const decoded = multibase.decode(encodedBytes);
        // Remove multicodec prefix (2 bytes for Ed25519)
        return decoded.slice(2);
    }
    static async createDIDDocument(did) {
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: did.id,
            verificationMethod: [{
                    id: `${did.id}#key-1`,
                    type: "Ed25519VerificationKey2020",
                    controller: did.id,
                    publicKeyMultibase: multibase.encode('base58btc', did.publicKey)
                }],
            authentication: [`${did.id}#key-1`],
            assertionMethod: [`${did.id}#key-1`]
        };
    }
}
exports.DIDService = DIDService;
DIDService.ED25519_MULTICODEC = 0xed;
//# sourceMappingURL=did.js.map