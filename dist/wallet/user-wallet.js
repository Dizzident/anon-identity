"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserWallet = void 0;
const jose_1 = require("jose");
const crypto_1 = require("../core/crypto");
const did_1 = require("../core/did");
const storage_1 = require("../core/storage");
class UserWallet {
    constructor(keyPair) {
        this.keyPair = keyPair;
        const didObject = did_1.DIDService.createDIDKey(keyPair.publicKey);
        this.did = didObject.id;
        this.credentials = new Map();
    }
    static async create() {
        const keyPair = await crypto_1.CryptoService.generateKeyPair();
        return new UserWallet(keyPair);
    }
    static async restore(passphrase, identifier = 'default') {
        const keyPair = await storage_1.SecureStorage.retrieveKeyPair(passphrase, identifier);
        if (!keyPair)
            return null;
        const wallet = new UserWallet(keyPair);
        // Restore stored credentials
        const storedCredentials = storage_1.SecureStorage.retrieve(`credentials:${identifier}`);
        if (storedCredentials && Array.isArray(storedCredentials)) {
            storedCredentials.forEach(vc => {
                wallet.credentials.set(vc.id, vc);
            });
        }
        return wallet;
    }
    async save(passphrase, identifier = 'default') {
        // Store key pair
        await storage_1.SecureStorage.storeKeyPair(this.keyPair, passphrase, identifier);
        // Store credentials
        const credentialsArray = Array.from(this.credentials.values());
        storage_1.SecureStorage.store(`credentials:${identifier}`, credentialsArray);
    }
    storeCredential(credential) {
        this.credentials.set(credential.id, credential);
    }
    getCredential(credentialId) {
        return this.credentials.get(credentialId);
    }
    getAllCredentials() {
        return Array.from(this.credentials.values());
    }
    getCredentialsByType(type) {
        return Array.from(this.credentials.values()).filter(vc => vc.type.includes(type));
    }
    async createVerifiablePresentation(credentialIds) {
        // Collect selected credentials
        const selectedCredentials = [];
        for (const credId of credentialIds) {
            const credential = this.credentials.get(credId);
            if (!credential) {
                throw new Error(`Credential not found: ${credId}`);
            }
            selectedCredentials.push(credential);
        }
        if (selectedCredentials.length === 0) {
            throw new Error('No credentials selected for presentation');
        }
        // Create the presentation without proof
        const presentation = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiablePresentation"],
            verifiableCredential: selectedCredentials
        };
        // Sign the presentation
        const signedPresentation = await this.signPresentation(presentation);
        return signedPresentation;
    }
    async signPresentation(presentation) {
        // Create a copy without the proof field for signing
        const presentationToSign = { ...presentation };
        delete presentationToSign.proof;
        // Convert private key to JWK format for jose
        const privateKeyJwk = {
            kty: 'OKP',
            crv: 'Ed25519',
            x: Buffer.from(this.keyPair.publicKey).toString('base64url'),
            d: Buffer.from(this.keyPair.privateKey).toString('base64url')
        };
        const privateKey = await (0, jose_1.importJWK)(privateKeyJwk, 'EdDSA');
        // Create JWT
        const jwt = await new jose_1.SignJWT(presentationToSign)
            .setProtectedHeader({
            alg: 'EdDSA',
            typ: 'JWT',
            kid: `${this.did}#key-1`
        })
            .setIssuedAt()
            .setIssuer(this.did)
            .sign(privateKey);
        // Add proof to presentation
        const signedPresentation = {
            ...presentation,
            proof: {
                type: 'Ed25519Signature2020',
                created: new Date().toISOString(),
                proofPurpose: 'authentication',
                verificationMethod: `${this.did}#key-1`,
                jws: jwt
            }
        };
        return signedPresentation;
    }
    getDID() {
        return this.did;
    }
    getPublicKey() {
        return this.keyPair.publicKey;
    }
}
exports.UserWallet = UserWallet;
//# sourceMappingURL=user-wallet.js.map