"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentityProvider = void 0;
const uuid_1 = require("uuid");
const jose_1 = require("jose");
const crypto_1 = require("../core/crypto");
const did_1 = require("../core/did");
const schemas_1 = require("./schemas");
class IdentityProvider {
    constructor(keyPair) {
        this.keyPair = keyPair;
        const didObject = did_1.DIDService.createDIDKey(keyPair.publicKey);
        this.did = didObject.id;
    }
    static async create() {
        const keyPair = await crypto_1.CryptoService.generateKeyPair();
        return new IdentityProvider(keyPair);
    }
    async issueVerifiableCredential(userDID, attributes) {
        // Validate attributes against schema
        const validation = (0, schemas_1.validateAttributes)(attributes, schemas_1.BASIC_PROFILE_SCHEMA);
        if (!validation.valid) {
            throw new Error(`Invalid attributes: ${validation.errors.join(', ')}`);
        }
        // Auto-calculate isOver18 if dateOfBirth is provided
        if (attributes.dateOfBirth && !attributes.hasOwnProperty('isOver18')) {
            const birthDate = new Date(attributes.dateOfBirth);
            const today = new Date();
            const age = today.getFullYear() - birthDate.getFullYear();
            const monthDiff = today.getMonth() - birthDate.getMonth();
            if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
                attributes.isOver18 = age - 1 >= 18;
            }
            else {
                attributes.isOver18 = age >= 18;
            }
        }
        const credentialId = `urn:uuid:${(0, uuid_1.v4)()}`;
        const issuanceDate = new Date().toISOString();
        // Create the credential without proof first
        const credential = {
            "@context": [
                schemas_1.CREDENTIAL_CONTEXTS.W3C_VC,
                schemas_1.CREDENTIAL_CONTEXTS.BASIC_PROFILE
            ],
            id: credentialId,
            type: [
                schemas_1.CREDENTIAL_TYPES.VERIFIABLE_CREDENTIAL,
                schemas_1.CREDENTIAL_TYPES.BASIC_PROFILE
            ],
            issuer: this.did,
            issuanceDate: issuanceDate,
            credentialSubject: {
                id: userDID,
                ...attributes
            }
        };
        // Sign the credential
        const signedCredential = await this.signCredential(credential);
        return signedCredential;
    }
    async signCredential(credential) {
        // Create a copy without the proof field for signing
        const credentialToSign = { ...credential };
        delete credentialToSign.proof;
        // Convert private key to JWK format for jose
        const privateKeyJwk = {
            kty: 'OKP',
            crv: 'Ed25519',
            x: Buffer.from(this.keyPair.publicKey).toString('base64url'),
            d: Buffer.from(this.keyPair.privateKey).toString('base64url')
        };
        const privateKey = await (0, jose_1.importJWK)(privateKeyJwk, 'EdDSA');
        // Create JWT
        const jwt = await new jose_1.SignJWT(credentialToSign)
            .setProtectedHeader({
            alg: 'EdDSA',
            typ: 'JWT',
            kid: `${this.did}#key-1`
        })
            .setIssuedAt()
            .setIssuer(this.did)
            .setSubject(credential.credentialSubject.id)
            .sign(privateKey);
        // Add proof to credential
        const signedCredential = {
            ...credential,
            proof: {
                type: 'Ed25519Signature2020',
                created: new Date().toISOString(),
                proofPurpose: 'assertionMethod',
                verificationMethod: `${this.did}#key-1`,
                jws: jwt
            }
        };
        return signedCredential;
    }
    getDID() {
        return this.did;
    }
}
exports.IdentityProvider = IdentityProvider;
//# sourceMappingURL=identity-provider.js.map