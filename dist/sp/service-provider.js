"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServiceProvider = void 0;
const jose_1 = require("jose");
const did_1 = require("../core/did");
const selective_disclosure_1 = require("../zkp/selective-disclosure");
class ServiceProvider {
    constructor(name, trustedIssuers = []) {
        this.name = name;
        this.trustedIssuers = new Set(trustedIssuers);
    }
    async verifyPresentation(presentation) {
        const errors = [];
        try {
            // 1. Verify the presentation signature
            if (!presentation.proof?.jws) {
                return {
                    valid: false,
                    errors: ['Presentation missing proof']
                };
            }
            // Extract holder DID from proof
            const holderDID = presentation.proof.verificationMethod.split('#')[0];
            // Verify presentation JWT
            const isPresentationValid = await this.verifyJWT(presentation.proof.jws, holderDID);
            if (!isPresentationValid.valid) {
                return {
                    valid: false,
                    errors: [`Invalid presentation signature: ${isPresentationValid.error}`]
                };
            }
            // 2. Verify each credential in the presentation
            const verifiedCredentials = [];
            for (const credential of presentation.verifiableCredential) {
                // Check if this is a selectively disclosed credential
                const isSelectivelyDisclosed = credential.type.includes('SelectivelyDisclosedCredential');
                if (isSelectivelyDisclosed) {
                    const sdCredential = credential;
                    // Verify the original issuer's signature
                    const credResult = await this.verifyCredential(sdCredential);
                    if (!credResult.valid) {
                        errors.push(`Credential ${sdCredential.id} verification failed: ${credResult.error}`);
                        continue;
                    }
                    // Verify the selective disclosure proof
                    const holderKey = did_1.DIDService.getPublicKeyFromDID(holderDID);
                    const sdValid = await selective_disclosure_1.SelectiveDisclosure.verifySelectiveDisclosure(sdCredential, holderKey);
                    if (!sdValid) {
                        errors.push(`Selective disclosure proof invalid for credential ${sdCredential.id}`);
                        continue;
                    }
                    // Check if issuer is trusted
                    if (!this.trustedIssuers.has(sdCredential.issuer)) {
                        errors.push(`Credential ${sdCredential.id} from untrusted issuer: ${sdCredential.issuer}`);
                        continue;
                    }
                    // Extract disclosed attributes
                    const { id, ...attributes } = sdCredential.credentialSubject;
                    verifiedCredentials.push({
                        id: sdCredential.id,
                        issuer: sdCredential.issuer,
                        type: sdCredential.type,
                        attributes,
                        selectivelyDisclosed: true,
                        disclosedAttributes: sdCredential.disclosureProof?.disclosedAttributes
                    });
                }
                else {
                    // Regular credential verification
                    const credResult = await this.verifyCredential(credential);
                    if (!credResult.valid) {
                        errors.push(`Credential ${credential.id} verification failed: ${credResult.error}`);
                        continue;
                    }
                    // Check if issuer is trusted
                    if (!this.trustedIssuers.has(credential.issuer)) {
                        errors.push(`Credential ${credential.id} from untrusted issuer: ${credential.issuer}`);
                        continue;
                    }
                    // Extract relevant attributes
                    const { id, ...attributes } = credential.credentialSubject;
                    verifiedCredentials.push({
                        id: credential.id,
                        issuer: credential.issuer,
                        type: credential.type,
                        attributes
                    });
                }
            }
            if (verifiedCredentials.length === 0 && errors.length > 0) {
                return {
                    valid: false,
                    errors
                };
            }
            return {
                valid: true,
                holder: holderDID,
                credentials: verifiedCredentials,
                errors: errors.length > 0 ? errors : undefined
            };
        }
        catch (error) {
            return {
                valid: false,
                errors: [`Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`]
            };
        }
    }
    async verifyCredential(credential) {
        try {
            if (!credential.proof?.jws) {
                return { valid: false, error: 'Credential missing proof' };
            }
            const result = await this.verifyJWT(credential.proof.jws, credential.issuer);
            return result;
        }
        catch (error) {
            return {
                valid: false,
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }
    async verifyJWT(jwt, issuerDID) {
        try {
            // Extract public key from DID
            const publicKey = did_1.DIDService.getPublicKeyFromDID(issuerDID);
            // Convert to JWK for jose
            const publicKeyJwk = {
                kty: 'OKP',
                crv: 'Ed25519',
                x: Buffer.from(publicKey).toString('base64url')
            };
            const key = await (0, jose_1.importJWK)(publicKeyJwk, 'EdDSA');
            // Verify JWT
            await (0, jose_1.jwtVerify)(jwt, key, {
                algorithms: ['EdDSA']
            });
            return { valid: true };
        }
        catch (error) {
            return {
                valid: false,
                error: error instanceof Error ? error.message : 'Invalid signature'
            };
        }
    }
    addTrustedIssuer(issuerDID) {
        this.trustedIssuers.add(issuerDID);
    }
    removeTrustedIssuer(issuerDID) {
        this.trustedIssuers.delete(issuerDID);
    }
    getTrustedIssuers() {
        return Array.from(this.trustedIssuers);
    }
    getName() {
        return this.name;
    }
}
exports.ServiceProvider = ServiceProvider;
//# sourceMappingURL=service-provider.js.map