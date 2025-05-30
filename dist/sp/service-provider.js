"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServiceProvider = void 0;
const jose_1 = require("jose");
const did_1 = require("../core/did");
const selective_disclosure_1 = require("../zkp/selective-disclosure");
const revocation_service_1 = require("../revocation/revocation-service");
const storage_1 = require("../storage");
const session_manager_1 = require("./session-manager");
const verification_errors_1 = require("./verification-errors");
const batch_operations_1 = require("./batch-operations");
const presentation_request_1 = require("./presentation-request");
class ServiceProvider {
    constructor(name, trustedIssuers = [], options = {}) {
        this.name = name;
        this.trustedIssuers = new Set(trustedIssuers);
        this.checkRevocation = options.checkRevocation ?? true;
        this.storageProvider = options.storageProvider || storage_1.StorageFactory.getDefaultProvider();
        this.sessionManager = new session_manager_1.SessionManager(options.sessionManager);
        this.batchOperations = new batch_operations_1.BatchOperations(options.batchOperations);
        // For presentation requests, we need a DID - in practice this would be the service provider's DID
        this.presentationRequest = new presentation_request_1.PresentationRequest(`did:key:${name}`);
    }
    // Backward compatibility constructor
    static create(name, trustedIssuers = [], checkRevocation = true, storageProvider) {
        return new ServiceProvider(name, trustedIssuers, {
            checkRevocation,
            storageProvider
        });
    }
    async verifyPresentation(presentation) {
        const errors = [];
        const timestamp = new Date();
        try {
            // 1. Verify the presentation signature
            if (!presentation.proof?.jws) {
                return {
                    valid: false,
                    errors: [verification_errors_1.VerificationError.missingProof('presentation')],
                    timestamp
                };
            }
            // Extract holder DID from proof
            const holderDID = presentation.proof.verificationMethod.split('#')[0];
            // Verify presentation JWT
            const isPresentationValid = await this.verifyJWT(presentation.proof.jws, holderDID);
            if (!isPresentationValid.valid) {
                return {
                    valid: false,
                    errors: [verification_errors_1.VerificationError.invalidPresentationSignature(isPresentationValid.error)],
                    timestamp
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
                        errors.push(verification_errors_1.VerificationError.invalidSignature(sdCredential.id, credResult.error));
                        continue;
                    }
                    // Verify the selective disclosure proof
                    const holderKey = did_1.DIDService.getPublicKeyFromDID(holderDID);
                    const sdValid = await selective_disclosure_1.SelectiveDisclosure.verifySelectiveDisclosure(sdCredential, holderKey);
                    if (!sdValid) {
                        errors.push(verification_errors_1.VerificationError.invalidDisclosureProof(sdCredential.id));
                        continue;
                    }
                    // Check if issuer is trusted
                    if (!this.trustedIssuers.has(sdCredential.issuer)) {
                        errors.push(verification_errors_1.VerificationError.untrustedIssuer(sdCredential.issuer, sdCredential.id));
                        continue;
                    }
                    // Check revocation status
                    if (this.checkRevocation) {
                        const isRevoked = await this.checkCredentialRevocation(sdCredential.id, sdCredential.issuer);
                        if (isRevoked) {
                            errors.push(verification_errors_1.VerificationError.revokedCredential(sdCredential.id, sdCredential.issuer));
                            continue;
                        }
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
                        errors.push(verification_errors_1.VerificationError.invalidSignature(credential.id, credResult.error));
                        continue;
                    }
                    // Check if issuer is trusted
                    if (!this.trustedIssuers.has(credential.issuer)) {
                        errors.push(verification_errors_1.VerificationError.untrustedIssuer(credential.issuer, credential.id));
                        continue;
                    }
                    // Check revocation status
                    if (this.checkRevocation) {
                        const isRevoked = await this.checkCredentialRevocation(credential.id, credential.issuer);
                        if (isRevoked) {
                            errors.push(verification_errors_1.VerificationError.revokedCredential(credential.id, credential.issuer));
                            continue;
                        }
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
                    errors,
                    timestamp
                };
            }
            return {
                valid: true,
                holder: holderDID,
                credentials: verifiedCredentials,
                errors: errors.length > 0 ? errors : undefined,
                timestamp
            };
        }
        catch (error) {
            const verificationError = error instanceof Error
                ? new verification_errors_1.VerificationError(verification_errors_1.VerificationErrorCode.NETWORK_ERROR, `Verification error: ${error.message}`)
                : new verification_errors_1.VerificationError(verification_errors_1.VerificationErrorCode.NETWORK_ERROR, 'Unknown verification error');
            return {
                valid: false,
                errors: [verificationError],
                timestamp
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
    setRevocationCheck(enabled) {
        this.checkRevocation = enabled;
    }
    async checkCredentialRevocation(credentialId, issuerDID) {
        try {
            // First check storage provider
            const isRevoked = await this.storageProvider.checkRevocation(issuerDID, credentialId);
            if (isRevoked) {
                return true;
            }
            // Also check the mock registry for backward compatibility
            const revocationList = await revocation_service_1.RevocationService.fetchRevocationListByIssuer(issuerDID);
            if (!revocationList) {
                // No revocation list published - credential is not revoked
                return false;
            }
            // Verify the revocation list signature
            const issuerPublicKey = did_1.DIDService.getPublicKeyFromDID(issuerDID);
            const isValid = await revocation_service_1.RevocationService.verifyRevocationList(revocationList, issuerPublicKey);
            if (!isValid) {
                // Invalid revocation list - treat as not revoked but log warning
                console.warn(`Invalid revocation list signature from issuer ${issuerDID}`);
                return false;
            }
            // Check if the credential ID is in the revocation list
            return revocationList.revokedCredentials.includes(credentialId);
        }
        catch (error) {
            // Error checking revocation - treat as not revoked
            console.error(`Error checking revocation for credential ${credentialId}:`, error);
            return false;
        }
    }
    setStorageProvider(provider) {
        this.storageProvider = provider;
    }
    // Session Management Methods
    async createSession(verificationResult, metadata) {
        return this.sessionManager.createSession(verificationResult, metadata);
    }
    async validateSession(sessionId) {
        return this.sessionManager.validateSession(sessionId);
    }
    async setSessionExpiry(sessionId, duration) {
        return this.sessionManager.setSessionExpiry(sessionId, duration);
    }
    getSession(sessionId) {
        return this.sessionManager.getSession(sessionId);
    }
    getAllSessions() {
        return this.sessionManager.getAllSessions();
    }
    getSessionsByHolder(holderDID) {
        return this.sessionManager.getSessionsByHolder(holderDID);
    }
    removeSession(sessionId) {
        this.sessionManager.removeSession(sessionId);
    }
    clearAllSessions() {
        this.sessionManager.clearAllSessions();
    }
    // Enhanced verification with automatic session creation
    async verifyPresentationWithSession(presentation, createSession = true, sessionMetadata) {
        const verificationResult = await this.verifyPresentation(presentation);
        if (createSession && verificationResult.valid) {
            const session = await this.createSession(verificationResult, sessionMetadata);
            return { verification: verificationResult, session };
        }
        return { verification: verificationResult };
    }
    // Handle credential revocation by invalidating related sessions
    async handleCredentialRevocation(credentialId) {
        await this.sessionManager.revokeSessions(credentialId);
    }
    // Cleanup method
    destroy() {
        this.sessionManager.destroy();
    }
    // Batch Operations
    async batchVerifyPresentations(presentations) {
        return this.batchOperations.batchVerifyPresentations(presentations, (presentation) => this.verifyPresentation(presentation));
    }
    async batchCheckRevocations(credentialIds) {
        return this.batchOperations.batchCheckRevocations(credentialIds, (credentialId) => this.checkCredentialRevocation(credentialId, 'unknown'));
    }
    async batchVerifyWithRevocationCheck(presentations) {
        return this.batchOperations.batchVerifyWithRevocationCheck(presentations, (presentation) => this.verifyPresentation(presentation), (credentialId) => this.checkCredentialRevocation(credentialId, 'unknown'));
    }
    // Presentation Request Protocol
    async createPresentationRequest(options) {
        return this.presentationRequest.createRequest(options);
    }
    async createSimplePresentationRequest(credentialTypes, purpose, requiredAttributes = [], optionalAttributes = []) {
        return this.presentationRequest.createSimpleRequest(credentialTypes, purpose, requiredAttributes, optionalAttributes);
    }
    async validatePresentationAgainstRequest(presentation, request) {
        return this.presentationRequest.validateAgainstRequest(presentation, request);
    }
    // Enhanced verification that includes request validation
    async verifyPresentationWithRequest(presentation, request) {
        const [verification, requestValidation] = await Promise.all([
            this.verifyPresentation(presentation),
            this.validatePresentationAgainstRequest(presentation, request)
        ]);
        return { verification, requestValidation };
    }
}
exports.ServiceProvider = ServiceProvider;
//# sourceMappingURL=service-provider.js.map