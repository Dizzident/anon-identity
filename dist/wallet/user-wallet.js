"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserWallet = void 0;
const jose_1 = require("jose");
const crypto_1 = require("../core/crypto");
const did_1 = require("../core/did");
const storage_1 = require("../core/storage");
const selective_disclosure_1 = require("../zkp/selective-disclosure");
const storage_2 = require("../storage");
const agent_identity_1 = require("../agent/agent-identity");
const delegation_manager_1 = require("../agent/delegation-manager");
const agent_revocation_service_1 = require("../agent/agent-revocation-service");
class UserWallet {
    constructor(keyPair, storageProvider) {
        this.keyPair = keyPair;
        const didObject = did_1.DIDService.createDIDKey(keyPair.publicKey);
        this.did = didObject.id;
        this.storageProvider = storageProvider || storage_2.StorageFactory.getDefaultProvider();
        this.agentManager = new agent_identity_1.AgentIdentityManager();
        this.delegationManager = new delegation_manager_1.DelegationManager();
        this.agentRevocationService = new agent_revocation_service_1.AgentRevocationService(keyPair, this.did, this.storageProvider);
    }
    static async create(storageProvider) {
        const keyPair = await crypto_1.CryptoService.generateKeyPair();
        const wallet = new UserWallet(keyPair, storageProvider);
        // Store DID document
        const publicKeyMultibase = wallet.did.substring('did:key:'.length); // Extract multibase from DID
        const didDocument = {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: wallet.did,
            verificationMethod: [{
                    id: `${wallet.did}#key-1`,
                    type: 'Ed25519VerificationKey2020',
                    controller: wallet.did,
                    publicKeyMultibase: publicKeyMultibase
                }],
            authentication: [`${wallet.did}#key-1`],
            assertionMethod: [`${wallet.did}#key-1`],
            created: new Date().toISOString()
        };
        await wallet.storageProvider.storeDID(wallet.did, didDocument);
        return wallet;
    }
    static async restore(passphrase, identifier = 'default', storageProvider) {
        const keyPair = await storage_1.SecureStorage.retrieveKeyPair(passphrase, identifier);
        if (!keyPair)
            return null;
        const wallet = new UserWallet(keyPair, storageProvider);
        return wallet;
    }
    async save(passphrase, identifier = 'default') {
        // Store key pair using SecureStorage (which uses the storage provider internally)
        await storage_1.SecureStorage.storeKeyPair(this.keyPair, passphrase, identifier);
    }
    async storeCredential(credential) {
        await this.storageProvider.storeCredential(credential);
    }
    async getCredential(credentialId) {
        return await this.storageProvider.getCredential(credentialId);
    }
    async getAllCredentials() {
        return await this.storageProvider.listCredentials(this.did);
    }
    async getCredentialsByType(type) {
        const allCredentials = await this.getAllCredentials();
        return allCredentials.filter(vc => vc.type.includes(type));
    }
    async createVerifiablePresentation(credentialIds) {
        // Collect selected credentials
        const selectedCredentials = [];
        for (const credId of credentialIds) {
            const credential = await this.storageProvider.getCredential(credId);
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
    async createSelectiveDisclosurePresentation(disclosureRequests) {
        const disclosedCredentials = [];
        for (const request of disclosureRequests) {
            const credential = await this.storageProvider.getCredential(request.credentialId);
            if (!credential) {
                throw new Error(`Credential not found: ${request.credentialId}`);
            }
            // If no specific attributes requested, include the full credential
            if (!request.attributesToDisclose || request.attributesToDisclose.length === 0) {
                disclosedCredentials.push(credential);
            }
            else {
                // Create selectively disclosed credential
                const disclosedCredential = await selective_disclosure_1.SelectiveDisclosure.createSelectivelyDisclosedCredential(credential, request.attributesToDisclose, this.keyPair.privateKey, this.did);
                disclosedCredentials.push(disclosedCredential);
            }
        }
        if (disclosedCredentials.length === 0) {
            throw new Error('No credentials selected for presentation');
        }
        // Create the presentation with selectively disclosed credentials
        const presentation = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            type: ["VerifiablePresentation", "SelectiveDisclosurePresentation"],
            verifiableCredential: disclosedCredentials
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
    setStorageProvider(provider) {
        this.storageProvider = provider;
    }
    // Agent management methods
    async createAgent(config) {
        const agent = await this.agentManager.createAgent(this.did, config);
        // Store agent information in storage provider
        await this.storageProvider.storeCredential({
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: `${this.did}/agents/${agent.did}`,
            type: ['VerifiableCredential', 'AgentRegistration'],
            issuer: this.did,
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
                id: agent.did,
                type: 'Agent',
                name: agent.name,
                description: agent.description,
                parentDID: this.did,
                createdAt: agent.createdAt.toISOString()
            }
        });
        return agent;
    }
    async grantAgentAccess(agentDID, grant) {
        const agent = this.agentManager.getAgent(agentDID);
        if (!agent || agent.parentDID !== this.did) {
            throw new Error('Agent not found or not owned by this wallet');
        }
        // Create delegation credential
        const delegationCredential = await this.delegationManager.createDelegationCredential(this.did, this.keyPair, agentDID, agent.name, grant);
        // Store grant and credential
        this.agentManager.addAccessGrant(agentDID, grant);
        this.agentManager.addDelegationCredential(agentDID, delegationCredential);
        // Store in persistent storage
        await this.storageProvider.storeCredential(delegationCredential);
        return delegationCredential;
    }
    listAgents() {
        return this.agentManager.listAgents(this.did);
    }
    getAgentAccess(agentDID) {
        const agent = this.agentManager.getAgent(agentDID);
        if (!agent || agent.parentDID !== this.did) {
            throw new Error('Agent not found or not owned by this wallet');
        }
        return this.agentManager.getAccessGrants(agentDID);
    }
    async revokeAgentAccess(agentDID, serviceDID) {
        const agent = this.agentManager.getAgent(agentDID);
        if (!agent || agent.parentDID !== this.did) {
            throw new Error('Agent not found or not owned by this wallet');
        }
        if (serviceDID) {
            // Revoke specific service access
            this.agentManager.revokeServiceAccess(agentDID, serviceDID);
            // Add to revocation list
            await this.agentRevocationService.revokeAgentServiceAccess(agentDID, this.did, serviceDID, 'Access revoked by user');
        }
        else {
            // Revoke all access for the agent
            const grants = this.agentManager.getAccessGrants(agentDID);
            for (const grant of grants) {
                this.agentManager.revokeServiceAccess(agentDID, grant.serviceDID);
            }
            // Add agent to revocation list
            await this.agentRevocationService.revokeAgent(agentDID, this.did, 'Agent access completely revoked by user');
        }
    }
    async revokeAgent(agentDID) {
        const agent = this.agentManager.getAgent(agentDID);
        if (!agent || agent.parentDID !== this.did) {
            throw new Error('Agent not found or not owned by this wallet');
        }
        // Revoke all access
        await this.revokeAgentAccess(agentDID);
        // Delete the agent
        this.agentManager.deleteAgent(agentDID);
    }
    getAgentManager() {
        return this.agentManager;
    }
}
exports.UserWallet = UserWallet;
//# sourceMappingURL=user-wallet.js.map