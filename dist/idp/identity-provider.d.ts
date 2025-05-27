import { VerifiableCredential, KeyPair, UserAttributes, RevocationList } from '../types';
export declare class IdentityProvider {
    private keyPair;
    private did;
    private revocationService;
    constructor(keyPair: KeyPair);
    static create(): Promise<IdentityProvider>;
    issueVerifiableCredential(userDID: string, attributes: UserAttributes): Promise<VerifiableCredential>;
    private signCredential;
    getDID(): string;
    /**
     * Revoke a previously issued credential
     */
    revokeCredential(credentialId: string): void;
    /**
     * Unrevoke a credential
     */
    unrevokeCredential(credentialId: string): void;
    /**
     * Check if a credential is revoked
     */
    isCredentialRevoked(credentialId: string): boolean;
    /**
     * Get the current revocation list
     */
    getRevocationList(): Promise<RevocationList>;
    /**
     * Publish the revocation list and return the URL
     */
    publishRevocationList(): Promise<string>;
    /**
     * Get all revoked credential IDs
     */
    getRevokedCredentials(): string[];
}
//# sourceMappingURL=identity-provider.d.ts.map