import { VerifiableCredential, VerifiablePresentation, KeyPair } from '../types';
export declare class UserWallet {
    private keyPair;
    private did;
    private credentials;
    constructor(keyPair: KeyPair);
    static create(): Promise<UserWallet>;
    static restore(passphrase: string, identifier?: string): Promise<UserWallet | null>;
    save(passphrase: string, identifier?: string): Promise<void>;
    storeCredential(credential: VerifiableCredential): void;
    getCredential(credentialId: string): VerifiableCredential | undefined;
    getAllCredentials(): VerifiableCredential[];
    getCredentialsByType(type: string): VerifiableCredential[];
    createVerifiablePresentation(credentialIds: string[]): Promise<VerifiablePresentation>;
    private signPresentation;
    getDID(): string;
    getPublicKey(): Uint8Array;
}
//# sourceMappingURL=user-wallet.d.ts.map