import { VerifiableCredential, VerifiablePresentation, KeyPair, SelectiveDisclosureRequest } from '../types';
import { IStorageProvider } from '../storage';
export declare class UserWallet {
    private keyPair;
    private did;
    private storageProvider;
    constructor(keyPair: KeyPair, storageProvider?: IStorageProvider);
    static create(storageProvider?: IStorageProvider): Promise<UserWallet>;
    static restore(passphrase: string, identifier?: string, storageProvider?: IStorageProvider): Promise<UserWallet | null>;
    save(passphrase: string, identifier?: string): Promise<void>;
    storeCredential(credential: VerifiableCredential): Promise<void>;
    getCredential(credentialId: string): Promise<VerifiableCredential | null>;
    getAllCredentials(): Promise<VerifiableCredential[]>;
    getCredentialsByType(type: string): Promise<VerifiableCredential[]>;
    createVerifiablePresentation(credentialIds: string[]): Promise<VerifiablePresentation>;
    createSelectiveDisclosurePresentation(disclosureRequests: SelectiveDisclosureRequest[]): Promise<VerifiablePresentation>;
    private signPresentation;
    getDID(): string;
    getPublicKey(): Uint8Array;
    setStorageProvider(provider: IStorageProvider): void;
}
//# sourceMappingURL=user-wallet.d.ts.map