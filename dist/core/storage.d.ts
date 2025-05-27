import { KeyPair } from '../types';
import { IStorageProvider } from '../storage';
export interface StoredKeyPair {
    publicKey: string;
    encryptedPrivateKey: string;
    salt: string;
    iv: string;
}
export declare class SecureStorage {
    private static storageProvider;
    /**
     * Set a custom storage provider
     */
    static setStorageProvider(provider: IStorageProvider): void;
    static storeKeyPair(keyPair: KeyPair, passphrase: string, identifier?: string): Promise<void>;
    static retrieveKeyPair(passphrase: string, identifier?: string): Promise<KeyPair | null>;
    static store(key: string, value: any): Promise<void>;
    static retrieve(key: string): Promise<any>;
    static delete(key: string): Promise<boolean>;
    static clear(): Promise<void>;
}
//# sourceMappingURL=storage.d.ts.map