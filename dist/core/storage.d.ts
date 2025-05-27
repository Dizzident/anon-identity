import { KeyPair } from '../types';
export interface StoredKeyPair {
    publicKey: string;
    encryptedPrivateKey: string;
    salt: string;
    iv: string;
}
export declare class SecureStorage {
    private static storage;
    static storeKeyPair(keyPair: KeyPair, passphrase: string, identifier?: string): Promise<void>;
    static retrieveKeyPair(passphrase: string, identifier?: string): Promise<KeyPair | null>;
    static store(key: string, value: any): void;
    static retrieve(key: string): any;
    static delete(key: string): boolean;
    static clear(): void;
}
//# sourceMappingURL=storage.d.ts.map