import { KeyPair } from '../types';
export declare class CryptoService {
    static generateKeyPair(): Promise<KeyPair>;
    static getPublicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array>;
    static sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
    static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
    static bytesToHex(bytes: Uint8Array): string;
    static hexToBytes(hex: string): Uint8Array;
}
export declare const generateKeyPair: typeof CryptoService.generateKeyPair;
export declare const signData: (data: string, privateKey: Uint8Array) => string;
export declare const verifyData: (signature: string, data: string, publicKey: Uint8Array) => Promise<boolean>;
//# sourceMappingURL=crypto.d.ts.map