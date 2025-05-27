import { KeyPair } from '../types';
export declare class CryptoService {
    static generateKeyPair(): Promise<KeyPair>;
    static sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
    static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
    static bytesToHex(bytes: Uint8Array): string;
    static hexToBytes(hex: string): Uint8Array;
}
//# sourceMappingURL=crypto.d.ts.map