import { DID } from '../types';
export declare class DIDService {
    private static readonly ED25519_MULTICODEC;
    static createDIDKey(publicKey: Uint8Array): DID;
    static getPublicKeyFromDID(didKey: string): Uint8Array;
    static createDIDDocument(did: DID): Promise<{
        "@context": string[];
        id: string;
        verificationMethod: {
            id: string;
            type: string;
            controller: string;
            publicKeyMultibase: Uint8Array<ArrayBufferLike>;
        }[];
        authentication: string[];
        assertionMethod: string[];
    }>;
}
//# sourceMappingURL=did.d.ts.map