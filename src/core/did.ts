import * as multibase from 'multibase';
import * as multicodec from 'multicodec';
import { DID, KeyPair } from '../types';

export class DIDService {
  private static readonly ED25519_MULTICODEC = 0xed;
  
  static createDIDKey(publicKey: Uint8Array): DID {
    // Add multicodec prefix for Ed25519 public key
    const multicodecPrefixed = new Uint8Array(2 + publicKey.length);
    multicodecPrefixed[0] = this.ED25519_MULTICODEC;
    multicodecPrefixed[1] = 0x01; // varint encoding for Ed25519
    multicodecPrefixed.set(publicKey, 2);
    
    // Encode with multibase (base58btc)
    const multibaseEncoded = multibase.encode('base58btc', multicodecPrefixed);
    
    // Convert to string
    const encodedString = new TextDecoder().decode(multibaseEncoded);
    
    // Create did:key identifier
    const did = `did:key:${encodedString}`;
    
    return {
      id: did,
      publicKey
    };
  }
  
  static getPublicKeyFromDID(didKey: string): Uint8Array {
    if (!didKey.startsWith('did:key:')) {
      throw new Error('Invalid did:key format');
    }
    
    // Extract the multibase encoded part
    const multibaseEncoded = didKey.substring('did:key:'.length);
    
    // Convert string to Uint8Array
    const encodedBytes = new TextEncoder().encode(multibaseEncoded);
    
    // Decode multibase
    const decoded = multibase.decode(encodedBytes);
    
    // Remove multicodec prefix (2 bytes for Ed25519)
    return decoded.slice(2);
  }
  
  static async createDIDDocument(did: DID) {
    return {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did.id,
      verificationMethod: [{
        id: `${did.id}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: did.id,
        publicKeyMultibase: multibase.encode('base58btc', did.publicKey)
      }],
      authentication: [`${did.id}#key-1`],
      assertionMethod: [`${did.id}#key-1`]
    };
  }
}