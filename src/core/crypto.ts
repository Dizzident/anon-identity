import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { KeyPair } from '../types';
import { webcrypto } from 'crypto';

// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Configure ed25519 to use sha512
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export class CryptoService {
  static async generateKeyPair(): Promise<KeyPair> {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKey(privateKey);
    
    return {
      privateKey,
      publicKey
    };
  }
  
  static async getPublicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
    return await ed.getPublicKey(privateKey);
  }

  static async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    return await ed.sign(message, privateKey);
  }

  static async verify(
    signature: Uint8Array, 
    message: Uint8Array, 
    publicKey: Uint8Array
  ): Promise<boolean> {
    return await ed.verify(signature, message, publicKey);
  }

  static bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  static hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }
}