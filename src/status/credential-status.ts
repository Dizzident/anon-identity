import { CredentialStatus, CredentialStatusType } from '../types/vc2';
import { DID } from '../types';
import { CryptoService } from '../core/crypto';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';

/**
 * Interface for credential status checking
 */
export interface CredentialStatusChecker {
  /**
   * Check if a credential is revoked or suspended
   * @param credentialId The credential ID to check
   * @param statusInfo The credential status information
   * @returns Status check result
   */
  checkStatus(credentialId: string, statusInfo: CredentialStatus): Promise<StatusCheckResult>;
}

export interface StatusCheckResult {
  revoked: boolean;
  suspended?: boolean;
  reason?: string;
  statusListIndex?: number;
  checkedAt: string;
}

/**
 * RevocationList2020 status checker
 * Compatible with existing revocation implementation
 */
export class RevocationList2020StatusChecker implements CredentialStatusChecker {
  constructor(
    private revocationLists: Map<string, any> = new Map()
  ) {}

  async checkStatus(credentialId: string, statusInfo: CredentialStatus): Promise<StatusCheckResult> {
    if (statusInfo.type !== CredentialStatusType.REVOCATION_LIST_2020) {
      throw new Error(`Unsupported status type: ${statusInfo.type}`);
    }

    const list = this.revocationLists.get(statusInfo.id);
    if (!list) {
      // If we can't find the list, assume not revoked
      return {
        revoked: false,
        checkedAt: new Date().toISOString()
      };
    }

    const isRevoked = list.revokedCredentials?.includes(credentialId) || false;
    
    return {
      revoked: isRevoked,
      reason: isRevoked ? 'Credential has been revoked' : undefined,
      checkedAt: new Date().toISOString()
    };
  }

  /**
   * Add or update a revocation list
   */
  addRevocationList(listId: string, list: any): void {
    this.revocationLists.set(listId, list);
  }
}

/**
 * StatusList2021 implementation
 * Uses a bitstring to efficiently store credential status
 */
export class StatusList2021 {
  private bitstring: Uint8Array;
  private size: number;

  constructor(size: number = 100000) {
    this.size = size;
    // Each byte holds 8 bits
    this.bitstring = new Uint8Array(Math.ceil(size / 8));
  }

  /**
   * Set status for a credential at given index
   * @param index The index in the status list
   * @param revoked Whether the credential is revoked
   */
  setStatus(index: number, revoked: boolean): void {
    if (index < 0 || index >= this.size) {
      throw new Error(`Index ${index} out of bounds (0-${this.size - 1})`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (revoked) {
      // Set bit to 1
      this.bitstring[byteIndex] |= (1 << bitIndex);
    } else {
      // Set bit to 0
      this.bitstring[byteIndex] &= ~(1 << bitIndex);
    }
  }

  /**
   * Check status for a credential at given index
   * @param index The index in the status list
   * @returns Whether the credential is revoked
   */
  getStatus(index: number): boolean {
    if (index < 0 || index >= this.size) {
      throw new Error(`Index ${index} out of bounds (0-${this.size - 1})`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    return (this.bitstring[byteIndex] & (1 << bitIndex)) !== 0;
  }

  /**
   * Encode the bitstring as base64
   */
  encode(): string {
    return Buffer.from(this.bitstring).toString('base64');
  }

  /**
   * Decode from base64
   */
  static decode(encoded: string, size: number): StatusList2021 {
    const list = new StatusList2021(size);
    list.bitstring = new Uint8Array(Buffer.from(encoded, 'base64'));
    return list;
  }

  /**
   * Create a signed status list credential
   */
  async createStatusListCredential(
    issuerDID: DID,
    privateKey: Uint8Array,
    listId: string
  ): Promise<any> {
    const now = new Date().toISOString();
    
    const statusListCredential = {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/vc/status-list/2021/v1"
      ],
      id: listId,
      type: ["VerifiableCredential", "StatusList2021Credential"],
      issuer: issuerDID.id,
      validFrom: now,
      credentialSubject: {
        id: `${listId}#list`,
        type: "StatusList2021",
        statusPurpose: "revocation",
        encodedList: this.encode()
      }
    };

    // Sign the credential
    const jwt = await new SignJWT({
      vc: statusListCredential,
      iss: issuerDID.id,
      sub: statusListCredential.credentialSubject.id
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .sign(privateKey);

    return {
      ...statusListCredential,
      proof: {
        type: "Ed25519Signature2020",
        created: now,
        verificationMethod: `${issuerDID.id}#key-1`,
        proofPurpose: "assertionMethod",
        jws: jwt
      }
    };
  }
}

/**
 * StatusList2021 status checker
 */
export class StatusList2021StatusChecker implements CredentialStatusChecker {
  constructor(
    private statusLists: Map<string, StatusList2021> = new Map()
  ) {}

  async checkStatus(credentialId: string, statusInfo: CredentialStatus): Promise<StatusCheckResult> {
    if (statusInfo.type !== CredentialStatusType.STATUS_LIST_2021) {
      throw new Error(`Unsupported status type: ${statusInfo.type}`);
    }

    const statusListIndex = (statusInfo as any).statusListIndex;
    if (typeof statusListIndex !== 'number') {
      throw new Error('StatusList2021 requires statusListIndex');
    }

    const list = this.statusLists.get(statusInfo.id);
    if (!list) {
      // If we can't find the list, assume not revoked
      return {
        revoked: false,
        statusListIndex,
        checkedAt: new Date().toISOString()
      };
    }

    const isRevoked = list.getStatus(statusListIndex);
    
    return {
      revoked: isRevoked,
      statusListIndex,
      reason: isRevoked ? 'Credential has been revoked' : undefined,
      checkedAt: new Date().toISOString()
    };
  }

  /**
   * Add or update a status list
   */
  addStatusList(listId: string, list: StatusList2021): void {
    this.statusLists.set(listId, list);
  }

  /**
   * Load a status list from a credential
   */
  async loadStatusListCredential(credential: any): Promise<void> {
    // Verify the credential first
    if (!credential.proof?.jws) {
      throw new Error('Status list credential must be signed');
    }

    // Extract the encoded list
    const encodedList = credential.credentialSubject?.encodedList;
    if (!encodedList) {
      throw new Error('Status list credential missing encodedList');
    }

    // TODO: Get size from credential metadata
    const size = 100000; // Default size
    const list = StatusList2021.decode(encodedList, size);
    
    this.addStatusList(credential.id, list);
  }
}

/**
 * Composite status checker that supports multiple status types
 */
export class CompositeStatusChecker implements CredentialStatusChecker {
  private checkers: Map<string, CredentialStatusChecker> = new Map();

  constructor() {
    // Register default checkers
    this.registerChecker(CredentialStatusType.REVOCATION_LIST_2020, new RevocationList2020StatusChecker());
    this.registerChecker(CredentialStatusType.STATUS_LIST_2021, new StatusList2021StatusChecker());
  }

  registerChecker(type: string, checker: CredentialStatusChecker): void {
    this.checkers.set(type, checker);
  }

  async checkStatus(credentialId: string, statusInfo: CredentialStatus): Promise<StatusCheckResult> {
    const checker = this.checkers.get(statusInfo.type);
    if (!checker) {
      throw new Error(`No status checker registered for type: ${statusInfo.type}`);
    }

    return checker.checkStatus(credentialId, statusInfo);
  }
}