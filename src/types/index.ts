export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface DID {
  id: string;
  publicKey: Uint8Array;
}

export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id: string;
    [key: string]: any;
  };
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
}

export interface VerifiablePresentation {
  "@context": string[];
  type: string[];
  verifiableCredential: (VerifiableCredential | SelectivelyDisclosedCredential)[];
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
}

export interface SelectivelyDisclosedCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id: string;
    [key: string]: any;
  };
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
  disclosureProof?: {
    type: string;
    originalCredentialId: string;
    disclosedAttributes: string[];
    nonce: string;
    proofValue: string;
  };
}

export interface SelectiveDisclosureRequest {
  credentialId: string;
  attributesToDisclose: string[];
}

export interface AttributeSchema {
  name: string;
  type: "string" | "date" | "boolean" | "number" | "object";
  required?: boolean;
}

export interface PhoneNumber {
  id?: string;
  number: string;
  type: 'mobile' | 'home' | 'work' | 'other';
  countryCode?: string;
  isPrimary?: boolean;
  verified?: boolean;
  verifiedAt?: string;
  // Two-factor authentication capabilities
  canReceiveSMS?: boolean;
  canReceiveCalls?: boolean;
  preferredFor2FA?: boolean;
}

export interface EmailAddress {
  id?: string;
  email: string;
  type: 'personal' | 'work' | 'school' | 'other';
  isPrimary?: boolean;
  verified?: boolean;
  verifiedAt?: string;
  // Two-factor authentication capabilities
  canReceive2FA?: boolean;
  preferredFor2FA?: boolean;
}

export interface Address {
  id?: string;
  street: string;
  city: string;
  state?: string;
  postalCode?: string;
  country: string;
  type: 'home' | 'work' | 'mailing' | 'other';
  isPrimary?: boolean;
  verified?: boolean;
  verifiedAt?: string;
}

export interface UserAttributes {
  givenName?: string;
  dateOfBirth?: string;
  isOver18?: boolean;
  phoneNumbers?: PhoneNumber[];
  emailAddresses?: EmailAddress[];
  addresses?: Address[];
  [key: string]: any;
}

export interface RevocationList {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  revokedCredentials: string[];
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
}

export interface RevocationRegistry {
  [issuerDID: string]: RevocationList;
}

// Re-export W3C VC 2.0 types
export * from './vc2';