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
  verifiableCredential: VerifiableCredential[];
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    jws: string;
  };
}

export interface AttributeSchema {
  name: string;
  type: "string" | "date" | "boolean" | "number";
  required?: boolean;
}

export interface UserAttributes {
  givenName?: string;
  dateOfBirth?: string;
  isOver18?: boolean;
  [key: string]: any;
}