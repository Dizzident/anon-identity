// W3C Verifiable Credentials 2.0 Types
// https://www.w3.org/TR/vc-data-model-2.0/

export interface Proof {
  type: string;
  created?: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue?: string;
  jws?: string;
  challenge?: string;
  domain?: string;
  nonce?: string;
  expires?: string;
  [key: string]: any;
}

export interface CredentialStatus {
  id: string;
  type: string;
  [key: string]: any;
}

export interface TermsOfUse {
  type: string;
  id?: string;
  profile?: string;
  prohibition?: Array<{
    assigner: string;
    assignee: string;
    target: string;
    action: string[];
  }>;
  obligation?: Array<{
    assigner: string;
    assignee: string;
    target: string;
    action: string[];
  }>;
  [key: string]: any;
}

export interface Evidence {
  id?: string;
  type: string | string[];
  verifier?: string;
  evidenceDocument?: string;
  subjectPresence?: string;
  documentPresence?: string;
  licenseNumber?: string;
  [key: string]: any;
}

export interface RefreshService {
  id: string;
  type: string;
  [key: string]: any;
}

export interface CredentialSchema {
  id: string;
  type: string;
  [key: string]: any;
}

// W3C VC 2.0 compliant VerifiableCredential
export interface VerifiableCredentialV2 {
  "@context": string | string[] | Record<string, any> | Array<string | Record<string, any>>;
  id?: string;
  type: string | string[];
  issuer: string | { id: string; [key: string]: any };
  validFrom?: string; // replaces issuanceDate in VC 2.0
  validUntil?: string; // new in VC 2.0
  credentialSubject: {
    id?: string;
    [key: string]: any;
  } | Array<{
    id?: string;
    [key: string]: any;
  }>;
  proof?: Proof | Proof[];
  credentialStatus?: CredentialStatus | CredentialStatus[];
  termsOfUse?: TermsOfUse | TermsOfUse[];
  evidence?: Evidence | Evidence[];
  credentialSchema?: CredentialSchema | CredentialSchema[];
  refreshService?: RefreshService | RefreshService[];
  // Legacy support
  issuanceDate?: string; // deprecated in VC 2.0, use validFrom
  expirationDate?: string; // deprecated in VC 2.0, use validUntil
}

// W3C VC 2.0 compliant VerifiablePresentation
export interface VerifiablePresentationV2 {
  "@context": string | string[] | Record<string, any> | Array<string | Record<string, any>>;
  id?: string;
  type: string | string[];
  verifiableCredential?: (VerifiableCredentialV2 | string)[];
  holder?: string | { id: string; [key: string]: any };
  proof?: Proof | Proof[];
  termsOfUse?: TermsOfUse | TermsOfUse[];
}

// Signature Suite type (interface moved to ld/signature-suites)
export type SignatureSuiteType = string;

// Proof Purpose definitions
export enum ProofPurpose {
  ASSERTION_METHOD = "assertionMethod",
  AUTHENTICATION = "authentication",
  KEY_AGREEMENT = "keyAgreement",
  CAPABILITY_INVOCATION = "capabilityInvocation",
  CAPABILITY_DELEGATION = "capabilityDelegation"
}

// Credential Status types
export enum CredentialStatusType {
  REVOCATION_LIST_2020 = "RevocationList2020",
  STATUS_LIST_2021 = "StatusList2021",
  BITSTRING_STATUS_LIST = "BitstringStatusListEntry"
}

// Common VC 2.0 contexts
export const VC_V2_CONTEXTS = {
  CREDENTIALS_V2: "https://www.w3.org/ns/credentials/v2",
  CREDENTIALS_V1: "https://www.w3.org/2018/credentials/v1", // for backward compatibility
  ED25519_2020: "https://w3id.org/security/suites/ed25519-2020/v1",
  BBS_2023: "https://w3id.org/security/bbs/v1",
  DATA_INTEGRITY_V2: "https://w3id.org/security/data-integrity/v2",
  STATUS_LIST_2021: "https://w3id.org/vc/status-list/2021/v1",
  TERMS_OF_USE: "https://w3id.org/credentials/terms-of-use/v1"
};

// Type guard to check if credential is V2
export function isVerifiableCredentialV2(credential: any): credential is VerifiableCredentialV2 {
  const contexts = Array.isArray(credential["@context"]) 
    ? credential["@context"] 
    : [credential["@context"]];
  
  return contexts.some((ctx: any) => 
    typeof ctx === "string" && 
    (ctx === VC_V2_CONTEXTS.CREDENTIALS_V2 || ctx.includes("/credentials/v2"))
  );
}

// Type to maintain backward compatibility
export type VerifiableCredentialCompat = VerifiableCredentialV2;