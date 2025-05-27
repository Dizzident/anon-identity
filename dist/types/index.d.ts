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
    type: "string" | "date" | "boolean" | "number";
    required?: boolean;
}
export interface UserAttributes {
    givenName?: string;
    dateOfBirth?: string;
    isOver18?: boolean;
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
//# sourceMappingURL=index.d.ts.map