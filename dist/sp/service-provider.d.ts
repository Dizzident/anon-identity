import { VerifiablePresentation } from '../types';
import { IStorageProvider } from '../storage';
import { Session, SessionValidation, SessionManagerOptions } from './session-manager';
import { VerificationError } from './verification-errors';
import { BatchVerificationResult, BatchRevocationResult, BatchOperationOptions } from './batch-operations';
import { PresentationRequestOptions, ValidationResult } from './presentation-request';
export interface VerificationResult {
    valid: boolean;
    holder?: string;
    credentials?: Array<{
        id: string;
        issuer: string;
        type: string[];
        attributes: Record<string, any>;
        selectivelyDisclosed?: boolean;
        disclosedAttributes?: string[];
    }>;
    errors?: VerificationError[];
    timestamp?: Date;
}
export interface ServiceProviderOptions {
    sessionManager?: SessionManagerOptions;
    checkRevocation?: boolean;
    storageProvider?: IStorageProvider;
    batchOperations?: BatchOperationOptions;
}
export declare class ServiceProvider {
    private trustedIssuers;
    private name;
    private checkRevocation;
    private storageProvider;
    private sessionManager;
    private batchOperations;
    private presentationRequest;
    constructor(name: string, trustedIssuers?: string[], options?: ServiceProviderOptions);
    static create(name: string, trustedIssuers?: string[], checkRevocation?: boolean, storageProvider?: IStorageProvider): ServiceProvider;
    verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult>;
    private verifyCredential;
    private verifyJWT;
    addTrustedIssuer(issuerDID: string): void;
    removeTrustedIssuer(issuerDID: string): void;
    getTrustedIssuers(): string[];
    getName(): string;
    setRevocationCheck(enabled: boolean): void;
    private checkCredentialRevocation;
    setStorageProvider(provider: IStorageProvider): void;
    createSession(verificationResult: VerificationResult, metadata?: Record<string, any>): Promise<Session>;
    validateSession(sessionId: string): Promise<SessionValidation>;
    setSessionExpiry(sessionId: string, duration: number): Promise<void>;
    getSession(sessionId: string): Session | undefined;
    getAllSessions(): Session[];
    getSessionsByHolder(holderDID: string): Session[];
    removeSession(sessionId: string): void;
    clearAllSessions(): void;
    verifyPresentationWithSession(presentation: VerifiablePresentation, createSession?: boolean, sessionMetadata?: Record<string, any>): Promise<{
        verification: VerificationResult;
        session?: Session;
    }>;
    handleCredentialRevocation(credentialId: string): Promise<void>;
    destroy(): void;
    batchVerifyPresentations(presentations: VerifiablePresentation[]): Promise<BatchVerificationResult[]>;
    batchCheckRevocations(credentialIds: string[]): Promise<Map<string, BatchRevocationResult>>;
    batchVerifyWithRevocationCheck(presentations: VerifiablePresentation[]): Promise<BatchVerificationResult[]>;
    createPresentationRequest(options: PresentationRequestOptions): Promise<import("./presentation-request").PresentationRequestObject>;
    createSimplePresentationRequest(credentialTypes: string[], purpose: string, requiredAttributes?: string[], optionalAttributes?: string[]): Promise<import("./presentation-request").PresentationRequestObject>;
    validatePresentationAgainstRequest(presentation: VerifiablePresentation, request: any): Promise<ValidationResult>;
    verifyPresentationWithRequest(presentation: VerifiablePresentation, request: any): Promise<{
        verification: VerificationResult;
        requestValidation: ValidationResult;
    }>;
}
//# sourceMappingURL=service-provider.d.ts.map