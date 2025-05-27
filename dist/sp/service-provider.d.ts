import { VerifiablePresentation } from '../types';
import { IStorageProvider } from '../storage';
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
    errors?: string[];
}
export declare class ServiceProvider {
    private trustedIssuers;
    private name;
    private checkRevocation;
    private storageProvider;
    constructor(name: string, trustedIssuers?: string[], checkRevocation?: boolean, storageProvider?: IStorageProvider);
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
}
//# sourceMappingURL=service-provider.d.ts.map