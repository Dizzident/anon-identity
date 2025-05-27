import { VerifiablePresentation } from '../types';
export interface VerificationResult {
    valid: boolean;
    holder?: string;
    credentials?: Array<{
        id: string;
        issuer: string;
        type: string[];
        attributes: Record<string, any>;
    }>;
    errors?: string[];
}
export declare class ServiceProvider {
    private trustedIssuers;
    private name;
    constructor(name: string, trustedIssuers?: string[]);
    verifyPresentation(presentation: VerifiablePresentation): Promise<VerificationResult>;
    private verifyCredential;
    private verifyJWT;
    addTrustedIssuer(issuerDID: string): void;
    removeTrustedIssuer(issuerDID: string): void;
    getTrustedIssuers(): string[];
    getName(): string;
}
//# sourceMappingURL=service-provider.d.ts.map