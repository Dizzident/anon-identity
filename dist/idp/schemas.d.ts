import { AttributeSchema } from '../types';
export declare const BASIC_PROFILE_SCHEMA: AttributeSchema[];
export declare const CONTACT_INFO_SCHEMA: AttributeSchema[];
export declare const CREDENTIAL_CONTEXTS: {
    W3C_VC: string;
    BASIC_PROFILE: string;
    CONTACT_INFO: string;
    ED25519_2020: string;
};
export declare const CREDENTIAL_TYPES: {
    VERIFIABLE_CREDENTIAL: string;
    BASIC_PROFILE: string;
    CONTACT_INFO: string;
};
export declare function validateAttributes(attributes: Record<string, any>, schema: AttributeSchema[]): {
    valid: boolean;
    errors: string[];
};
//# sourceMappingURL=schemas.d.ts.map