import { VerifiableCredential, KeyPair, UserAttributes } from '../types';
export declare class IdentityProvider {
    private keyPair;
    private did;
    constructor(keyPair: KeyPair);
    static create(): Promise<IdentityProvider>;
    issueVerifiableCredential(userDID: string, attributes: UserAttributes): Promise<VerifiableCredential>;
    private signCredential;
    getDID(): string;
}
//# sourceMappingURL=identity-provider.d.ts.map