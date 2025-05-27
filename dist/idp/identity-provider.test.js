"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const identity_provider_1 = require("./identity-provider");
const user_wallet_1 = require("../wallet/user-wallet");
describe('IdentityProvider', () => {
    let idp;
    let userWallet;
    beforeEach(async () => {
        idp = await identity_provider_1.IdentityProvider.create();
        userWallet = await user_wallet_1.UserWallet.create();
    });
    describe('issueVerifiableCredential', () => {
        it('should issue a valid verifiable credential', async () => {
            const attributes = {
                givenName: 'Alice',
                dateOfBirth: '1990-01-15'
            };
            const credential = await idp.issueVerifiableCredential(userWallet.getDID(), attributes);
            expect(credential['@context']).toBeDefined();
            expect(credential.type).toContain('VerifiableCredential');
            expect(credential.type).toContain('BasicProfileCredential');
            expect(credential.issuer).toBe(idp.getDID());
            expect(credential.credentialSubject.id).toBe(userWallet.getDID());
            expect(credential.credentialSubject.givenName).toBe('Alice');
            expect(credential.credentialSubject.dateOfBirth).toBe('1990-01-15');
            expect(credential.credentialSubject.isOver18).toBe(true);
            expect(credential.proof).toBeDefined();
            expect(credential.proof?.jws).toBeDefined();
        });
        it('should auto-calculate isOver18 based on dateOfBirth', async () => {
            const today = new Date();
            const recentBirthDate = new Date(today.getFullYear() - 17, today.getMonth(), today.getDate()).toISOString().split('T')[0];
            const attributes = {
                givenName: 'Bob',
                dateOfBirth: recentBirthDate
            };
            const credential = await idp.issueVerifiableCredential(userWallet.getDID(), attributes);
            expect(credential.credentialSubject.isOver18).toBe(false);
        });
        it('should validate required attributes', async () => {
            const attributes = {
                // Missing required givenName
                dateOfBirth: '1990-01-15'
            };
            await expect(idp.issueVerifiableCredential(userWallet.getDID(), attributes)).rejects.toThrow('Invalid attributes');
        });
        it('should validate attribute types', async () => {
            const attributes = {
                givenName: 'Alice',
                dateOfBirth: 'invalid-date'
            };
            await expect(idp.issueVerifiableCredential(userWallet.getDID(), attributes)).rejects.toThrow('Invalid attributes');
        });
    });
});
//# sourceMappingURL=identity-provider.test.js.map