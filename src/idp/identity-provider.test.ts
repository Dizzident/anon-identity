import { IdentityProvider } from './identity-provider';
import { UserWallet } from '../wallet/user-wallet';
import { UserAttributes } from '../types';

describe('IdentityProvider', () => {
  let idp: IdentityProvider;
  let userWallet: UserWallet;
  
  beforeEach(async () => {
    idp = await IdentityProvider.create();
    userWallet = await UserWallet.create();
  });
  
  describe('issueVerifiableCredential', () => {
    it('should issue a valid verifiable credential', async () => {
      const attributes: UserAttributes = {
        givenName: 'Alice',
        dateOfBirth: '1990-01-15'
      };
      
      const credential = await idp.issueVerifiableCredential(
        userWallet.getDID(),
        attributes
      );
      
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
      const recentBirthDate = new Date(
        today.getFullYear() - 17, 
        today.getMonth(), 
        today.getDate()
      ).toISOString().split('T')[0];
      
      const attributes: UserAttributes = {
        givenName: 'Bob',
        dateOfBirth: recentBirthDate
      };
      
      const credential = await idp.issueVerifiableCredential(
        userWallet.getDID(),
        attributes
      );
      
      expect(credential.credentialSubject.isOver18).toBe(false);
    });
    
    it('should validate required attributes', async () => {
      const attributes: UserAttributes = {
        // Missing required givenName
        dateOfBirth: '1990-01-15'
      };
      
      await expect(
        idp.issueVerifiableCredential(userWallet.getDID(), attributes)
      ).rejects.toThrow('Invalid attributes');
    });
    
    it('should validate attribute types', async () => {
      const attributes: any = {
        givenName: 'Alice',
        dateOfBirth: 'invalid-date'
      };
      
      await expect(
        idp.issueVerifiableCredential(userWallet.getDID(), attributes)
      ).rejects.toThrow('Invalid attributes');
    });
  });
});