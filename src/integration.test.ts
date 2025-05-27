import { IdentityProvider } from './idp/identity-provider';
import { UserWallet } from './wallet/user-wallet';
import { ServiceProvider } from './sp/service-provider';
import { UserAttributes } from './types';

describe('End-to-End Identity Flow', () => {
  it('should complete full identity verification flow', async () => {
    // 1. Setup
    const idp = await IdentityProvider.create();
    const userWallet = await UserWallet.create();
    const serviceProvider = new ServiceProvider('Test Service', [idp.getDID()]);
    
    // 2. Issue credential
    const attributes: UserAttributes = {
      givenName: 'Alice',
      dateOfBirth: '1990-01-15'
    };
    
    const credential = await idp.issueVerifiableCredential(
      userWallet.getDID(),
      attributes
    );
    
    // 3. Store credential
    userWallet.storeCredential(credential);
    
    // 4. Create presentation
    const presentation = await userWallet.createVerifiablePresentation([credential.id]);
    
    // 5. Verify presentation
    const verificationResult = await serviceProvider.verifyPresentation(presentation);
    
    // Assertions
    expect(verificationResult.valid).toBe(true);
    expect(verificationResult.holder).toBe(userWallet.getDID());
    expect(verificationResult.credentials).toHaveLength(1);
    expect(verificationResult.credentials![0].attributes.givenName).toBe('Alice');
    expect(verificationResult.credentials![0].attributes.isOver18).toBe(true);
  });
  
  it('should reject presentation from untrusted issuer', async () => {
    // Setup with untrusted IDP
    const untrustedIdp = await IdentityProvider.create();
    const userWallet = await UserWallet.create();
    const serviceProvider = new ServiceProvider('Test Service', []); // No trusted issuers
    
    // Issue credential from untrusted IDP
    const credential = await untrustedIdp.issueVerifiableCredential(
      userWallet.getDID(),
      { givenName: 'Bob', dateOfBirth: '1990-01-01' }
    );
    
    userWallet.storeCredential(credential);
    const presentation = await userWallet.createVerifiablePresentation([credential.id]);
    
    // Verify presentation
    const verificationResult = await serviceProvider.verifyPresentation(presentation);
    
    expect(verificationResult.valid).toBe(false);
    expect(verificationResult.errors).toContain(
      expect.stringContaining('untrusted issuer')
    );
  });
  
  it('should support multiple credentials in presentation', async () => {
    const idp1 = await IdentityProvider.create();
    const idp2 = await IdentityProvider.create();
    const userWallet = await UserWallet.create();
    const serviceProvider = new ServiceProvider('Test Service', [
      idp1.getDID(),
      idp2.getDID()
    ]);
    
    // Issue multiple credentials
    const credential1 = await idp1.issueVerifiableCredential(
      userWallet.getDID(),
      { givenName: 'Alice', dateOfBirth: '1990-01-15' }
    );
    
    const credential2 = await idp2.issueVerifiableCredential(
      userWallet.getDID(),
      { givenName: 'Alice', dateOfBirth: '1990-01-15' }
    );
    
    userWallet.storeCredential(credential1);
    userWallet.storeCredential(credential2);
    
    // Create presentation with both credentials
    const presentation = await userWallet.createVerifiablePresentation([
      credential1.id,
      credential2.id
    ]);
    
    const verificationResult = await serviceProvider.verifyPresentation(presentation);
    
    expect(verificationResult.valid).toBe(true);
    expect(verificationResult.credentials).toHaveLength(2);
  });
  
  it('should persist and restore wallet', async () => {
    const idp = await IdentityProvider.create();
    const originalWallet = await UserWallet.create();
    const passphrase = 'test-passphrase';
    const walletId = 'test-wallet';
    
    // Issue and store credential
    const credential = await idp.issueVerifiableCredential(
      originalWallet.getDID(),
      { givenName: 'Alice', dateOfBirth: '1990-01-15' }
    );
    originalWallet.storeCredential(credential);
    
    // Save wallet
    await originalWallet.save(passphrase, walletId);
    
    // Restore wallet
    const restoredWallet = await UserWallet.restore(passphrase, walletId);
    
    expect(restoredWallet).not.toBeNull();
    expect(restoredWallet!.getDID()).toBe(originalWallet.getDID());
    expect(restoredWallet!.getAllCredentials()).toHaveLength(1);
    expect(restoredWallet!.getCredential(credential.id)).toEqual(credential);
  });
});