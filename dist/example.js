"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const identity_provider_1 = require("./idp/identity-provider");
const user_wallet_1 = require("./wallet/user-wallet");
const service_provider_1 = require("./sp/service-provider");
async function demonstrateIdentityFlow() {
    console.log('=== Anonymous Identity Framework Demo ===\n');
    // 1. Create Identity Provider (IDP)
    console.log('1. Setting up Identity Provider...');
    const idp = await identity_provider_1.IdentityProvider.create();
    console.log(`   IDP DID: ${idp.getDID()}\n`);
    // 2. Create User Wallet
    console.log('2. Creating User Wallet...');
    const userWallet = await user_wallet_1.UserWallet.create();
    console.log(`   User DID: ${userWallet.getDID()}\n`);
    // 3. User requests credential from IDP
    console.log('3. Issuing Verifiable Credential...');
    const userAttributes = {
        givenName: 'Alice',
        dateOfBirth: '1990-01-15',
        // isOver18 will be auto-calculated
    };
    const credential = await idp.issueVerifiableCredential(userWallet.getDID(), userAttributes);
    console.log('   Credential issued:');
    console.log(`   - ID: ${credential.id}`);
    console.log(`   - Type: ${credential.type.join(', ')}`);
    console.log(`   - Subject:`, credential.credentialSubject);
    console.log();
    // 4. User stores credential in wallet
    console.log('4. Storing credential in wallet...');
    userWallet.storeCredential(credential);
    console.log(`   Credentials in wallet: ${userWallet.getAllCredentials().length}\n`);
    // 5. Save wallet with passphrase
    console.log('5. Saving wallet with passphrase...');
    await userWallet.save('my-secure-passphrase', 'alice-wallet');
    console.log('   Wallet saved successfully\n');
    // 6. Create Service Provider
    console.log('6. Setting up Service Provider...');
    const serviceProvider = new service_provider_1.ServiceProvider('Online Age Verification Service', [
        idp.getDID() // Trust this IDP
    ]);
    console.log(`   Service: ${serviceProvider.getName()}`);
    console.log(`   Trusted Issuers: ${serviceProvider.getTrustedIssuers().join(', ')}\n`);
    // 7. User creates Verifiable Presentation
    console.log('7. Creating Verifiable Presentation...');
    const presentation = await userWallet.createVerifiablePresentation([credential.id]);
    console.log('   Presentation created with credentials:', presentation.verifiableCredential.map(vc => vc.id));
    console.log();
    // 8. Service Provider verifies presentation
    console.log('8. Verifying Presentation...');
    const verificationResult = await serviceProvider.verifyPresentation(presentation);
    if (verificationResult.valid) {
        console.log('   ✓ Presentation verified successfully!');
        console.log(`   Holder: ${verificationResult.holder}`);
        console.log('   Verified credentials:');
        verificationResult.credentials?.forEach(cred => {
            console.log(`     - ${cred.type.join(', ')}`);
            console.log(`       Issuer: ${cred.issuer}`);
            console.log('       Attributes:', cred.attributes);
        });
    }
    else {
        console.log('   ✗ Verification failed:');
        verificationResult.errors?.forEach(error => {
            console.log(`     - ${error}`);
        });
    }
    console.log('\n=== Demo Complete ===');
}
// Run the demo
demonstrateIdentityFlow().catch(console.error);
//# sourceMappingURL=example.js.map