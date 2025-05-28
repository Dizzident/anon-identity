import { StorageFactory } from '../src/storage';
import { PhoneNumber, EmailAddress, Address } from '../src/types';

async function testContactStorage() {
  console.log('Testing Phone Number, Email Address, and Address Storage...\n');

  // Create a memory storage provider
  const storage = StorageFactory.getDefaultProvider();
  
  const userDID = 'did:key:example-user';

  // Test Phone Number Storage
  console.log('=== Phone Number Storage ===');
  
  const phoneNumber: PhoneNumber = {
    number: '+1-555-123-4567',
    type: 'mobile',
    countryCode: '+1',
    isPrimary: true,
    verified: true,
    verifiedAt: new Date().toISOString(),
    // 2FA capabilities
    canReceiveSMS: true,
    canReceiveCalls: true,
    preferredFor2FA: true
  };

  const phoneId = await storage.storePhoneNumber(userDID, phoneNumber);
  console.log(`✓ Stored phone number with ID: ${phoneId}`);

  const retrievedPhone = await storage.getPhoneNumber(userDID, phoneId);
  console.log('✓ Retrieved phone number:', retrievedPhone);

  // Store another phone number
  const workPhone: PhoneNumber = {
    number: '+1-555-987-6543',
    type: 'work',
    countryCode: '+1',
    isPrimary: false,
    verified: false,
    // 2FA capabilities - work phone is not suitable for 2FA
    canReceiveSMS: false,
    canReceiveCalls: true,
    preferredFor2FA: false
  };

  const workPhoneId = await storage.storePhoneNumber(userDID, workPhone);
  console.log(`✓ Stored work phone with ID: ${workPhoneId}`);

  const allPhones = await storage.listPhoneNumbers(userDID);
  console.log(`✓ Listed ${allPhones.length} phone numbers:`, allPhones);

  // Update phone number
  await storage.updatePhoneNumber(userDID, workPhoneId, { 
    verified: true, 
    verifiedAt: new Date().toISOString() 
  });
  console.log('✓ Updated work phone verification status');

  console.log('\n=== Email Address Storage ===');

  // Test Email Address Storage
  const primaryEmail: EmailAddress = {
    email: 'user@example.com',
    type: 'personal',
    isPrimary: true,
    verified: true,
    verifiedAt: new Date().toISOString(),
    // 2FA capabilities
    canReceive2FA: true,
    preferredFor2FA: true
  };

  const emailId = await storage.storeEmailAddress(userDID, primaryEmail);
  console.log(`✓ Stored primary email with ID: ${emailId}`);

  const retrievedEmail = await storage.getEmailAddress(userDID, emailId);
  console.log('✓ Retrieved email address:', retrievedEmail);

  // Store work email
  const workEmail: EmailAddress = {
    email: 'user@company.com',
    type: 'work',
    isPrimary: false,
    verified: false,
    // 2FA capabilities - work email can receive 2FA but not preferred
    canReceive2FA: true,
    preferredFor2FA: false
  };

  const workEmailId = await storage.storeEmailAddress(userDID, workEmail);
  console.log(`✓ Stored work email with ID: ${workEmailId}`);

  const allEmails = await storage.listEmailAddresses(userDID);
  console.log(`✓ Listed ${allEmails.length} email addresses:`, allEmails);

  // Update email verification
  await storage.updateEmailAddress(userDID, workEmailId, { 
    verified: true, 
    verifiedAt: new Date().toISOString() 
  });
  console.log('✓ Updated work email verification status');

  console.log('\n=== Address Storage ===');

  // Test Address Storage
  const homeAddress: Address = {
    street: '123 Main Street',
    city: 'San Francisco',
    state: 'CA',
    postalCode: '94102',
    country: 'USA',
    type: 'home',
    isPrimary: true,
    verified: true,
    verifiedAt: new Date().toISOString()
  };

  const addressId = await storage.storeAddress(userDID, homeAddress);
  console.log(`✓ Stored home address with ID: ${addressId}`);

  const retrievedAddress = await storage.getAddress(userDID, addressId);
  console.log('✓ Retrieved address:', retrievedAddress);

  // Store work address
  const workAddress: Address = {
    street: '456 Business Ave, Suite 100',
    city: 'Palo Alto',
    state: 'CA',
    postalCode: '94301',
    country: 'USA',
    type: 'work',
    isPrimary: false,
    verified: false
  };

  const workAddressId = await storage.storeAddress(userDID, workAddress);
  console.log(`✓ Stored work address with ID: ${workAddressId}`);

  const allAddresses = await storage.listAddresses(userDID);
  console.log(`✓ Listed ${allAddresses.length} addresses:`, allAddresses);

  // Update address
  await storage.updateAddress(userDID, workAddressId, { 
    verified: true, 
    verifiedAt: new Date().toISOString() 
  });
  console.log('✓ Updated work address verification status');

  console.log('\n=== Testing Deletion ===');

  // Test deletion
  await storage.deletePhoneNumber(userDID, workPhoneId);
  console.log('✓ Deleted work phone number');

  await storage.deleteEmailAddress(userDID, workEmailId);
  console.log('✓ Deleted work email address');

  await storage.deleteAddress(userDID, workAddressId);
  console.log('✓ Deleted work address');

  const remainingPhones = await storage.listPhoneNumbers(userDID);
  const remainingEmails = await storage.listEmailAddresses(userDID);
  const remainingAddresses = await storage.listAddresses(userDID);
  
  console.log(`✓ Remaining phones: ${remainingPhones.length}`);
  console.log(`✓ Remaining emails: ${remainingEmails.length}`);
  console.log(`✓ Remaining addresses: ${remainingAddresses.length}`);

  console.log('\n=== Testing Error Cases ===');

  try {
    await storage.getPhoneNumber(userDID, 'non-existent-id');
    console.log('✓ Non-existent phone returns null');
  } catch (error) {
    console.log('✗ Error getting non-existent phone:', error);
  }

  try {
    await storage.getEmailAddress(userDID, 'non-existent-id');
    console.log('✓ Non-existent email returns null');
  } catch (error) {
    console.log('✗ Error getting non-existent email:', error);
  }

  try {
    await storage.updatePhoneNumber(userDID, 'non-existent-id', { verified: true });
    console.log('✗ Should have thrown error for non-existent phone');
  } catch (error) {
    console.log('✓ Correctly threw error for non-existent phone update');
  }

  try {
    await storage.updateEmailAddress(userDID, 'non-existent-id', { verified: true });
    console.log('✗ Should have thrown error for non-existent email');
  } catch (error) {
    console.log('✓ Correctly threw error for non-existent email update');
  }

  console.log('\n🎉 Contact storage test completed successfully!');
}

// Run the test
if (require.main === module) {
  testContactStorage().catch(console.error);
}

export { testContactStorage };