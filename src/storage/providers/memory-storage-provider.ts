import { IStorageProvider, RevocationList, CredentialSchema } from '../types';
import { VerifiableCredential, PhoneNumber, EmailAddress, Address } from '../../types';
import { DIDDocument } from '../../types/did';
import { v4 as uuidv4 } from 'uuid';

export class MemoryStorageProvider implements IStorageProvider {
  private dids: Map<string, DIDDocument> = new Map();
  private credentials: Map<string, VerifiableCredential> = new Map();
  private credentialsByHolder: Map<string, Set<string>> = new Map();
  private keyPairs: Map<string, string> = new Map();
  private revocationLists: Map<string, RevocationList> = new Map();
  private schemas: Map<string, CredentialSchema> = new Map();
  private schemasByIssuer: Map<string, Set<string>> = new Map();
  private phoneNumbers: Map<string, PhoneNumber> = new Map();
  private phoneNumbersByUser: Map<string, Set<string>> = new Map();
  private emailAddresses: Map<string, EmailAddress> = new Map();
  private emailAddressesByUser: Map<string, Set<string>> = new Map();
  private addresses: Map<string, Address> = new Map();
  private addressesByUser: Map<string, Set<string>> = new Map();

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    this.dids.set(did, document);
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    return this.dids.get(did) || null;
  }

  async listDIDs(owner?: string): Promise<string[]> {
    if (!owner) {
      return Array.from(this.dids.keys());
    }
    // Filter by owner - check if any verification method has this owner as controller
    return Array.from(this.dids.keys()).filter(did => {
      const doc = this.dids.get(did);
      if (!doc || !doc.verificationMethod) return false;
      return doc.verificationMethod.some(vm => vm.controller === owner);
    });
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    this.credentials.set(credential.id, credential);
    
    // Update holder index
    const holder = credential.credentialSubject.id;
    if (!this.credentialsByHolder.has(holder)) {
      this.credentialsByHolder.set(holder, new Set());
    }
    this.credentialsByHolder.get(holder)!.add(credential.id);
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    return this.credentials.get(id) || null;
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    const credentialIds = this.credentialsByHolder.get(holder);
    if (!credentialIds) return [];
    
    const credentials: VerifiableCredential[] = [];
    for (const id of credentialIds) {
      const credential = this.credentials.get(id);
      if (credential) {
        credentials.push(credential);
      }
    }
    return credentials;
  }

  async deleteCredential(id: string): Promise<void> {
    const credential = this.credentials.get(id);
    if (credential) {
      const holder = credential.credentialSubject.id;
      const holderCreds = this.credentialsByHolder.get(holder);
      if (holderCreds) {
        holderCreds.delete(id);
        if (holderCreds.size === 0) {
          this.credentialsByHolder.delete(holder);
        }
      }
      this.credentials.delete(id);
    }
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    this.revocationLists.set(issuerDID, revocationList);
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    const revocationList = this.revocationLists.get(issuerDID);
    if (!revocationList) return false;
    return revocationList.revokedCredentialIds.includes(credentialId);
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    return this.revocationLists.get(issuerDID) || null;
  }

  // Key Management
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    this.keyPairs.set(identifier, encryptedKeyPair);
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    return this.keyPairs.get(identifier) || null;
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    this.keyPairs.delete(identifier);
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const schemaWithId = { ...schema, id: schemaId };
    this.schemas.set(schemaId, schemaWithId);
    
    // Update issuer index
    if (!this.schemasByIssuer.has(schema.issuerDID)) {
      this.schemasByIssuer.set(schema.issuerDID, new Set());
    }
    this.schemasByIssuer.get(schema.issuerDID)!.add(schemaId);
    
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    return this.schemas.get(schemaId) || null;
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    if (!issuerDID) {
      return Array.from(this.schemas.values());
    }
    
    const schemaIds = this.schemasByIssuer.get(issuerDID);
    if (!schemaIds) return [];
    
    const schemas: CredentialSchema[] = [];
    for (const id of schemaIds) {
      const schema = this.schemas.get(id);
      if (schema) {
        schemas.push(schema);
      }
    }
    return schemas;
  }

  // Phone Number Operations
  async storePhoneNumber(userDID: string, phoneNumber: PhoneNumber): Promise<string> {
    const phoneId = phoneNumber.id || `phone:${uuidv4()}`;
    const phoneWithId = { ...phoneNumber, id: phoneId };
    this.phoneNumbers.set(phoneId, phoneWithId);
    
    // Update user index
    if (!this.phoneNumbersByUser.has(userDID)) {
      this.phoneNumbersByUser.set(userDID, new Set());
    }
    this.phoneNumbersByUser.get(userDID)!.add(phoneId);
    
    return phoneId;
  }

  async getPhoneNumber(userDID: string, phoneId: string): Promise<PhoneNumber | null> {
    const userPhones = this.phoneNumbersByUser.get(userDID);
    if (!userPhones || !userPhones.has(phoneId)) {
      return null;
    }
    return this.phoneNumbers.get(phoneId) || null;
  }

  async listPhoneNumbers(userDID: string): Promise<PhoneNumber[]> {
    const phoneIds = this.phoneNumbersByUser.get(userDID);
    if (!phoneIds) return [];
    
    const phoneNumbers: PhoneNumber[] = [];
    for (const id of phoneIds) {
      const phone = this.phoneNumbers.get(id);
      if (phone) {
        phoneNumbers.push(phone);
      }
    }
    return phoneNumbers;
  }

  async updatePhoneNumber(userDID: string, phoneId: string, phoneNumber: Partial<PhoneNumber>): Promise<void> {
    const userPhones = this.phoneNumbersByUser.get(userDID);
    if (!userPhones || !userPhones.has(phoneId)) {
      throw new Error('Phone number not found');
    }
    
    const existingPhone = this.phoneNumbers.get(phoneId);
    if (existingPhone) {
      const updatedPhone = { ...existingPhone, ...phoneNumber, id: phoneId };
      this.phoneNumbers.set(phoneId, updatedPhone);
    }
  }

  async deletePhoneNumber(userDID: string, phoneId: string): Promise<void> {
    const userPhones = this.phoneNumbersByUser.get(userDID);
    if (userPhones) {
      userPhones.delete(phoneId);
      if (userPhones.size === 0) {
        this.phoneNumbersByUser.delete(userDID);
      }
    }
    this.phoneNumbers.delete(phoneId);
  }

  // Email Address Operations
  async storeEmailAddress(userDID: string, emailAddress: EmailAddress): Promise<string> {
    const emailId = emailAddress.id || `email:${uuidv4()}`;
    const emailWithId = { ...emailAddress, id: emailId };
    this.emailAddresses.set(emailId, emailWithId);
    
    // Update user index
    if (!this.emailAddressesByUser.has(userDID)) {
      this.emailAddressesByUser.set(userDID, new Set());
    }
    this.emailAddressesByUser.get(userDID)!.add(emailId);
    
    return emailId;
  }

  async getEmailAddress(userDID: string, emailId: string): Promise<EmailAddress | null> {
    const userEmails = this.emailAddressesByUser.get(userDID);
    if (!userEmails || !userEmails.has(emailId)) {
      return null;
    }
    return this.emailAddresses.get(emailId) || null;
  }

  async listEmailAddresses(userDID: string): Promise<EmailAddress[]> {
    const emailIds = this.emailAddressesByUser.get(userDID);
    if (!emailIds) return [];
    
    const emailAddresses: EmailAddress[] = [];
    for (const id of emailIds) {
      const email = this.emailAddresses.get(id);
      if (email) {
        emailAddresses.push(email);
      }
    }
    return emailAddresses;
  }

  async updateEmailAddress(userDID: string, emailId: string, emailAddress: Partial<EmailAddress>): Promise<void> {
    const userEmails = this.emailAddressesByUser.get(userDID);
    if (!userEmails || !userEmails.has(emailId)) {
      throw new Error('Email address not found');
    }
    
    const existingEmail = this.emailAddresses.get(emailId);
    if (existingEmail) {
      const updatedEmail = { ...existingEmail, ...emailAddress, id: emailId };
      this.emailAddresses.set(emailId, updatedEmail);
    }
  }

  async deleteEmailAddress(userDID: string, emailId: string): Promise<void> {
    const userEmails = this.emailAddressesByUser.get(userDID);
    if (userEmails) {
      userEmails.delete(emailId);
      if (userEmails.size === 0) {
        this.emailAddressesByUser.delete(userDID);
      }
    }
    this.emailAddresses.delete(emailId);
  }

  // Address Operations
  async storeAddress(userDID: string, address: Address): Promise<string> {
    const addressId = address.id || `address:${uuidv4()}`;
    const addressWithId = { ...address, id: addressId };
    this.addresses.set(addressId, addressWithId);
    
    // Update user index
    if (!this.addressesByUser.has(userDID)) {
      this.addressesByUser.set(userDID, new Set());
    }
    this.addressesByUser.get(userDID)!.add(addressId);
    
    return addressId;
  }

  async getAddress(userDID: string, addressId: string): Promise<Address | null> {
    const userAddresses = this.addressesByUser.get(userDID);
    if (!userAddresses || !userAddresses.has(addressId)) {
      return null;
    }
    return this.addresses.get(addressId) || null;
  }

  async listAddresses(userDID: string): Promise<Address[]> {
    const addressIds = this.addressesByUser.get(userDID);
    if (!addressIds) return [];
    
    const addresses: Address[] = [];
    for (const id of addressIds) {
      const address = this.addresses.get(id);
      if (address) {
        addresses.push(address);
      }
    }
    return addresses;
  }

  async updateAddress(userDID: string, addressId: string, address: Partial<Address>): Promise<void> {
    const userAddresses = this.addressesByUser.get(userDID);
    if (!userAddresses || !userAddresses.has(addressId)) {
      throw new Error('Address not found');
    }
    
    const existingAddress = this.addresses.get(addressId);
    if (existingAddress) {
      const updatedAddress = { ...existingAddress, ...address, id: addressId };
      this.addresses.set(addressId, updatedAddress);
    }
  }

  async deleteAddress(userDID: string, addressId: string): Promise<void> {
    const userAddresses = this.addressesByUser.get(userDID);
    if (userAddresses) {
      userAddresses.delete(addressId);
      if (userAddresses.size === 0) {
        this.addressesByUser.delete(userDID);
      }
    }
    this.addresses.delete(addressId);
  }

  // General operations
  async clear(): Promise<void> {
    this.dids.clear();
    this.credentials.clear();
    this.credentialsByHolder.clear();
    this.keyPairs.clear();
    this.revocationLists.clear();
    this.schemas.clear();
    this.schemasByIssuer.clear();
    this.phoneNumbers.clear();
    this.phoneNumbersByUser.clear();
    this.emailAddresses.clear();
    this.emailAddressesByUser.clear();
    this.addresses.clear();
    this.addressesByUser.clear();
  }
}