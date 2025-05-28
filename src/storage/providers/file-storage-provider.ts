import { IStorageProvider, RevocationList, CredentialSchema } from '../types';
import { VerifiableCredential, PhoneNumber, EmailAddress, Address } from '../../types';
import { DIDDocument } from '../../types/did';
import { promises as fs } from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

interface StorageData {
  dids: Record<string, DIDDocument>;
  credentials: Record<string, VerifiableCredential>;
  keyPairs: Record<string, string>;
  revocationLists: Record<string, RevocationList>;
  schemas: Record<string, CredentialSchema>;
  phoneNumbers: Record<string, PhoneNumber>;
  phoneNumbersByUser: Record<string, string[]>;
  emailAddresses: Record<string, EmailAddress>;
  emailAddressesByUser: Record<string, string[]>;
  addresses: Record<string, Address>;
  addressesByUser: Record<string, string[]>;
}

export class FileStorageProvider implements IStorageProvider {
  private dataPath: string;
  private encryption: boolean;
  private encryptionKey?: Buffer;
  private data: StorageData = {
    dids: {},
    credentials: {},
    keyPairs: {},
    revocationLists: {},
    schemas: {},
    phoneNumbers: {},
    phoneNumbersByUser: {},
    emailAddresses: {},
    emailAddressesByUser: {},
    addresses: {},
    addressesByUser: {}
  };

  constructor(dataPath: string, encryption: boolean = true, passphrase?: string) {
    this.dataPath = dataPath;
    this.encryption = encryption;
    
    if (encryption && passphrase) {
      // Derive encryption key from passphrase
      this.encryptionKey = crypto.scryptSync(passphrase, 'salt', 32);
    }
  }

  private async ensureDirectory(): Promise<void> {
    const dir = path.dirname(this.dataPath);
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  private encrypt(data: string): string {
    if (!this.encryption || !this.encryptionKey) return data;
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      encrypted,
      authTag: authTag.toString('hex'),
      iv: iv.toString('hex')
    });
  }

  private decrypt(encryptedData: string): string {
    if (!this.encryption || !this.encryptionKey) return encryptedData;
    
    try {
      const { encrypted, authTag, iv } = JSON.parse(encryptedData);
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.encryptionKey,
        Buffer.from(iv, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Failed to decrypt data. Invalid passphrase or corrupted data.');
    }
  }

  private async load(): Promise<void> {
    try {
      const rawData = await fs.readFile(this.dataPath, 'utf8');
      const decryptedData = this.decrypt(rawData);
      this.data = JSON.parse(decryptedData);
    } catch (error) {
      // File doesn't exist or is corrupted, start with empty data
      this.data = {
        dids: {},
        credentials: {},
        keyPairs: {},
        revocationLists: {},
        schemas: {},
        phoneNumbers: {},
        phoneNumbersByUser: {},
        emailAddresses: {},
        emailAddressesByUser: {},
        addresses: {},
        addressesByUser: {}
      };
    }
  }

  private async save(): Promise<void> {
    await this.ensureDirectory();
    const jsonData = JSON.stringify(this.data, null, 2);
    const dataToSave = this.encrypt(jsonData);
    await fs.writeFile(this.dataPath, dataToSave, 'utf8');
  }

  // DID Operations
  async storeDID(did: string, document: DIDDocument): Promise<void> {
    await this.load();
    this.data.dids[did] = document;
    await this.save();
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    await this.load();
    return this.data.dids[did] || null;
  }

  async listDIDs(owner?: string): Promise<string[]> {
    await this.load();
    const dids = Object.keys(this.data.dids);
    
    if (!owner) return dids;
    
    return dids.filter(did => {
      const doc = this.data.dids[did];
      if (!doc || !doc.verificationMethod) return false;
      return doc.verificationMethod.some(vm => vm.controller === owner);
    });
  }

  // Credential Operations
  async storeCredential(credential: VerifiableCredential): Promise<void> {
    await this.load();
    this.data.credentials[credential.id] = credential;
    await this.save();
  }

  async getCredential(id: string): Promise<VerifiableCredential | null> {
    await this.load();
    return this.data.credentials[id] || null;
  }

  async listCredentials(holder: string): Promise<VerifiableCredential[]> {
    await this.load();
    return Object.values(this.data.credentials).filter(
      cred => cred.credentialSubject.id === holder
    );
  }

  async deleteCredential(id: string): Promise<void> {
    await this.load();
    delete this.data.credentials[id];
    await this.save();
  }

  // Revocation Operations
  async publishRevocation(issuerDID: string, revocationList: RevocationList): Promise<void> {
    await this.load();
    this.data.revocationLists[issuerDID] = revocationList;
    await this.save();
  }

  async checkRevocation(issuerDID: string, credentialId: string): Promise<boolean> {
    await this.load();
    const revocationList = this.data.revocationLists[issuerDID];
    if (!revocationList) return false;
    return revocationList.revokedCredentialIds.includes(credentialId);
  }

  async getRevocationList(issuerDID: string): Promise<RevocationList | null> {
    await this.load();
    return this.data.revocationLists[issuerDID] || null;
  }

  // Key Management
  async storeKeyPair(identifier: string, encryptedKeyPair: string): Promise<void> {
    await this.load();
    this.data.keyPairs[identifier] = encryptedKeyPair;
    await this.save();
  }

  async retrieveKeyPair(identifier: string): Promise<string | null> {
    await this.load();
    return this.data.keyPairs[identifier] || null;
  }

  async deleteKeyPair(identifier: string): Promise<void> {
    await this.load();
    delete this.data.keyPairs[identifier];
    await this.save();
  }

  // Schema Operations
  async registerSchema(schema: CredentialSchema): Promise<string> {
    await this.load();
    const schemaId = schema.id || `schema:${uuidv4()}`;
    const schemaWithId = { ...schema, id: schemaId };
    this.data.schemas[schemaId] = schemaWithId;
    await this.save();
    return schemaId;
  }

  async getSchema(schemaId: string): Promise<CredentialSchema | null> {
    await this.load();
    return this.data.schemas[schemaId] || null;
  }

  async listSchemas(issuerDID?: string): Promise<CredentialSchema[]> {
    await this.load();
    const schemas = Object.values(this.data.schemas);
    
    if (!issuerDID) return schemas;
    
    return schemas.filter(schema => schema.issuerDID === issuerDID);
  }

  // Phone Number Operations
  async storePhoneNumber(userDID: string, phoneNumber: PhoneNumber): Promise<string> {
    await this.load();
    const phoneId = phoneNumber.id || `phone:${uuidv4()}`;
    const phoneWithId = { ...phoneNumber, id: phoneId };
    this.data.phoneNumbers[phoneId] = phoneWithId;
    
    // Update user index
    if (!this.data.phoneNumbersByUser[userDID]) {
      this.data.phoneNumbersByUser[userDID] = [];
    }
    if (!this.data.phoneNumbersByUser[userDID].includes(phoneId)) {
      this.data.phoneNumbersByUser[userDID].push(phoneId);
    }
    
    await this.save();
    return phoneId;
  }

  async getPhoneNumber(userDID: string, phoneId: string): Promise<PhoneNumber | null> {
    await this.load();
    const userPhones = this.data.phoneNumbersByUser[userDID] || [];
    if (!userPhones.includes(phoneId)) {
      return null;
    }
    return this.data.phoneNumbers[phoneId] || null;
  }

  async listPhoneNumbers(userDID: string): Promise<PhoneNumber[]> {
    await this.load();
    const phoneIds = this.data.phoneNumbersByUser[userDID] || [];
    return phoneIds
      .map(id => this.data.phoneNumbers[id])
      .filter(phone => phone !== undefined);
  }

  async updatePhoneNumber(userDID: string, phoneId: string, phoneNumber: Partial<PhoneNumber>): Promise<void> {
    await this.load();
    const userPhones = this.data.phoneNumbersByUser[userDID] || [];
    if (!userPhones.includes(phoneId)) {
      throw new Error('Phone number not found');
    }
    
    const existingPhone = this.data.phoneNumbers[phoneId];
    if (existingPhone) {
      this.data.phoneNumbers[phoneId] = { ...existingPhone, ...phoneNumber, id: phoneId };
      await this.save();
    }
  }

  async deletePhoneNumber(userDID: string, phoneId: string): Promise<void> {
    await this.load();
    const userPhones = this.data.phoneNumbersByUser[userDID] || [];
    this.data.phoneNumbersByUser[userDID] = userPhones.filter(id => id !== phoneId);
    
    if (this.data.phoneNumbersByUser[userDID].length === 0) {
      delete this.data.phoneNumbersByUser[userDID];
    }
    
    delete this.data.phoneNumbers[phoneId];
    await this.save();
  }

  // Email Address Operations
  async storeEmailAddress(userDID: string, emailAddress: EmailAddress): Promise<string> {
    await this.load();
    const emailId = emailAddress.id || `email:${uuidv4()}`;
    const emailWithId = { ...emailAddress, id: emailId };
    this.data.emailAddresses[emailId] = emailWithId;
    
    // Update user index
    if (!this.data.emailAddressesByUser[userDID]) {
      this.data.emailAddressesByUser[userDID] = [];
    }
    if (!this.data.emailAddressesByUser[userDID].includes(emailId)) {
      this.data.emailAddressesByUser[userDID].push(emailId);
    }
    
    await this.save();
    return emailId;
  }

  async getEmailAddress(userDID: string, emailId: string): Promise<EmailAddress | null> {
    await this.load();
    const userEmails = this.data.emailAddressesByUser[userDID] || [];
    if (!userEmails.includes(emailId)) {
      return null;
    }
    return this.data.emailAddresses[emailId] || null;
  }

  async listEmailAddresses(userDID: string): Promise<EmailAddress[]> {
    await this.load();
    const emailIds = this.data.emailAddressesByUser[userDID] || [];
    return emailIds
      .map(id => this.data.emailAddresses[id])
      .filter(email => email !== undefined);
  }

  async updateEmailAddress(userDID: string, emailId: string, emailAddress: Partial<EmailAddress>): Promise<void> {
    await this.load();
    const userEmails = this.data.emailAddressesByUser[userDID] || [];
    if (!userEmails.includes(emailId)) {
      throw new Error('Email address not found');
    }
    
    const existingEmail = this.data.emailAddresses[emailId];
    if (existingEmail) {
      this.data.emailAddresses[emailId] = { ...existingEmail, ...emailAddress, id: emailId };
      await this.save();
    }
  }

  async deleteEmailAddress(userDID: string, emailId: string): Promise<void> {
    await this.load();
    const userEmails = this.data.emailAddressesByUser[userDID] || [];
    this.data.emailAddressesByUser[userDID] = userEmails.filter(id => id !== emailId);
    
    if (this.data.emailAddressesByUser[userDID].length === 0) {
      delete this.data.emailAddressesByUser[userDID];
    }
    
    delete this.data.emailAddresses[emailId];
    await this.save();
  }

  // Address Operations
  async storeAddress(userDID: string, address: Address): Promise<string> {
    await this.load();
    const addressId = address.id || `address:${uuidv4()}`;
    const addressWithId = { ...address, id: addressId };
    this.data.addresses[addressId] = addressWithId;
    
    // Update user index
    if (!this.data.addressesByUser[userDID]) {
      this.data.addressesByUser[userDID] = [];
    }
    if (!this.data.addressesByUser[userDID].includes(addressId)) {
      this.data.addressesByUser[userDID].push(addressId);
    }
    
    await this.save();
    return addressId;
  }

  async getAddress(userDID: string, addressId: string): Promise<Address | null> {
    await this.load();
    const userAddresses = this.data.addressesByUser[userDID] || [];
    if (!userAddresses.includes(addressId)) {
      return null;
    }
    return this.data.addresses[addressId] || null;
  }

  async listAddresses(userDID: string): Promise<Address[]> {
    await this.load();
    const addressIds = this.data.addressesByUser[userDID] || [];
    return addressIds
      .map(id => this.data.addresses[id])
      .filter(address => address !== undefined);
  }

  async updateAddress(userDID: string, addressId: string, address: Partial<Address>): Promise<void> {
    await this.load();
    const userAddresses = this.data.addressesByUser[userDID] || [];
    if (!userAddresses.includes(addressId)) {
      throw new Error('Address not found');
    }
    
    const existingAddress = this.data.addresses[addressId];
    if (existingAddress) {
      this.data.addresses[addressId] = { ...existingAddress, ...address, id: addressId };
      await this.save();
    }
  }

  async deleteAddress(userDID: string, addressId: string): Promise<void> {
    await this.load();
    const userAddresses = this.data.addressesByUser[userDID] || [];
    this.data.addressesByUser[userDID] = userAddresses.filter(id => id !== addressId);
    
    if (this.data.addressesByUser[userDID].length === 0) {
      delete this.data.addressesByUser[userDID];
    }
    
    delete this.data.addresses[addressId];
    await this.save();
  }

  // General operations
  async clear(): Promise<void> {
    this.data = {
      dids: {},
      credentials: {},
      keyPairs: {},
      revocationLists: {},
      schemas: {},
      phoneNumbers: {},
      phoneNumbersByUser: {},
      emailAddresses: {},
      emailAddressesByUser: {},
      addresses: {},
      addressesByUser: {}
    };
    await this.save();
  }
}