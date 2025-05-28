import { PhoneNumber, Address } from '../../types';

/**
 * Base mixin for storage providers that don't implement phone/address storage
 */
export class StorageProviderBase {
  // Phone Number Operations (not implemented)
  async storePhoneNumber(userDID: string, phoneNumber: PhoneNumber): Promise<string> {
    throw new Error(`Phone number storage not implemented for ${this.constructor.name}`);
  }

  async getPhoneNumber(userDID: string, phoneId: string): Promise<PhoneNumber | null> {
    throw new Error(`Phone number storage not implemented for ${this.constructor.name}`);
  }

  async listPhoneNumbers(userDID: string): Promise<PhoneNumber[]> {
    throw new Error(`Phone number storage not implemented for ${this.constructor.name}`);
  }

  async updatePhoneNumber(userDID: string, phoneId: string, phoneNumber: Partial<PhoneNumber>): Promise<void> {
    throw new Error(`Phone number storage not implemented for ${this.constructor.name}`);
  }

  async deletePhoneNumber(userDID: string, phoneId: string): Promise<void> {
    throw new Error(`Phone number storage not implemented for ${this.constructor.name}`);
  }

  // Address Operations (not implemented)
  async storeAddress(userDID: string, address: Address): Promise<string> {
    throw new Error(`Address storage not implemented for ${this.constructor.name}`);
  }

  async getAddress(userDID: string, addressId: string): Promise<Address | null> {
    throw new Error(`Address storage not implemented for ${this.constructor.name}`);
  }

  async listAddresses(userDID: string): Promise<Address[]> {
    throw new Error(`Address storage not implemented for ${this.constructor.name}`);
  }

  async updateAddress(userDID: string, addressId: string, address: Partial<Address>): Promise<void> {
    throw new Error(`Address storage not implemented for ${this.constructor.name}`);
  }

  async deleteAddress(userDID: string, addressId: string): Promise<void> {
    throw new Error(`Address storage not implemented for ${this.constructor.name}`);
  }
}