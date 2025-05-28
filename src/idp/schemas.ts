import { AttributeSchema } from '../types';

export const BASIC_PROFILE_SCHEMA: AttributeSchema[] = [
  {
    name: 'givenName',
    type: 'string',
    required: true
  },
  {
    name: 'dateOfBirth',
    type: 'date',
    required: true
  },
  {
    name: 'isOver18',
    type: 'boolean',
    required: false
  }
];

export const CONTACT_INFO_SCHEMA: AttributeSchema[] = [
  {
    name: 'phoneNumbers',
    type: 'object',
    required: false
  },
  {
    name: 'emailAddresses',
    type: 'object',
    required: false
  },
  {
    name: 'addresses',
    type: 'object',
    required: false
  }
];

export const CREDENTIAL_CONTEXTS = {
  W3C_VC: 'https://www.w3.org/2018/credentials/v1',
  BASIC_PROFILE: 'https://example.com/schemas/BasicProfile',
  CONTACT_INFO: 'https://example.com/schemas/ContactInfo',
  ED25519_2020: 'https://w3id.org/security/suites/ed25519-2020/v1'
};

export const CREDENTIAL_TYPES = {
  VERIFIABLE_CREDENTIAL: 'VerifiableCredential',
  BASIC_PROFILE: 'BasicProfileCredential',
  CONTACT_INFO: 'ContactInfoCredential'
};

export function validateAttributes(
  attributes: Record<string, any>, 
  schema: AttributeSchema[]
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  for (const field of schema) {
    const value = attributes[field.name];
    
    if (field.required && (value === undefined || value === null)) {
      errors.push(`Missing required field: ${field.name}`);
      continue;
    }
    
    if (value !== undefined && value !== null) {
      switch (field.type) {
        case 'string':
          if (typeof value !== 'string') {
            errors.push(`Field ${field.name} must be a string`);
          }
          break;
        case 'date':
          if (typeof value !== 'string' || isNaN(Date.parse(value))) {
            errors.push(`Field ${field.name} must be a valid date string`);
          }
          break;
        case 'boolean':
          if (typeof value !== 'boolean') {
            errors.push(`Field ${field.name} must be a boolean`);
          }
          break;
        case 'number':
          if (typeof value !== 'number' || isNaN(value)) {
            errors.push(`Field ${field.name} must be a number`);
          }
          break;
        case 'object':
          if (typeof value !== 'object' || value === null) {
            errors.push(`Field ${field.name} must be an object`);
          }
          break;
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}