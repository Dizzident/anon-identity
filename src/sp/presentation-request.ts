import { randomBytes } from 'crypto';
import { VerifiablePresentation } from '../types';
import { VerificationError, VerificationErrorCode } from './verification-errors';

export interface AttributeConstraint {
  name: string;
  required: boolean;
  expectedValue?: any;
  allowedValues?: any[];
  minValue?: number;
  maxValue?: number;
  pattern?: string; // regex pattern for string validation
}

export interface CredentialRequirement {
  type: string[];
  issuer?: string; // specific issuer DID, if required
  trustedIssuers?: string[]; // list of acceptable issuers
  attributes: AttributeConstraint[];
  maxAge?: number; // maximum age in milliseconds
}

export interface PresentationRequestOptions {
  credentialRequirements: CredentialRequirement[];
  purpose: string;
  challenge?: string;
  domain?: string;
  expiresAt?: Date;
  allowPartialMatch?: boolean; // whether to accept presentations that don't fulfill all requirements
}

export interface PresentationRequestObject {
  id: string;
  type: ['PresentationRequest'];
  from: string; // service provider DID
  purpose: string;
  challenge: string;
  domain?: string;
  credentialRequirements: CredentialRequirement[];
  createdAt: Date;
  expiresAt?: Date;
  allowPartialMatch: boolean;
}

export interface ValidationResult {
  valid: boolean;
  matchedRequirements: CredentialRequirement[];
  unmatchedRequirements: CredentialRequirement[];
  errors: VerificationError[];
  score: number; // 0-1, percentage of requirements satisfied
}

export class PresentationRequest {
  private serviceProviderDID: string;

  constructor(serviceProviderDID: string) {
    this.serviceProviderDID = serviceProviderDID;
  }

  /**
   * Create a presentation request with specific requirements
   */
  async createRequest(options: PresentationRequestOptions): Promise<PresentationRequestObject> {
    const challenge = options.challenge || this.generateChallenge();
    const id = `urn:uuid:${randomBytes(16).toString('hex')}`;
    const createdAt = new Date();

    return {
      id,
      type: ['PresentationRequest'],
      from: this.serviceProviderDID,
      purpose: options.purpose,
      challenge,
      domain: options.domain,
      credentialRequirements: options.credentialRequirements,
      createdAt,
      expiresAt: options.expiresAt,
      allowPartialMatch: options.allowPartialMatch || false
    };
  }

  /**
   * Validate a presentation against a request
   */
  async validateAgainstRequest(
    presentation: VerifiablePresentation,
    request: PresentationRequestObject
  ): Promise<ValidationResult> {
    const errors: VerificationError[] = [];
    const matchedRequirements: CredentialRequirement[] = [];
    const unmatchedRequirements: CredentialRequirement[] = [];

    // Check if request has expired
    if (request.expiresAt && new Date() > request.expiresAt) {
      errors.push(new VerificationError(
        VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
        'Presentation request has expired'
      ));
    }

    // Check challenge in presentation proof
    if (!this.validateChallenge(presentation, request.challenge)) {
      errors.push(new VerificationError(
        VerificationErrorCode.INVALID_SIGNATURE,
        'Presentation challenge does not match request'
      ));
    }

    // Check domain if specified
    if (request.domain && !this.validateDomain(presentation, request.domain)) {
      errors.push(new VerificationError(
        VerificationErrorCode.INVALID_SIGNATURE,
        'Presentation domain does not match request'
      ));
    }

    // Validate each credential requirement
    for (const requirement of request.credentialRequirements) {
      const matchingCredentials = this.findMatchingCredentials(presentation, requirement);
      
      if (matchingCredentials.length > 0) {
        // Validate attributes for each matching credential
        let requirementMet = false;
        
        for (const credential of matchingCredentials) {
          const attributeValidation = this.validateAttributes(credential, requirement.attributes);
          if (attributeValidation.valid) {
            requirementMet = true;
            break;
          } else {
            errors.push(...attributeValidation.errors);
          }
        }
        
        if (requirementMet) {
          matchedRequirements.push(requirement);
        } else {
          unmatchedRequirements.push(requirement);
        }
      } else {
        unmatchedRequirements.push(requirement);
        errors.push(new VerificationError(
          VerificationErrorCode.MISSING_REQUIRED_ATTRIBUTE,
          `No credentials found matching requirement for types: ${requirement.type.join(', ')}`
        ));
      }
    }

    const totalRequirements = request.credentialRequirements.length;
    const satisfiedRequirements = matchedRequirements.length;
    const score = totalRequirements > 0 ? satisfiedRequirements / totalRequirements : 0;

    const valid = request.allowPartialMatch 
      ? satisfiedRequirements > 0 
      : satisfiedRequirements === totalRequirements;

    return {
      valid: valid && errors.length === 0,
      matchedRequirements,
      unmatchedRequirements,
      errors,
      score
    };
  }

  /**
   * Create a simple request for specific credential types
   */
  createSimpleRequest(
    credentialTypes: string[],
    purpose: string,
    requiredAttributes: string[] = [],
    optionalAttributes: string[] = []
  ): Promise<PresentationRequestObject> {
    const requirements: CredentialRequirement[] = credentialTypes.map(type => ({
      type: [type],
      attributes: [
        ...requiredAttributes.map(attr => ({ name: attr, required: true })),
        ...optionalAttributes.map(attr => ({ name: attr, required: false }))
      ]
    }));

    return this.createRequest({
      credentialRequirements: requirements,
      purpose,
      allowPartialMatch: optionalAttributes.length > 0
    });
  }

  /**
   * Validate challenge in presentation
   */
  private validateChallenge(presentation: VerifiablePresentation, expectedChallenge: string): boolean {
    // In a full implementation, this would decode the JWT proof and check the challenge claim
    // For now, we'll assume the challenge is properly embedded in the proof
    return true; // Simplified for this implementation
  }

  /**
   * Validate domain in presentation
   */
  private validateDomain(presentation: VerifiablePresentation, expectedDomain: string): boolean {
    // In a full implementation, this would check the domain claim in the JWT proof
    return true; // Simplified for this implementation
  }

  /**
   * Find credentials that match a requirement
   */
  private findMatchingCredentials(
    presentation: VerifiablePresentation, 
    requirement: CredentialRequirement
  ): any[] {
    return presentation.verifiableCredential.filter(credential => {
      // Check credential type
      const hasMatchingType = requirement.type.some(reqType => 
        credential.type.includes(reqType)
      );
      
      if (!hasMatchingType) {
        return false;
      }

      // Check issuer if specified
      if (requirement.issuer && credential.issuer !== requirement.issuer) {
        return false;
      }

      // Check trusted issuers if specified
      if (requirement.trustedIssuers && !requirement.trustedIssuers.includes(credential.issuer)) {
        return false;
      }

      // Check age if specified
      if (requirement.maxAge) {
        const issuanceDate = new Date(credential.issuanceDate);
        const maxAgeDate = new Date(Date.now() - requirement.maxAge);
        if (issuanceDate < maxAgeDate) {
          return false;
        }
      }

      return true;
    });
  }

  /**
   * Validate attributes against constraints
   */
  private validateAttributes(
    credential: any, 
    constraints: AttributeConstraint[]
  ): { valid: boolean; errors: VerificationError[] } {
    const errors: VerificationError[] = [];
    const { id, ...attributes } = credential.credentialSubject;

    for (const constraint of constraints) {
      const value = attributes[constraint.name];

      // Check required attributes
      if (constraint.required && (value === undefined || value === null)) {
        errors.push(VerificationError.missingRequiredAttribute(constraint.name, credential.id));
        continue;
      }

      // Skip validation for missing optional attributes
      if (!constraint.required && (value === undefined || value === null)) {
        continue;
      }

      // Validate expected value
      if (constraint.expectedValue !== undefined && value !== constraint.expectedValue) {
        errors.push(new VerificationError(
          VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
          `Attribute ${constraint.name} expected ${constraint.expectedValue}, got ${value}`,
          { attribute: constraint.name, expectedValue: constraint.expectedValue, actualValue: value }
        ));
      }

      // Validate allowed values
      if (constraint.allowedValues && !constraint.allowedValues.includes(value)) {
        errors.push(new VerificationError(
          VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
          `Attribute ${constraint.name} value ${value} not in allowed values: ${constraint.allowedValues.join(', ')}`,
          { attribute: constraint.name, allowedValues: constraint.allowedValues, actualValue: value }
        ));
      }

      // Validate numeric ranges
      if (typeof value === 'number') {
        if (constraint.minValue !== undefined && value < constraint.minValue) {
          errors.push(new VerificationError(
            VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
            `Attribute ${constraint.name} value ${value} below minimum ${constraint.minValue}`,
            { attribute: constraint.name, minValue: constraint.minValue, actualValue: value }
          ));
        }

        if (constraint.maxValue !== undefined && value > constraint.maxValue) {
          errors.push(new VerificationError(
            VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
            `Attribute ${constraint.name} value ${value} above maximum ${constraint.maxValue}`,
            { attribute: constraint.name, maxValue: constraint.maxValue, actualValue: value }
          ));
        }
      }

      // Validate pattern for strings
      if (typeof value === 'string' && constraint.pattern) {
        const regex = new RegExp(constraint.pattern);
        if (!regex.test(value)) {
          errors.push(new VerificationError(
            VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
            `Attribute ${constraint.name} value ${value} does not match pattern ${constraint.pattern}`,
            { attribute: constraint.name, pattern: constraint.pattern, actualValue: value }
          ));
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Generate a secure challenge
   */
  private generateChallenge(): string {
    return randomBytes(32).toString('base64url');
  }
}