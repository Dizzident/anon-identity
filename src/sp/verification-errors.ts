export enum VerificationErrorCode {
  EXPIRED_CREDENTIAL = 'EXPIRED_CREDENTIAL',
  REVOKED_CREDENTIAL = 'REVOKED_CREDENTIAL',
  UNTRUSTED_ISSUER = 'UNTRUSTED_ISSUER',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  MISSING_REQUIRED_ATTRIBUTE = 'MISSING_REQUIRED_ATTRIBUTE',
  INVALID_DISCLOSURE_PROOF = 'INVALID_DISCLOSURE_PROOF',
  MISSING_PROOF = 'MISSING_PROOF',
  INVALID_PRESENTATION_SIGNATURE = 'INVALID_PRESENTATION_SIGNATURE',
  INVALID_CREDENTIAL_FORMAT = 'INVALID_CREDENTIAL_FORMAT',
  NETWORK_ERROR = 'NETWORK_ERROR',
  STORAGE_ERROR = 'STORAGE_ERROR',
  CREDENTIAL_SUSPENDED = 'CREDENTIAL_SUSPENDED'
}

export interface VerificationErrorDetails {
  credentialId?: string;
  issuer?: string;
  attribute?: string;
  expectedValue?: any;
  actualValue?: any;
  timestamp?: Date;
  [key: string]: any;
}

export class VerificationError extends Error {
  public readonly code: VerificationErrorCode;
  public readonly details: VerificationErrorDetails;

  constructor(
    code: VerificationErrorCode,
    message: string,
    details: VerificationErrorDetails = {}
  ) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
    this.details = details;
    
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, VerificationError);
    }
  }

  /**
   * Create a standardized error message
   */
  toString(): string {
    return `${this.name} [${this.code}]: ${this.message}`;
  }

  /**
   * Convert to JSON for API responses
   */
  toJSON(): Record<string, any> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      details: this.details
    };
  }

  /**
   * Factory methods for common errors
   */
  static expiredCredential(credentialId: string, issuer: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.EXPIRED_CREDENTIAL,
      `Credential ${credentialId} has expired`,
      { credentialId, issuer }
    );
  }

  static revokedCredential(credentialId: string, issuer: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.REVOKED_CREDENTIAL,
      `Credential ${credentialId} has been revoked`,
      { credentialId, issuer }
    );
  }

  static untrustedIssuer(issuer: string, credentialId: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.UNTRUSTED_ISSUER,
      `Credential from untrusted issuer: ${issuer}`,
      { issuer, credentialId }
    );
  }

  static invalidSignature(credentialId: string, reason?: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.INVALID_SIGNATURE,
      `Invalid signature for credential ${credentialId}${reason ? `: ${reason}` : ''}`,
      { credentialId, reason }
    );
  }

  static missingRequiredAttribute(attribute: string, credentialId?: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.MISSING_REQUIRED_ATTRIBUTE,
      `Missing required attribute: ${attribute}`,
      { attribute, credentialId }
    );
  }

  static invalidDisclosureProof(credentialId: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.INVALID_DISCLOSURE_PROOF,
      `Invalid selective disclosure proof for credential ${credentialId}`,
      { credentialId }
    );
  }

  static missingProof(type: 'presentation' | 'credential', id?: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.MISSING_PROOF,
      `${type} missing proof${id ? ` (${id})` : ''}`,
      { type, id }
    );
  }

  static invalidPresentationSignature(reason?: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.INVALID_PRESENTATION_SIGNATURE,
      `Invalid presentation signature${reason ? `: ${reason}` : ''}`,
      { reason }
    );
  }

  static invalidCredentialFormat(credentialId: string, reason?: string): VerificationError {
    return new VerificationError(
      VerificationErrorCode.INVALID_CREDENTIAL_FORMAT,
      `Invalid credential format${reason ? `: ${reason}` : ''}`,
      { credentialId, reason }
    );
  }

  static networkError(operation: string, error: Error): VerificationError {
    return new VerificationError(
      VerificationErrorCode.NETWORK_ERROR,
      `Network error during ${operation}: ${error.message}`,
      { operation, originalError: error.message }
    );
  }

  static storageError(operation: string, error: Error): VerificationError {
    return new VerificationError(
      VerificationErrorCode.STORAGE_ERROR,
      `Storage error during ${operation}: ${error.message}`,
      { operation, originalError: error.message }
    );
  }
}

/**
 * Helper to determine if an error is a VerificationError
 */
export function isVerificationError(error: unknown): error is VerificationError {
  return error instanceof VerificationError;
}

/**
 * Helper to get error code from any error
 */
export function getErrorCode(error: unknown): VerificationErrorCode | null {
  if (isVerificationError(error)) {
    return error.code;
  }
  return null;
}