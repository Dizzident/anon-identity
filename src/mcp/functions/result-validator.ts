/**
 * Result Validator for MCP Functions
 * 
 * Validates and sanitizes function execution results
 */

import {
  MCPError,
  MCPErrorCode
} from '../types';

/**
 * Validation rule types
 */
export type ValidationRuleType = 
  | 'type' 
  | 'format' 
  | 'length' 
  | 'range' 
  | 'pattern' 
  | 'whitelist' 
  | 'blacklist' 
  | 'custom';

/**
 * Validation rule
 */
export interface ValidationRule {
  type: ValidationRuleType;
  constraint: any;
  message?: string;
  severity: 'error' | 'warning' | 'info';
}

/**
 * Validation schema
 */
export interface ValidationSchema {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'null' | 'any';
  rules: ValidationRule[];
  properties?: Record<string, ValidationSchema>;
  items?: ValidationSchema;
  required?: string[];
  optional?: string[];
  additionalProperties?: boolean;
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  sanitizedValue?: any;
  metadata: {
    validatedAt: Date;
    validationTime: number;
    rulesApplied: number;
    transformationsApplied: string[];
  };
}

/**
 * Validation error
 */
export interface ValidationError {
  path: string;
  rule: ValidationRuleType;
  message: string;
  actualValue: any;
  expectedConstraint: any;
}

/**
 * Validation warning
 */
export interface ValidationWarning {
  path: string;
  rule: ValidationRuleType;
  message: string;
  suggestion?: string;
}

/**
 * Sanitization options
 */
export interface SanitizationOptions {
  removeUnknownProperties: boolean;
  truncateStrings: boolean;
  maxStringLength: number;
  maxArrayLength: number;
  maxObjectDepth: number;
  convertTypes: boolean;
  removeNullValues: boolean;
  escapeSqlInjection: boolean;
  escapeXssVectors: boolean;
  removeScriptTags: boolean;
}

/**
 * Built-in validation patterns
 */
export const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  URL: /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  PHONE: /^\+?[\d\s\-\(\)]{7,}$/,
  IP_ADDRESS: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  DATE_ISO: /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2}))?$/,
  ALPHANUMERIC: /^[a-zA-Z0-9]+$/,
  NO_SQL_INJECTION: /^(?!.*(?:'|"|;|--|\*|\/\*|\*\/|xp_|sp_|union|select|insert|update|delete|drop|create|alter|exec|execute)).+$/i,
  NO_XSS: /^(?!.*(?:<script|javascript:|onclick|onload|onerror|onmouseover)).+$/i
};

/**
 * Result Validator
 */
export class ResultValidator {
  private schemas: Map<string, ValidationSchema> = new Map();
  private customRules: Map<string, (value: any) => boolean> = new Map();

  constructor(
    private defaultSanitizationOptions: SanitizationOptions = {
      removeUnknownProperties: true,
      truncateStrings: true,
      maxStringLength: 10000,
      maxArrayLength: 1000,
      maxObjectDepth: 10,
      convertTypes: false,
      removeNullValues: false,
      escapeSqlInjection: true,
      escapeXssVectors: true,
      removeScriptTags: true
    }
  ) {
    this.initializeBuiltinSchemas();
  }

  /**
   * Register validation schema for a function
   */
  registerSchema(functionName: string, schema: ValidationSchema): void {
    this.schemas.set(functionName, schema);
  }

  /**
   * Register custom validation rule
   */
  registerCustomRule(ruleName: string, validator: (value: any) => boolean): void {
    this.customRules.set(ruleName, validator);
  }

  /**
   * Validate function result
   */
  async validateResult(
    functionName: string,
    result: any,
    options?: Partial<SanitizationOptions>
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const schema = this.schemas.get(functionName);
    
    if (!schema) {
      // No schema defined, perform basic sanitization only
      return this.basicValidation(result, options);
    }

    const sanitizationOptions = { ...this.defaultSanitizationOptions, ...options };
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const transformations: string[] = [];
    let rulesApplied = 0;

    try {
      const sanitizedValue = await this.validateValue(
        result,
        schema,
        '',
        errors,
        warnings,
        transformations,
        sanitizationOptions,
        0
      );

      rulesApplied = this.countRules(schema);

      return {
        valid: errors.length === 0,
        errors,
        warnings,
        sanitizedValue: errors.length === 0 ? sanitizedValue : undefined,
        metadata: {
          validatedAt: new Date(),
          validationTime: Date.now() - startTime,
          rulesApplied,
          transformationsApplied: transformations
        }
      };

    } catch (error) {
      throw new MCPError({
        code: MCPErrorCode.FUNCTION_ERROR,
        message: `Validation failed: ${(error as Error).message}`,
        timestamp: new Date(),
        retryable: false
      });
    }
  }

  /**
   * Validate value against schema
   */
  private async validateValue(
    value: any,
    schema: ValidationSchema,
    path: string,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    transformations: string[],
    options: SanitizationOptions,
    depth: number
  ): Promise<any> {
    // Check maximum depth
    if (depth > options.maxObjectDepth) {
      errors.push({
        path,
        rule: 'custom',
        message: `Maximum object depth exceeded: ${depth} > ${options.maxObjectDepth}`,
        actualValue: value,
        expectedConstraint: options.maxObjectDepth
      });
      return value;
    }

    // Type validation and conversion
    let sanitizedValue = value;
    
    if (schema.type !== 'any') {
      const typeResult = this.validateType(value, schema.type, path);
      if (!typeResult.valid) {
        if (options.convertTypes) {
          const converted = this.attemptTypeConversion(value, schema.type);
          if (converted.success) {
            sanitizedValue = converted.value;
            transformations.push(`${path}: converted ${typeof value} to ${schema.type}`);
          } else {
            errors.push({
              path,
              rule: 'type',
              message: typeResult.message,
              actualValue: value,
              expectedConstraint: schema.type
            });
            return value;
          }
        } else {
          errors.push({
            path,
            rule: 'type',
            message: typeResult.message,
            actualValue: value,
            expectedConstraint: schema.type
          });
          return value;
        }
      }
    }

    // Apply validation rules
    for (const rule of schema.rules) {
      const ruleResult = await this.applyValidationRule(sanitizedValue, rule, path);
      
      if (ruleResult.transformed) {
        sanitizedValue = ruleResult.value;
        transformations.push(`${path}: ${rule.type} rule applied`);
      }

      if (!ruleResult.valid) {
        if (rule.severity === 'error') {
          errors.push({
            path,
            rule: rule.type,
            message: rule.message || ruleResult.message || 'Validation failed',
            actualValue: value,
            expectedConstraint: rule.constraint
          });
        } else if (rule.severity === 'warning') {
          warnings.push({
            path,
            rule: rule.type,
            message: rule.message || ruleResult.message || 'Validation warning',
            suggestion: ruleResult.suggestion
          });
        }
      }
    }

    // Type-specific validation
    switch (schema.type) {
      case 'string':
        sanitizedValue = this.validateString(sanitizedValue, path, errors, warnings, transformations, options);
        break;
      case 'array':
        sanitizedValue = await this.validateArray(sanitizedValue, schema, path, errors, warnings, transformations, options, depth);
        break;
      case 'object':
        sanitizedValue = await this.validateObject(sanitizedValue, schema, path, errors, warnings, transformations, options, depth);
        break;
    }

    return sanitizedValue;
  }

  /**
   * Validate type
   */
  private validateType(value: any, expectedType: string, path: string): { valid: boolean; message: string } {
    const actualType = Array.isArray(value) ? 'array' : 
                      value === null ? 'null' : 
                      typeof value;

    if (actualType === expectedType) {
      return { valid: true, message: '' };
    }

    return {
      valid: false,
      message: `Expected ${expectedType}, got ${actualType} at ${path}`
    };
  }

  /**
   * Attempt type conversion
   */
  private attemptTypeConversion(value: any, targetType: string): { success: boolean; value: any } {
    try {
      switch (targetType) {
        case 'string':
          return { success: true, value: String(value) };
        case 'number':
          const num = Number(value);
          return { success: !isNaN(num), value: num };
        case 'boolean':
          if (typeof value === 'string') {
            const lower = value.toLowerCase();
            if (lower === 'true' || lower === '1') return { success: true, value: true };
            if (lower === 'false' || lower === '0') return { success: true, value: false };
          }
          return { success: true, value: Boolean(value) };
        case 'array':
          return Array.isArray(value) ? 
            { success: true, value } : 
            { success: false, value };
        default:
          return { success: false, value };
      }
    } catch {
      return { success: false, value };
    }
  }

  /**
   * Apply validation rule
   */
  private async applyValidationRule(
    value: any,
    rule: ValidationRule,
    path: string
  ): Promise<{ valid: boolean; value: any; transformed: boolean; message?: string; suggestion?: string }> {
    switch (rule.type) {
      case 'length':
        return this.applyLengthRule(value, rule.constraint, path);
      case 'range':
        return this.applyRangeRule(value, rule.constraint, path);
      case 'pattern':
        return this.applyPatternRule(value, rule.constraint, path);
      case 'whitelist':
        return this.applyWhitelistRule(value, rule.constraint, path);
      case 'blacklist':
        return this.applyBlacklistRule(value, rule.constraint, path);
      case 'format':
        return this.applyFormatRule(value, rule.constraint, path);
      case 'custom':
        return this.applyCustomRule(value, rule.constraint, path);
      default:
        return { valid: true, value, transformed: false };
    }
  }

  /**
   * Apply length rule
   */
  private applyLengthRule(
    value: any,
    constraint: { min?: number; max?: number },
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    const length = typeof value === 'string' ? value.length : 
                   Array.isArray(value) ? value.length :
                   typeof value === 'object' ? Object.keys(value).length : 0;

    let valid = true;
    let message = '';
    let transformedValue = value;
    let transformed = false;

    if (constraint.min !== undefined && length < constraint.min) {
      valid = false;
      message = `Length ${length} is less than minimum ${constraint.min} at ${path}`;
    }

    if (constraint.max !== undefined && length > constraint.max) {
      if (typeof value === 'string') {
        transformedValue = value.substring(0, constraint.max);
        transformed = true;
      } else if (Array.isArray(value)) {
        transformedValue = value.slice(0, constraint.max);
        transformed = true;
      } else {
        valid = false;
        message = `Length ${length} exceeds maximum ${constraint.max} at ${path}`;
      }
    }

    return { valid: valid || transformed, value: transformedValue, transformed, message };
  }

  /**
   * Apply range rule
   */
  private applyRangeRule(
    value: any,
    constraint: { min?: number; max?: number },
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    if (typeof value !== 'number') {
      return { valid: false, value, transformed: false, message: `Range rule applied to non-number at ${path}` };
    }

    let valid = true;
    let message = '';
    let transformedValue = value;
    let transformed = false;

    if (constraint.min !== undefined && value < constraint.min) {
      transformedValue = constraint.min;
      transformed = true;
    }

    if (constraint.max !== undefined && value > constraint.max) {
      transformedValue = constraint.max;
      transformed = true;
    }

    return { valid, value: transformedValue, transformed, message };
  }

  /**
   * Apply pattern rule
   */
  private applyPatternRule(
    value: any,
    pattern: string | RegExp,
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    if (typeof value !== 'string') {
      return { valid: false, value, transformed: false, message: `Pattern rule applied to non-string at ${path}` };
    }

    const regex = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
    const valid = regex.test(value);

    return {
      valid,
      value,
      transformed: false,
      message: valid ? undefined : `Value does not match pattern ${pattern} at ${path}`
    };
  }

  /**
   * Apply whitelist rule
   */
  private applyWhitelistRule(
    value: any,
    allowedValues: any[],
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    const valid = allowedValues.includes(value);
    return {
      valid,
      value,
      transformed: false,
      message: valid ? undefined : `Value not in whitelist at ${path}`
    };
  }

  /**
   * Apply blacklist rule
   */
  private applyBlacklistRule(
    value: any,
    forbiddenValues: any[],
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    const valid = !forbiddenValues.includes(value);
    return {
      valid,
      value,
      transformed: false,
      message: valid ? undefined : `Value in blacklist at ${path}`
    };
  }

  /**
   * Apply format rule
   */
  private applyFormatRule(
    value: any,
    format: string,
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    if (typeof value !== 'string') {
      return { valid: false, value, transformed: false, message: `Format rule applied to non-string at ${path}` };
    }

    const pattern = VALIDATION_PATTERNS[format as keyof typeof VALIDATION_PATTERNS];
    if (!pattern) {
      return { valid: false, value, transformed: false, message: `Unknown format: ${format}` };
    }

    const valid = pattern.test(value);
    return {
      valid,
      value,
      transformed: false,
      message: valid ? undefined : `Value does not match format ${format} at ${path}`
    };
  }

  /**
   * Apply custom rule
   */
  private applyCustomRule(
    value: any,
    ruleName: string,
    path: string
  ): { valid: boolean; value: any; transformed: boolean; message?: string } {
    const customValidator = this.customRules.get(ruleName);
    if (!customValidator) {
      return { valid: false, value, transformed: false, message: `Unknown custom rule: ${ruleName}` };
    }

    const valid = customValidator(value);
    return {
      valid,
      value,
      transformed: false,
      message: valid ? undefined : `Custom rule ${ruleName} failed at ${path}`
    };
  }

  /**
   * Validate string
   */
  private validateString(
    value: string,
    path: string,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    transformations: string[],
    options: SanitizationOptions
  ): string {
    let sanitized = value;

    // Truncate if too long
    if (options.truncateStrings && sanitized.length > options.maxStringLength) {
      sanitized = sanitized.substring(0, options.maxStringLength);
      transformations.push(`${path}: truncated to ${options.maxStringLength} characters`);
    }

    // Remove script tags
    if (options.removeScriptTags) {
      const original = sanitized;
      sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
      if (original !== sanitized) {
        transformations.push(`${path}: removed script tags`);
      }
    }

    // Escape XSS vectors
    if (options.escapeXssVectors) {
      const original = sanitized;
      sanitized = sanitized
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
      if (original !== sanitized) {
        transformations.push(`${path}: escaped XSS vectors`);
      }
    }

    // Check for SQL injection patterns
    if (options.escapeSqlInjection && !VALIDATION_PATTERNS.NO_SQL_INJECTION.test(sanitized)) {
      warnings.push({
        path,
        rule: 'pattern',
        message: 'Potential SQL injection pattern detected',
        suggestion: 'Consider using parameterized queries'
      });
    }

    return sanitized;
  }

  /**
   * Validate array
   */
  private async validateArray(
    value: any[],
    schema: ValidationSchema,
    path: string,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    transformations: string[],
    options: SanitizationOptions,
    depth: number
  ): Promise<any[]> {
    let sanitized = [...value];

    // Truncate if too long
    if (sanitized.length > options.maxArrayLength) {
      sanitized = sanitized.slice(0, options.maxArrayLength);
      transformations.push(`${path}: truncated to ${options.maxArrayLength} items`);
    }

    // Validate items
    if (schema.items) {
      const validatedItems = [];
      for (let i = 0; i < sanitized.length; i++) {
        const itemPath = `${path}[${i}]`;
        const validatedItem = await this.validateValue(
          sanitized[i],
          schema.items,
          itemPath,
          errors,
          warnings,
          transformations,
          options,
          depth + 1
        );
        validatedItems.push(validatedItem);
      }
      sanitized = validatedItems;
    }

    return sanitized;
  }

  /**
   * Validate object
   */
  private async validateObject(
    value: Record<string, any>,
    schema: ValidationSchema,
    path: string,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    transformations: string[],
    options: SanitizationOptions,
    depth: number
  ): Promise<Record<string, any>> {
    let sanitized = { ...value };

    // Check required properties
    if (schema.required) {
      for (const requiredProp of schema.required) {
        if (!(requiredProp in sanitized)) {
          errors.push({
            path: `${path}.${requiredProp}`,
            rule: 'type',
            message: `Missing required property: ${requiredProp}`,
            actualValue: undefined,
            expectedConstraint: 'required'
          });
        }
      }
    }

    // Remove unknown properties if configured
    if (options.removeUnknownProperties && schema.properties && !schema.additionalProperties) {
      const knownProps = new Set([
        ...Object.keys(schema.properties),
        ...(schema.optional || [])
      ]);
      
      for (const prop of Object.keys(sanitized)) {
        if (!knownProps.has(prop)) {
          delete sanitized[prop];
          transformations.push(`${path}.${prop}: removed unknown property`);
        }
      }
    }

    // Validate known properties
    if (schema.properties) {
      for (const [prop, propSchema] of Object.entries(schema.properties)) {
        if (prop in sanitized) {
          const propPath = `${path}.${prop}`;
          sanitized[prop] = await this.validateValue(
            sanitized[prop],
            propSchema,
            propPath,
            errors,
            warnings,
            transformations,
            options,
            depth + 1
          );
        }
      }
    }

    // Remove null values if configured
    if (options.removeNullValues) {
      for (const [prop, propValue] of Object.entries(sanitized)) {
        if (propValue === null) {
          delete sanitized[prop];
          transformations.push(`${path}.${prop}: removed null value`);
        }
      }
    }

    return sanitized;
  }

  /**
   * Basic validation for functions without schemas
   */
  private async basicValidation(
    result: any,
    options?: Partial<SanitizationOptions>
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const sanitizationOptions = { ...this.defaultSanitizationOptions, ...options };
    const transformations: string[] = [];
    
    let sanitizedValue = result;

    // Basic sanitization
    if (typeof result === 'string') {
      sanitizedValue = this.validateString(result, 'result', [], [], transformations, sanitizationOptions);
    }

    return {
      valid: true,
      errors: [],
      warnings: [],
      sanitizedValue,
      metadata: {
        validatedAt: new Date(),
        validationTime: Date.now() - startTime,
        rulesApplied: 0,
        transformationsApplied: transformations
      }
    };
  }

  /**
   * Count rules in schema
   */
  private countRules(schema: ValidationSchema): number {
    let count = schema.rules.length;
    
    if (schema.properties) {
      for (const propSchema of Object.values(schema.properties)) {
        count += this.countRules(propSchema);
      }
    }
    
    if (schema.items) {
      count += this.countRules(schema.items);
    }
    
    return count;
  }

  /**
   * Initialize built-in schemas
   */
  private initializeBuiltinSchemas(): void {
    // Common data validation schemas
    this.registerSchema('validate_email', {
      type: 'string',
      rules: [
        { type: 'format', constraint: 'EMAIL', severity: 'error' }
      ]
    });

    this.registerSchema('validate_url', {
      type: 'string',
      rules: [
        { type: 'format', constraint: 'URL', severity: 'error' }
      ]
    });

    this.registerSchema('safe_text', {
      type: 'string',
      rules: [
        { type: 'pattern', constraint: VALIDATION_PATTERNS.NO_XSS, severity: 'error' },
        { type: 'pattern', constraint: VALIDATION_PATTERNS.NO_SQL_INJECTION, severity: 'warning' },
        { type: 'length', constraint: { max: 1000 }, severity: 'warning' }
      ]
    });
  }

  /**
   * Get registered schemas
   */
  getRegisteredSchemas(): string[] {
    return Array.from(this.schemas.keys());
  }

  /**
   * Remove schema
   */
  removeSchema(functionName: string): boolean {
    return this.schemas.delete(functionName);
  }
}

export default ResultValidator;