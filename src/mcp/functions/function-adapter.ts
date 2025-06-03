/**
 * Function Adapter for MCP
 * 
 * Converts between different provider function calling formats
 */

import {
  FunctionDefinition,
  FunctionCall,
  FunctionResult,
  ParameterDefinition,
  MCPError,
  MCPErrorCode
} from '../types';

/**
 * OpenAI function format
 */
export interface OpenAIFunction {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}

export interface OpenAIFunctionCall {
  name: string;
  arguments: string; // JSON string
}

/**
 * Anthropic function format
 */
export interface AnthropicTool {
  name: string;
  description: string;
  input_schema: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}

export interface AnthropicToolUse {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, any>;
}

/**
 * Google function format
 */
export interface GoogleFunction {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}

/**
 * Provider types
 */
export type ProviderType = 'openai' | 'anthropic' | 'google' | 'generic';

/**
 * Function adapter configuration
 */
export interface FunctionAdapterConfig {
  strictValidation: boolean;
  preserveMetadata: boolean;
  sanitizeArguments: boolean;
  maxArgumentSize: number;
}

/**
 * Function Adapter
 */
export class FunctionAdapter {
  constructor(
    private config: FunctionAdapterConfig = {
      strictValidation: true,
      preserveMetadata: true,
      sanitizeArguments: true,
      maxArgumentSize: 10000 // 10KB
    }
  ) {}

  /**
   * Convert MCP function definition to provider format
   */
  toProviderFormat(
    definition: FunctionDefinition,
    providerType: ProviderType
  ): any {
    switch (providerType) {
      case 'openai':
        return this.toOpenAIFormat(definition);
      case 'anthropic':
        return this.toAnthropicFormat(definition);
      case 'google':
        return this.toGoogleFormat(definition);
      default:
        return definition;
    }
  }

  /**
   * Convert provider function call to MCP format
   */
  fromProviderCall(
    providerCall: any,
    providerType: ProviderType
  ): FunctionCall {
    switch (providerType) {
      case 'openai':
        return this.fromOpenAICall(providerCall);
      case 'anthropic':
        return this.fromAnthropicCall(providerCall);
      case 'google':
        return this.fromGoogleCall(providerCall);
      default:
        return providerCall;
    }
  }

  /**
   * Convert provider format to MCP function definition
   */
  fromProviderFormat(
    providerFunction: any,
    providerType: ProviderType
  ): FunctionDefinition {
    switch (providerType) {
      case 'openai':
        return this.fromOpenAIFormat(providerFunction);
      case 'anthropic':
        return this.fromAnthropicFormat(providerFunction);
      case 'google':
        return this.fromGoogleFormat(providerFunction);
      default:
        return providerFunction;
    }
  }

  /**
   * Batch convert function definitions
   */
  batchToProviderFormat(
    definitions: FunctionDefinition[],
    providerType: ProviderType
  ): any[] {
    return definitions.map(def => this.toProviderFormat(def, providerType));
  }

  /**
   * Convert to OpenAI format
   */
  private toOpenAIFormat(definition: FunctionDefinition): OpenAIFunction {
    const openaiFunction: OpenAIFunction = {
      name: definition.name,
      description: definition.description,
      parameters: {
        type: 'object',
        properties: this.convertParameters(definition.parameters.properties, 'openai'),
        required: definition.parameters.required
      }
    };

    // Validate against OpenAI constraints
    if (this.config.strictValidation) {
      this.validateOpenAIFunction(openaiFunction);
    }

    return openaiFunction;
  }

  /**
   * Convert from OpenAI format
   */
  private fromOpenAIFormat(openaiFunction: OpenAIFunction): FunctionDefinition {
    return {
      name: openaiFunction.name,
      description: openaiFunction.description,
      parameters: {
        type: 'object',
        properties: this.convertParameters(openaiFunction.parameters.properties, 'generic'),
        required: openaiFunction.parameters.required || []
      }
    };
  }

  /**
   * Convert from OpenAI function call
   */
  private fromOpenAICall(openaiCall: OpenAIFunctionCall): FunctionCall {
    let args: Record<string, any> = {};
    
    try {
      args = JSON.parse(openaiCall.arguments);
    } catch (error) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: `Invalid function arguments: ${(error as Error).message}`,
        timestamp: new Date(),
        retryable: false
      });
    }

    if (this.config.sanitizeArguments) {
      args = this.sanitizeArguments(args);
    }

    return {
      name: openaiCall.name,
      arguments: args,
      id: `openai-${Date.now()}`
    };
  }

  /**
   * Convert to Anthropic format
   */
  private toAnthropicFormat(definition: FunctionDefinition): AnthropicTool {
    return {
      name: definition.name,
      description: definition.description,
      input_schema: {
        type: 'object',
        properties: this.convertParameters(definition.parameters.properties, 'anthropic'),
        required: definition.parameters.required
      }
    };
  }

  /**
   * Convert from Anthropic format
   */
  private fromAnthropicFormat(anthropicTool: AnthropicTool): FunctionDefinition {
    return {
      name: anthropicTool.name,
      description: anthropicTool.description,
      parameters: {
        type: 'object',
        properties: this.convertParameters(anthropicTool.input_schema.properties, 'generic'),
        required: anthropicTool.input_schema.required || []
      }
    };
  }

  /**
   * Convert from Anthropic tool use
   */
  private fromAnthropicCall(anthropicCall: AnthropicToolUse): FunctionCall {
    let args = anthropicCall.input;

    if (this.config.sanitizeArguments) {
      args = this.sanitizeArguments(args);
    }

    return {
      name: anthropicCall.name,
      arguments: args,
      id: anthropicCall.id
    };
  }

  /**
   * Convert to Google format
   */
  private toGoogleFormat(definition: FunctionDefinition): GoogleFunction {
    return {
      name: definition.name,
      description: definition.description,
      parameters: {
        type: 'object',
        properties: this.convertParameters(definition.parameters.properties, 'google'),
        required: definition.parameters.required
      }
    };
  }

  /**
   * Convert from Google format
   */
  private fromGoogleFormat(googleFunction: GoogleFunction): FunctionDefinition {
    return {
      name: googleFunction.name,
      description: googleFunction.description,
      parameters: {
        type: 'object',
        properties: this.convertParameters(googleFunction.parameters.properties, 'generic'),
        required: googleFunction.parameters.required || []
      }
    };
  }

  /**
   * Convert from Google function call
   */
  private fromGoogleCall(googleCall: any): FunctionCall {
    let args = googleCall.args || googleCall.arguments || {};

    if (this.config.sanitizeArguments) {
      args = this.sanitizeArguments(args);
    }

    return {
      name: googleCall.name,
      arguments: args,
      id: googleCall.id || `google-${Date.now()}`
    };
  }

  /**
   * Convert parameter definitions between formats
   */
  private convertParameters(
    properties: Record<string, any>,
    targetFormat: ProviderType | 'generic'
  ): Record<string, any> {
    const converted: Record<string, any> = {};

    for (const [name, param] of Object.entries(properties)) {
      converted[name] = this.convertSingleParameter(param, targetFormat);
    }

    return converted;
  }

  /**
   * Convert single parameter definition
   */
  private convertSingleParameter(
    param: any,
    targetFormat: ProviderType | 'generic'
  ): ParameterDefinition {
    const baseParam: ParameterDefinition = {
      type: param.type,
      description: param.description || ''
    };

    // Add common properties
    if (param.enum) baseParam.enum = param.enum;
    if (param.default !== undefined) baseParam.default = param.default;

    // Type-specific properties
    switch (param.type) {
      case 'string':
        if (param.minLength !== undefined) baseParam.minLength = param.minLength;
        if (param.maxLength !== undefined) baseParam.maxLength = param.maxLength;
        if (param.pattern) baseParam.pattern = param.pattern;
        break;

      case 'number':
      case 'integer':
        if (param.minimum !== undefined) baseParam.minimum = param.minimum;
        if (param.maximum !== undefined) baseParam.maximum = param.maximum;
        if (param.multipleOf !== undefined) baseParam.multipleOf = param.multipleOf;
        break;

      case 'array':
        if (param.items) {
          baseParam.items = this.convertSingleParameter(param.items, targetFormat);
        }
        if (param.minItems !== undefined) baseParam.minItems = param.minItems;
        if (param.maxItems !== undefined) baseParam.maxItems = param.maxItems;
        break;

      case 'object':
        if (param.properties) {
          baseParam.properties = this.convertParameters(param.properties, targetFormat);
        }
        if (param.required) baseParam.required = param.required;
        if (param.additionalProperties !== undefined) {
          baseParam.additionalProperties = param.additionalProperties;
        }
        break;
    }

    // Provider-specific adjustments
    switch (targetFormat) {
      case 'openai':
        // OpenAI doesn't support some JSON Schema features
        delete baseParam.multipleOf;
        break;

      case 'anthropic':
        // Anthropic uses slightly different naming
        if (baseParam.enum) {
          baseParam.enum = baseParam.enum;
        }
        break;

      case 'google':
        // Google has its own constraints
        break;
    }

    return baseParam;
  }

  /**
   * Validate OpenAI function
   */
  private validateOpenAIFunction(func: OpenAIFunction): void {
    // Check name constraints
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(func.name)) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: 'OpenAI function names must be 1-64 characters, alphanumeric plus underscore and dash',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check description length
    if (func.description.length > 1024) {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: 'OpenAI function description must be <= 1024 characters',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Check parameters structure
    this.validateParametersStructure(func.parameters);
  }

  /**
   * Validate parameters structure
   */
  private validateParametersStructure(params: any): void {
    if (params.type !== 'object') {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: 'Function parameters must be of type "object"',
        timestamp: new Date(),
        retryable: false
      });
    }

    if (!params.properties || typeof params.properties !== 'object') {
      throw new MCPError({
        code: MCPErrorCode.INVALID_FUNCTION_CALL,
        message: 'Function parameters must have properties',
        timestamp: new Date(),
        retryable: false
      });
    }

    // Recursively validate nested objects
    for (const [name, prop] of Object.entries(params.properties)) {
      if (typeof prop === 'object' && prop !== null && 'type' in prop && prop.type === 'object' && 'properties' in prop && prop.properties) {
        this.validateParametersStructure(prop);
      }
    }
  }

  /**
   * Sanitize function arguments
   */
  private sanitizeArguments(args: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};

    for (const [key, value] of Object.entries(args)) {
      // Check key safety
      if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key)) {
        continue; // Skip unsafe keys
      }

      // Sanitize value
      sanitized[key] = this.sanitizeValue(value);
    }

    return sanitized;
  }

  /**
   * Sanitize individual value
   */
  private sanitizeValue(value: any): any {
    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'string') {
      // Limit string length
      if (value.length > this.config.maxArgumentSize) {
        return value.substring(0, this.config.maxArgumentSize);
      }
      return value;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }

    if (Array.isArray(value)) {
      return value.slice(0, 100).map(item => this.sanitizeValue(item)); // Limit array size
    }

    if (typeof value === 'object') {
      const sanitized: Record<string, any> = {};
      let keyCount = 0;
      for (const [key, val] of Object.entries(value)) {
        if (keyCount >= 100) break; // Limit object size
        if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key)) continue; // Skip unsafe keys
        sanitized[key] = this.sanitizeValue(val);
        keyCount++;
      }
      return sanitized;
    }

    return null; // Drop unknown types
  }

  /**
   * Get supported provider types
   */
  getSupportedProviders(): ProviderType[] {
    return ['openai', 'anthropic', 'google', 'generic'];
  }

  /**
   * Check if provider supports feature
   */
  supportsFeature(providerType: ProviderType, feature: string): boolean {
    const supportMatrix: Record<string, Record<string, boolean>> = {
      openai: {
        function_calling: true,
        streaming_functions: true,
        parallel_functions: true,
        nested_objects: true,
        arrays: true,
        enums: true
      },
      anthropic: {
        function_calling: true,
        streaming_functions: false,
        parallel_functions: false,
        nested_objects: true,
        arrays: true,
        enums: true
      },
      google: {
        function_calling: true,
        streaming_functions: true,
        parallel_functions: true,
        nested_objects: true,
        arrays: true,
        enums: true
      },
      generic: {
        function_calling: true,
        streaming_functions: true,
        parallel_functions: true,
        nested_objects: true,
        arrays: true,
        enums: true
      }
    };

    return supportMatrix[providerType]?.[feature] || false;
  }

  /**
   * Get provider constraints
   */
  getProviderConstraints(providerType: ProviderType): {
    maxFunctionNameLength: number;
    maxDescriptionLength: number;
    maxParameters: number;
    maxNestingDepth: number;
    supportedTypes: string[];
  } {
    const constraints = {
      openai: {
        maxFunctionNameLength: 64,
        maxDescriptionLength: 1024,
        maxParameters: 100,
        maxNestingDepth: 5,
        supportedTypes: ['string', 'number', 'integer', 'boolean', 'array', 'object']
      },
      anthropic: {
        maxFunctionNameLength: 64,
        maxDescriptionLength: 2048,
        maxParameters: 100,
        maxNestingDepth: 10,
        supportedTypes: ['string', 'number', 'integer', 'boolean', 'array', 'object']
      },
      google: {
        maxFunctionNameLength: 64,
        maxDescriptionLength: 1024,
        maxParameters: 50,
        maxNestingDepth: 5,
        supportedTypes: ['string', 'number', 'integer', 'boolean', 'array', 'object']
      },
      generic: {
        maxFunctionNameLength: 128,
        maxDescriptionLength: 4096,
        maxParameters: 200,
        maxNestingDepth: 20,
        supportedTypes: ['string', 'number', 'integer', 'boolean', 'array', 'object', 'null']
      }
    };

    return constraints[providerType] || constraints.generic;
  }
}

export default FunctionAdapter;