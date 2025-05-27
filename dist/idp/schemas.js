"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CREDENTIAL_TYPES = exports.CREDENTIAL_CONTEXTS = exports.BASIC_PROFILE_SCHEMA = void 0;
exports.validateAttributes = validateAttributes;
exports.BASIC_PROFILE_SCHEMA = [
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
exports.CREDENTIAL_CONTEXTS = {
    W3C_VC: 'https://www.w3.org/2018/credentials/v1',
    BASIC_PROFILE: 'https://example.com/schemas/BasicProfile',
    ED25519_2020: 'https://w3id.org/security/suites/ed25519-2020/v1'
};
exports.CREDENTIAL_TYPES = {
    VERIFIABLE_CREDENTIAL: 'VerifiableCredential',
    BASIC_PROFILE: 'BasicProfileCredential'
};
function validateAttributes(attributes, schema) {
    const errors = [];
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
            }
        }
    }
    return {
        valid: errors.length === 0,
        errors
    };
}
//# sourceMappingURL=schemas.js.map