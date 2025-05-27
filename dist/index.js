"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileStorageProvider = exports.MemoryStorageProvider = exports.StorageFactory = exports.validateAttributes = exports.CREDENTIAL_TYPES = exports.CREDENTIAL_CONTEXTS = exports.BASIC_PROFILE_SCHEMA = exports.MockRevocationRegistry = exports.RevocationService = exports.SelectiveDisclosure = exports.ServiceProvider = exports.UserWallet = exports.IdentityProvider = exports.SecureStorage = exports.DIDService = exports.CryptoService = void 0;
var crypto_1 = require("./core/crypto");
Object.defineProperty(exports, "CryptoService", { enumerable: true, get: function () { return crypto_1.CryptoService; } });
var did_1 = require("./core/did");
Object.defineProperty(exports, "DIDService", { enumerable: true, get: function () { return did_1.DIDService; } });
var storage_1 = require("./core/storage");
Object.defineProperty(exports, "SecureStorage", { enumerable: true, get: function () { return storage_1.SecureStorage; } });
var identity_provider_1 = require("./idp/identity-provider");
Object.defineProperty(exports, "IdentityProvider", { enumerable: true, get: function () { return identity_provider_1.IdentityProvider; } });
var user_wallet_1 = require("./wallet/user-wallet");
Object.defineProperty(exports, "UserWallet", { enumerable: true, get: function () { return user_wallet_1.UserWallet; } });
var service_provider_1 = require("./sp/service-provider");
Object.defineProperty(exports, "ServiceProvider", { enumerable: true, get: function () { return service_provider_1.ServiceProvider; } });
var selective_disclosure_1 = require("./zkp/selective-disclosure");
Object.defineProperty(exports, "SelectiveDisclosure", { enumerable: true, get: function () { return selective_disclosure_1.SelectiveDisclosure; } });
var revocation_service_1 = require("./revocation/revocation-service");
Object.defineProperty(exports, "RevocationService", { enumerable: true, get: function () { return revocation_service_1.RevocationService; } });
Object.defineProperty(exports, "MockRevocationRegistry", { enumerable: true, get: function () { return revocation_service_1.MockRevocationRegistry; } });
__exportStar(require("./types"), exports);
var schemas_1 = require("./idp/schemas");
Object.defineProperty(exports, "BASIC_PROFILE_SCHEMA", { enumerable: true, get: function () { return schemas_1.BASIC_PROFILE_SCHEMA; } });
Object.defineProperty(exports, "CREDENTIAL_CONTEXTS", { enumerable: true, get: function () { return schemas_1.CREDENTIAL_CONTEXTS; } });
Object.defineProperty(exports, "CREDENTIAL_TYPES", { enumerable: true, get: function () { return schemas_1.CREDENTIAL_TYPES; } });
Object.defineProperty(exports, "validateAttributes", { enumerable: true, get: function () { return schemas_1.validateAttributes; } });
// Storage exports
var storage_2 = require("./storage");
Object.defineProperty(exports, "StorageFactory", { enumerable: true, get: function () { return storage_2.StorageFactory; } });
Object.defineProperty(exports, "MemoryStorageProvider", { enumerable: true, get: function () { return storage_2.MemoryStorageProvider; } });
Object.defineProperty(exports, "FileStorageProvider", { enumerable: true, get: function () { return storage_2.FileStorageProvider; } });
//# sourceMappingURL=index.js.map