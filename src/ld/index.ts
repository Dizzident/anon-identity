// JSON-LD processing
export { JsonLdProcessor, defaultJsonLdProcessor, JsonLdProcessorOptions } from './jsonld-processor';
export { ContextLoader, defaultContextLoader, ContextLoaderOptions, ContextDocument } from './context-loader';

// Signature suites
export { 
  SignatureSuite, 
  SignatureSuiteRegistry,
  SignatureSuiteOptions,
  SigningOptions,
  VerificationOptions,
  SelectiveDisclosureOptions,
  KeyType
} from './signature-suites/signature-suite';
export { Ed25519Signature2020Suite } from './signature-suites/ed25519-signature-2020';
export { BbsBlsSignature2020Suite } from './signature-suites/bbs-bls-signature-2020';