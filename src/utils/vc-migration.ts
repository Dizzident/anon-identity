import { VerifiableCredential, VerifiablePresentation } from '../types';
import { 
  VerifiableCredentialV2, 
  VerifiablePresentationV2,
  VC_V2_CONTEXTS,
  isVerifiableCredentialV2
} from '../types/vc2';

/**
 * Migrates a W3C VC 1.1 credential to VC 2.0 format
 * @param vc11 The VC 1.1 credential
 * @returns The migrated VC 2.0 credential
 */
export function migrateCredentialToV2(vc11: VerifiableCredential): VerifiableCredentialV2 {
  // If already V2, return as-is
  if (isVerifiableCredentialV2(vc11)) {
    return vc11 as any as VerifiableCredentialV2;
  }
  
  const credential = vc11 as VerifiableCredential;

  // Create a new context array with V2 context
  const contexts = Array.isArray(credential["@context"]) 
    ? [...credential["@context"]]
    : [credential["@context"]];
  
  // Replace V1 context with V2
  const v2Contexts = contexts.map(ctx => 
    ctx === VC_V2_CONTEXTS.CREDENTIALS_V1 
      ? VC_V2_CONTEXTS.CREDENTIALS_V2 
      : ctx
  );
  
  // If no V2 context found, add it
  if (!v2Contexts.includes(VC_V2_CONTEXTS.CREDENTIALS_V2)) {
    v2Contexts.unshift(VC_V2_CONTEXTS.CREDENTIALS_V2);
  }

  const vc2: VerifiableCredentialV2 = {
    "@context": v2Contexts,
    type: credential.type,
    issuer: credential.issuer,
    credentialSubject: credential.credentialSubject,
    // Map issuanceDate to validFrom
    validFrom: credential.issuanceDate,
    // Keep issuanceDate for backward compatibility
    issuanceDate: credential.issuanceDate,
    // Copy optional fields
    ...(credential.id && { id: credential.id }),
    ...(credential.proof && { proof: credential.proof })
  };

  return vc2;
}

/**
 * Migrates a W3C VP 1.1 to VP 2.0 format
 * @param vp11 The VP 1.1 presentation
 * @returns The migrated VP 2.0 presentation
 */
export function migratePresentationToV2(vp11: VerifiablePresentation): VerifiablePresentationV2 {
  // Create a new context array with V2 context
  const contexts = Array.isArray(vp11["@context"]) 
    ? [...vp11["@context"]]
    : [vp11["@context"]];
  
  // Replace V1 context with V2
  const v2Contexts = contexts.map(ctx => 
    ctx === VC_V2_CONTEXTS.CREDENTIALS_V1 
      ? VC_V2_CONTEXTS.CREDENTIALS_V2 
      : ctx
  );
  
  // If no V2 context found, add it
  if (!v2Contexts.includes(VC_V2_CONTEXTS.CREDENTIALS_V2)) {
    v2Contexts.unshift(VC_V2_CONTEXTS.CREDENTIALS_V2);
  }

  const vp2: VerifiablePresentationV2 = {
    "@context": v2Contexts,
    type: vp11.type,
    verifiableCredential: vp11.verifiableCredential?.map(vc => {
      if (typeof vc === 'string') return vc;
      // Check if it's a SelectivelyDisclosedCredential
      if ('disclosureProof' in vc) {
        // For now, keep as-is until we implement BBS+
        return vc as any;
      }
      return migrateCredentialToV2(vc);
    })
  };

  // Copy optional fields
  if (vp11.proof) vp2.proof = vp11.proof;

  return vp2;
}

/**
 * Creates a VC 2.0 context based on the features used
 * @param options Configuration for which contexts to include
 * @returns An array of context URLs
 */
export function createV2Context(options: {
  base?: boolean;
  ed25519?: boolean;
  bbs?: boolean;
  statusList?: boolean;
  termsOfUse?: boolean;
  customContexts?: string[];
} = {}): string[] {
  const contexts: string[] = [];
  
  // Always include base V2 context
  contexts.push(VC_V2_CONTEXTS.CREDENTIALS_V2);
  
  if (options.ed25519) {
    contexts.push(VC_V2_CONTEXTS.ED25519_2020);
  }
  
  if (options.bbs) {
    contexts.push(VC_V2_CONTEXTS.BBS_2023);
  }
  
  if (options.statusList) {
    contexts.push(VC_V2_CONTEXTS.STATUS_LIST_2021);
  }
  
  if (options.termsOfUse) {
    contexts.push(VC_V2_CONTEXTS.TERMS_OF_USE);
  }
  
  if (options.customContexts) {
    contexts.push(...options.customContexts);
  }
  
  return contexts;
}