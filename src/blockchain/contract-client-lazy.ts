import type { Contract, Wallet, Provider } from 'ethers';
import { BlockchainConfig, ContractAddresses } from './types';

// Lazy-loaded dependencies
let ethersModule: any;
let DIDRegistryABI: any;
let RevocationRegistryABI: any;
let SchemaRegistryABI: any;

export class ContractClient {
  private provider: Provider | null = null;
  private signer?: Wallet;
  private contracts: {
    didRegistry: Contract | null;
    revocationRegistry: Contract | null;
    schemaRegistry: Contract | null;
  } = {
    didRegistry: null,
    revocationRegistry: null,
    schemaRegistry: null,
  };
  private initialized = false;
  private initPromise: Promise<void> | null = null;

  constructor(
    private rpcUrlOrConfig: string | BlockchainConfig,
    private privateKey?: string,
    private contractAddresses?: ContractAddresses
  ) {}

  private async initialize(): Promise<void> {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = this.doInitialize();
    await this.initPromise;
    this.initialized = true;
  }

  private async doInitialize(): Promise<void> {
    try {
      // Dynamic import of ethers
      ethersModule = await import('ethers');
      const { ethers } = ethersModule;

      // Dynamic import of contract ABIs
      [DIDRegistryABI, RevocationRegistryABI, SchemaRegistryABI] = await Promise.all([
        import('../../artifacts/contracts/DIDRegistry.sol/DIDRegistry.json'),
        import('../../artifacts/contracts/RevocationRegistry.sol/RevocationRegistry.json'),
        import('../../artifacts/contracts/SchemaRegistry.sol/SchemaRegistry.json'),
      ]);

      // Handle both constructor signatures
      if (typeof this.rpcUrlOrConfig === 'string') {
        // New signature: (rpcUrl, privateKey, contractAddresses)
        this.provider = new ethers.JsonRpcProvider(this.rpcUrlOrConfig);
        
        if (this.privateKey) {
          this.signer = new ethers.Wallet(this.privateKey, this.provider);
        }

        if (!this.contractAddresses) {
          throw new Error('Contract addresses required when using RPC URL constructor');
        }

        const signerOrProvider = this.signer || this.provider;
        
        this.contracts = {
          didRegistry: new ethers.Contract(
            this.contractAddresses.didRegistry,
            DIDRegistryABI.abi,
            signerOrProvider
          ),
          revocationRegistry: new ethers.Contract(
            this.contractAddresses.revocationRegistry,
            RevocationRegistryABI.abi,
            signerOrProvider
          ),
          schemaRegistry: new ethers.Contract(
            this.contractAddresses.schemaRegistry,
            SchemaRegistryABI.abi,
            signerOrProvider
          ),
        };
      } else {
        // Legacy signature: (config)
        const config = this.rpcUrlOrConfig;
        this.provider = new ethers.JsonRpcProvider(config.rpcUrl);
        
        if (config.privateKey) {
          this.signer = new ethers.Wallet(config.privateKey, this.provider);
        }

        const signerOrProvider = this.signer || this.provider;
        
        this.contracts = {
          didRegistry: new ethers.Contract(
            config.contracts.didRegistry,
            DIDRegistryABI.abi,
            signerOrProvider
          ),
          revocationRegistry: new ethers.Contract(
            config.contracts.revocationRegistry,
            RevocationRegistryABI.abi,
            signerOrProvider
          ),
          schemaRegistry: new ethers.Contract(
            config.contracts.schemaRegistry,
            SchemaRegistryABI.abi,
            signerOrProvider
          ),
        };
      }
    } catch (error) {
      throw new Error(`Failed to initialize blockchain client: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // DID Registry Methods
  async registerDID(did: string, didDocument: string): Promise<any> {
    await this.initialize();
    if (!this.contracts.didRegistry) throw new Error('DID Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.didRegistry.registerDID(did, didDocument);
  }

  async resolveDID(did: string): Promise<string> {
    await this.initialize();
    if (!this.contracts.didRegistry) throw new Error('DID Registry not initialized');
    
    return await this.contracts.didRegistry.resolveDID(did);
  }

  async updateDID(did: string, didDocument: string): Promise<any> {
    await this.initialize();
    if (!this.contracts.didRegistry) throw new Error('DID Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.didRegistry.updateDID(did, didDocument);
  }

  async deactivateDID(did: string): Promise<any> {
    await this.initialize();
    if (!this.contracts.didRegistry) throw new Error('DID Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.didRegistry.deactivateDID(did);
  }

  async isDIDActive(did: string): Promise<boolean> {
    await this.initialize();
    if (!this.contracts.didRegistry) throw new Error('DID Registry not initialized');
    
    return await this.contracts.didRegistry.isDIDActive(did);
  }

  // Revocation Registry Methods
  async publishRevocationList(
    issuerDID: string,
    listId: string,
    revokedCredentials: string[]
  ): Promise<any> {
    await this.initialize();
    if (!this.contracts.revocationRegistry) throw new Error('Revocation Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.revocationRegistry.publishRevocationList(
      issuerDID,
      listId,
      revokedCredentials
    );
  }

  async isCredentialRevoked(
    issuerDID: string,
    credentialId: string
  ): Promise<boolean> {
    await this.initialize();
    if (!this.contracts.revocationRegistry) throw new Error('Revocation Registry not initialized');
    
    return await this.contracts.revocationRegistry.isCredentialRevoked(
      issuerDID,
      credentialId
    );
  }

  async getRevocationList(
    issuerDID: string,
    listId: string
  ): Promise<string[]> {
    await this.initialize();
    if (!this.contracts.revocationRegistry) throw new Error('Revocation Registry not initialized');
    
    return await this.contracts.revocationRegistry.getRevocationList(
      issuerDID,
      listId
    );
  }

  // Schema Registry Methods
  async registerSchema(
    schemaId: string,
    schema: string
  ): Promise<any> {
    await this.initialize();
    if (!this.contracts.schemaRegistry) throw new Error('Schema Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.schemaRegistry.registerSchema(schemaId, schema);
  }

  async getSchema(schemaId: string): Promise<string> {
    await this.initialize();
    if (!this.contracts.schemaRegistry) throw new Error('Schema Registry not initialized');
    
    return await this.contracts.schemaRegistry.getSchema(schemaId);
  }

  async updateSchema(
    schemaId: string,
    schema: string
  ): Promise<any> {
    await this.initialize();
    if (!this.contracts.schemaRegistry) throw new Error('Schema Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.schemaRegistry.updateSchema(schemaId, schema);
  }

  async deactivateSchema(schemaId: string): Promise<any> {
    await this.initialize();
    if (!this.contracts.schemaRegistry) throw new Error('Schema Registry not initialized');
    if (!this.signer) throw new Error('Signer required for write operations');
    
    return await this.contracts.schemaRegistry.deactivateSchema(schemaId);
  }

  async isSchemaActive(schemaId: string): Promise<boolean> {
    await this.initialize();
    if (!this.contracts.schemaRegistry) throw new Error('Schema Registry not initialized');
    
    return await this.contracts.schemaRegistry.isSchemaActive(schemaId);
  }

  // Utility methods
  async getBlockNumber(): Promise<number> {
    await this.initialize();
    if (!this.provider) throw new Error('Provider not initialized');
    
    return await this.provider.getBlockNumber();
  }

  async waitForTransaction(
    txHash: string,
    confirmations = 1
  ): Promise<any> {
    await this.initialize();
    if (!this.provider) throw new Error('Provider not initialized');
    
    return await this.provider.waitForTransaction(txHash, confirmations);
  }

  getProvider(): Provider {
    if (!this.provider) throw new Error('Provider not initialized. Call initialize() first.');
    return this.provider;
  }

  getSigner(): Wallet | undefined {
    return this.signer;
  }

  getContracts() {
    return this.contracts;
  }
}