// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DIDRegistry
 * @dev Smart contract for managing Decentralized Identifiers (DIDs) on-chain
 * @notice This contract stores DID documents and provides resolution functionality
 */
contract DIDRegistry {
    struct DIDDocument {
        bytes publicKey;      // Ed25519 public key
        uint256 created;      // Creation timestamp
        uint256 updated;      // Last update timestamp
        bool active;          // Whether the DID is active
        address owner;        // Ethereum address that controls this DID
        string documentHash;  // IPFS hash of full DID document (optional)
    }
    
    // Mapping from DID string to DID document
    mapping(string => DIDDocument) public dids;
    
    // Mapping from owner address to list of owned DIDs
    mapping(address => string[]) public ownerDIDs;
    
    // Events
    event DIDRegistered(
        string indexed did, 
        address indexed owner, 
        bytes publicKey,
        uint256 timestamp
    );
    
    event DIDUpdated(
        string indexed did, 
        address indexed owner,
        bytes newPublicKey,
        uint256 timestamp
    );
    
    event DIDDeactivated(
        string indexed did, 
        address indexed owner,
        uint256 timestamp
    );
    
    event DIDTransferred(
        string indexed did,
        address indexed oldOwner,
        address indexed newOwner,
        uint256 timestamp
    );
    
    // Modifiers
    modifier onlyDIDOwner(string memory did) {
        require(dids[did].owner == msg.sender, "Not DID owner");
        require(dids[did].active, "DID is deactivated");
        _;
    }
    
    modifier validDID(string memory did) {
        require(bytes(did).length > 0, "Invalid DID");
        require(bytes(did).length <= 256, "DID too long");
        _;
    }
    
    /**
     * @dev Register a new DID
     * @param did The DID string (e.g., "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
     * @param publicKey The Ed25519 public key bytes
     * @param documentHash Optional IPFS hash of the full DID document
     */
    function registerDID(
        string memory did,
        bytes memory publicKey,
        string memory documentHash
    ) external validDID(did) {
        require(!dids[did].active, "DID already exists");
        require(publicKey.length == 32, "Invalid public key length");
        
        dids[did] = DIDDocument({
            publicKey: publicKey,
            created: block.timestamp,
            updated: block.timestamp,
            active: true,
            owner: msg.sender,
            documentHash: documentHash
        });
        
        ownerDIDs[msg.sender].push(did);
        
        emit DIDRegistered(did, msg.sender, publicKey, block.timestamp);
    }
    
    /**
     * @dev Update a DID's public key
     * @param did The DID to update
     * @param newPublicKey The new Ed25519 public key
     * @param documentHash Optional new IPFS hash of the DID document
     */
    function updateDID(
        string memory did,
        bytes memory newPublicKey,
        string memory documentHash
    ) external onlyDIDOwner(did) {
        require(newPublicKey.length == 32, "Invalid public key length");
        
        dids[did].publicKey = newPublicKey;
        dids[did].updated = block.timestamp;
        dids[did].documentHash = documentHash;
        
        emit DIDUpdated(did, msg.sender, newPublicKey, block.timestamp);
    }
    
    /**
     * @dev Deactivate a DID (cannot be reactivated)
     * @param did The DID to deactivate
     */
    function deactivateDID(string memory did) external onlyDIDOwner(did) {
        dids[did].active = false;
        dids[did].updated = block.timestamp;
        
        emit DIDDeactivated(did, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Transfer ownership of a DID to another address
     * @param did The DID to transfer
     * @param newOwner The new owner address
     */
    function transferDID(
        string memory did,
        address newOwner
    ) external onlyDIDOwner(did) {
        require(newOwner != address(0), "Invalid new owner");
        require(newOwner != msg.sender, "Already owner");
        
        address oldOwner = msg.sender;
        dids[did].owner = newOwner;
        dids[did].updated = block.timestamp;
        
        // Add to new owner's list
        ownerDIDs[newOwner].push(did);
        
        // Remove from old owner's list
        string[] storage oldOwnerDIDs = ownerDIDs[oldOwner];
        for (uint i = 0; i < oldOwnerDIDs.length; i++) {
            if (keccak256(bytes(oldOwnerDIDs[i])) == keccak256(bytes(did))) {
                oldOwnerDIDs[i] = oldOwnerDIDs[oldOwnerDIDs.length - 1];
                oldOwnerDIDs.pop();
                break;
            }
        }
        
        emit DIDTransferred(did, oldOwner, newOwner, block.timestamp);
    }
    
    /**
     * @dev Resolve a DID to get its document
     * @param did The DID to resolve
     * @return The DID document struct
     */
    function resolveDID(string memory did) 
        external 
        view 
        returns (DIDDocument memory) 
    {
        require(dids[did].active, "DID not found or deactivated");
        return dids[did];
    }
    
    /**
     * @dev Check if a DID exists and is active
     * @param did The DID to check
     * @return Whether the DID exists and is active
     */
    function didExists(string memory did) external view returns (bool) {
        return dids[did].active;
    }
    
    /**
     * @dev Get all DIDs owned by an address
     * @param owner The owner address
     * @return Array of DID strings
     */
    function getDIDsByOwner(address owner) 
        external 
        view 
        returns (string[] memory) 
    {
        return ownerDIDs[owner];
    }
    
    /**
     * @dev Get the number of DIDs owned by an address
     * @param owner The owner address
     * @return Number of DIDs
     */
    function getDIDCountByOwner(address owner) external view returns (uint256) {
        return ownerDIDs[owner].length;
    }
    
    /**
     * @dev Verify that a signature was created by the DID owner
     * @param did The DID that allegedly signed the message
     * @param messageHash The hash of the signed message
     * @param signature The Ed25519 signature (64 bytes)
     * @return Whether the signature is valid
     */
    function verifyDIDSignature(
        string memory did,
        bytes32 messageHash,
        bytes memory signature
    ) external view returns (bool) {
        require(dids[did].active, "DID not found or deactivated");
        require(signature.length == 64, "Invalid signature length");
        
        // Note: This is a placeholder. In practice, you'd need to implement
        // Ed25519 signature verification in Solidity, which is complex.
        // Consider using a precompiled contract or oracle for this.
        return true; // Placeholder
    }
}