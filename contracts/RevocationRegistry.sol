// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevocationRegistry
 * @dev Smart contract for managing credential revocation lists on-chain
 * @notice This contract allows issuers to publish revocation lists and enables verification of credential status
 */
contract RevocationRegistry {
    struct RevocationList {
        uint256[] revokedCredentialIds;  // Array of revoked credential IDs (hashed)
        uint256 timestamp;               // When the list was published
        bytes signature;                 // Issuer's signature over the list
        uint256 version;                 // Version number for the list
        bytes32 merkleRoot;              // Merkle root for efficient revocation checks
    }
    
    // Mapping from issuer DID hash to their revocation list
    mapping(bytes32 => RevocationList) public revocationLists;
    
    // Mapping from issuer DID hash to authorized issuer status
    mapping(bytes32 => bool) public authorizedIssuers;
    
    // Mapping from issuer to their DID string (for events)
    mapping(bytes32 => string) public issuerDIDs;
    
    // Mapping for efficient revocation lookups: issuerHash => credentialHash => isRevoked
    mapping(bytes32 => mapping(bytes32 => bool)) public revokedCredentials;
    
    // Events
    event IssuerAuthorized(bytes32 indexed issuerHash, string issuerDID, uint256 timestamp);
    event IssuerDeauthorized(bytes32 indexed issuerHash, string issuerDID, uint256 timestamp);
    event RevocationListPublished(
        bytes32 indexed issuerHash, 
        string issuerDID,
        uint256 version,
        uint256 revokedCount,
        bytes32 merkleRoot,
        uint256 timestamp
    );
    event CredentialRevoked(
        bytes32 indexed issuerHash,
        bytes32 indexed credentialHash,
        string issuerDID,
        uint256 timestamp
    );
    
    // Access control
    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }
    
    modifier onlyAuthorizedIssuer(string memory issuerDID) {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        require(authorizedIssuers[issuerHash], "Not authorized issuer");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Authorize an issuer to publish revocation lists
     * @param issuerDID The DID of the issuer to authorize
     */
    function authorizeIssuer(string memory issuerDID) external onlyOwner {
        require(bytes(issuerDID).length > 0, "Invalid issuer DID");
        
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        authorizedIssuers[issuerHash] = true;
        issuerDIDs[issuerHash] = issuerDID;
        
        emit IssuerAuthorized(issuerHash, issuerDID, block.timestamp);
    }
    
    /**
     * @dev Deauthorize an issuer
     * @param issuerDID The DID of the issuer to deauthorize
     */
    function deauthorizeIssuer(string memory issuerDID) external onlyOwner {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        require(authorizedIssuers[issuerHash], "Issuer not authorized");
        
        authorizedIssuers[issuerHash] = false;
        
        emit IssuerDeauthorized(issuerHash, issuerDID, block.timestamp);
    }
    
    /**
     * @dev Publish a revocation list with individual credential hashes
     * @param issuerDID The DID of the issuer
     * @param credentialHashes Array of hashed credential IDs to revoke
     * @param signature Issuer's signature over the revocation data
     * @param merkleRoot Merkle root for efficient verification (optional, can be 0x0)
     */
    function publishRevocationList(
        string memory issuerDID,
        bytes32[] memory credentialHashes,
        bytes memory signature,
        bytes32 merkleRoot
    ) external onlyAuthorizedIssuer(issuerDID) {
        require(credentialHashes.length > 0, "Empty revocation list");
        require(signature.length > 0, "Invalid signature");
        
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        
        // Convert bytes32 array to uint256 array for storage
        uint256[] memory revokedIds = new uint256[](credentialHashes.length);
        for (uint i = 0; i < credentialHashes.length; i++) {
            revokedIds[i] = uint256(credentialHashes[i]);
            // Mark individual credentials as revoked for quick lookup
            revokedCredentials[issuerHash][credentialHashes[i]] = true;
            
            emit CredentialRevoked(issuerHash, credentialHashes[i], issuerDID, block.timestamp);
        }
        
        // Increment version
        uint256 newVersion = revocationLists[issuerHash].version + 1;
        
        // Store the revocation list
        revocationLists[issuerHash] = RevocationList({
            revokedCredentialIds: revokedIds,
            timestamp: block.timestamp,
            signature: signature,
            version: newVersion,
            merkleRoot: merkleRoot
        });
        
        emit RevocationListPublished(
            issuerHash,
            issuerDID,
            newVersion,
            credentialHashes.length,
            merkleRoot,
            block.timestamp
        );
    }
    
    /**
     * @dev Add individual credentials to the revocation list
     * @param issuerDID The DID of the issuer
     * @param credentialHashes Array of credential hashes to revoke
     * @param signature New signature covering the updated list
     */
    function revokeCredentials(
        string memory issuerDID,
        bytes32[] memory credentialHashes,
        bytes memory signature
    ) external onlyAuthorizedIssuer(issuerDID) {
        require(credentialHashes.length > 0, "No credentials to revoke");
        
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        
        // Mark credentials as revoked
        for (uint i = 0; i < credentialHashes.length; i++) {
            if (!revokedCredentials[issuerHash][credentialHashes[i]]) {
                revokedCredentials[issuerHash][credentialHashes[i]] = true;
                
                // Add to the stored list
                revocationLists[issuerHash].revokedCredentialIds.push(uint256(credentialHashes[i]));
                
                emit CredentialRevoked(issuerHash, credentialHashes[i], issuerDID, block.timestamp);
            }
        }
        
        // Update metadata
        revocationLists[issuerHash].timestamp = block.timestamp;
        revocationLists[issuerHash].signature = signature;
        revocationLists[issuerHash].version += 1;
        
        emit RevocationListPublished(
            issuerHash,
            issuerDID,
            revocationLists[issuerHash].version,
            credentialHashes.length,
            revocationLists[issuerHash].merkleRoot,
            block.timestamp
        );
    }
    
    /**
     * @dev Check if a credential is revoked
     * @param issuerDID The DID of the issuer
     * @param credentialId The credential ID to check
     * @return Whether the credential is revoked
     */
    function isCredentialRevoked(
        string memory issuerDID,
        string memory credentialId
    ) external view returns (bool) {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        bytes32 credentialHash = keccak256(bytes(credentialId));
        
        return revokedCredentials[issuerHash][credentialHash];
    }
    
    /**
     * @dev Check if a credential is revoked using hashes (more efficient)
     * @param issuerHash Hash of the issuer DID
     * @param credentialHash Hash of the credential ID
     * @return Whether the credential is revoked
     */
    function isCredentialRevokedByHash(
        bytes32 issuerHash,
        bytes32 credentialHash
    ) external view returns (bool) {
        return revokedCredentials[issuerHash][credentialHash];
    }
    
    /**
     * @dev Get the revocation list for an issuer
     * @param issuerDID The DID of the issuer
     * @return The revocation list struct
     */
    function getRevocationList(string memory issuerDID) 
        external 
        view 
        returns (RevocationList memory) 
    {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        return revocationLists[issuerHash];
    }
    
    /**
     * @dev Get the number of revoked credentials for an issuer
     * @param issuerDID The DID of the issuer
     * @return Number of revoked credentials
     */
    function getRevokedCredentialCount(string memory issuerDID) 
        external 
        view 
        returns (uint256) 
    {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        return revocationLists[issuerHash].revokedCredentialIds.length;
    }
    
    /**
     * @dev Verify a Merkle proof for credential revocation
     * @param issuerDID The DID of the issuer
     * @param credentialHash The hash of the credential to verify
     * @param merkleProof Array of hashes forming the Merkle proof
     * @return Whether the credential is in the revocation list
     */
    function verifyRevocationProof(
        string memory issuerDID,
        bytes32 credentialHash,
        bytes32[] memory merkleProof
    ) external view returns (bool) {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        bytes32 merkleRoot = revocationLists[issuerHash].merkleRoot;
        
        if (merkleRoot == bytes32(0)) {
            // No Merkle tree, fall back to direct lookup
            return revokedCredentials[issuerHash][credentialHash];
        }
        
        return _verifyMerkleProof(merkleProof, merkleRoot, credentialHash);
    }
    
    /**
     * @dev Internal function to verify Merkle proof
     * @param proof Array of sibling hashes
     * @param root The Merkle root
     * @param leaf The leaf to verify
     * @return Whether the proof is valid
     */
    function _verifyMerkleProof(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        
        return computedHash == root;
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        owner = newOwner;
    }
}