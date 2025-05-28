// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SchemaRegistry
 * @dev Smart contract for managing credential schemas on-chain
 * @notice This contract allows registration and management of verifiable credential schemas
 */
contract SchemaRegistry {
    struct CredentialSchema {
        string name;              // Human-readable name
        string description;       // Schema description
        string schemaHash;        // IPFS hash of the full JSON schema
        string issuerDID;         // DID of the schema creator
        string version;           // Schema version (e.g., "1.0.0")
        uint256 created;          // Creation timestamp
        uint256 updated;          // Last update timestamp
        bool active;              // Whether the schema is active
        address owner;            // Ethereum address that owns this schema
        SchemaType schemaType;    // Type of schema
        string[] dependencies;    // Other schema IDs this schema depends on
    }
    
    enum SchemaType {
        BasicProfile,     // Basic user profile information
        Educational,      // Educational credentials
        Professional,     // Professional certifications
        Medical,          // Medical records
        Financial,        // Financial information
        Identity,         // Identity verification
        Custom           // Custom schema type
    }
    
    // Mapping from schema ID to schema
    mapping(uint256 => CredentialSchema) public schemas;
    
    // Mapping from issuer DID hash to their schema IDs
    mapping(bytes32 => uint256[]) public issuerSchemas;
    
    // Mapping from schema name hash to schema ID (for name uniqueness per issuer)
    mapping(bytes32 => mapping(bytes32 => uint256)) public schemaNameToId;
    
    // Counter for schema IDs
    uint256 private nextSchemaId = 1;
    
    // Events
    event SchemaRegistered(
        uint256 indexed schemaId,
        string indexed issuerDID,
        string name,
        string version,
        SchemaType schemaType,
        uint256 timestamp
    );
    
    event SchemaUpdated(
        uint256 indexed schemaId,
        string indexed issuerDID,
        string newVersion,
        uint256 timestamp
    );
    
    event SchemaDeactivated(
        uint256 indexed schemaId,
        string indexed issuerDID,
        uint256 timestamp
    );
    
    event SchemaTransferred(
        uint256 indexed schemaId,
        string issuerDID,
        address indexed oldOwner,
        address indexed newOwner,
        uint256 timestamp
    );
    
    // Modifiers
    modifier onlySchemaOwner(uint256 schemaId) {
        require(schemas[schemaId].owner == msg.sender, "Not schema owner");
        require(schemas[schemaId].active, "Schema is deactivated");
        _;
    }
    
    modifier validSchemaId(uint256 schemaId) {
        require(schemaId > 0 && schemaId < nextSchemaId, "Invalid schema ID");
        _;
    }
    
    /**
     * @dev Register a new credential schema
     * @param name Human-readable name for the schema
     * @param description Description of the schema
     * @param schemaHash IPFS hash of the full JSON schema
     * @param issuerDID DID of the schema creator
     * @param version Version string (e.g., "1.0.0")
     * @param schemaType Type of the schema
     * @param dependencies Array of schema IDs this schema depends on
     * @return The ID of the newly registered schema
     */
    function registerSchema(
        string memory name,
        string memory description,
        string memory schemaHash,
        string memory issuerDID,
        string memory version,
        SchemaType schemaType,
        string[] memory dependencies
    ) external returns (uint256) {
        require(bytes(name).length > 0, "Schema name required");
        require(bytes(schemaHash).length > 0, "Schema hash required");
        require(bytes(issuerDID).length > 0, "Issuer DID required");
        require(bytes(version).length > 0, "Version required");
        
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        bytes32 nameHash = keccak256(bytes(name));
        
        // Check if schema name already exists for this issuer
        require(
            schemaNameToId[issuerHash][nameHash] == 0, 
            "Schema name already exists for this issuer"
        );
        
        // Validate dependencies exist
        for (uint i = 0; i < dependencies.length; i++) {
            uint256 depId = _stringToUint(dependencies[i]);
            require(depId > 0 && depId < nextSchemaId, "Invalid dependency");
            require(schemas[depId].active, "Dependency schema not active");
        }
        
        uint256 schemaId = nextSchemaId++;
        
        schemas[schemaId] = CredentialSchema({
            name: name,
            description: description,
            schemaHash: schemaHash,
            issuerDID: issuerDID,
            version: version,
            created: block.timestamp,
            updated: block.timestamp,
            active: true,
            owner: msg.sender,
            schemaType: schemaType,
            dependencies: dependencies
        });
        
        issuerSchemas[issuerHash].push(schemaId);
        schemaNameToId[issuerHash][nameHash] = schemaId;
        
        emit SchemaRegistered(
            schemaId,
            issuerDID,
            name,
            version,
            schemaType,
            block.timestamp
        );
        
        return schemaId;
    }
    
    /**
     * @dev Update an existing schema
     * @param schemaId The ID of the schema to update
     * @param description New description
     * @param schemaHash New IPFS hash of the schema
     * @param newVersion New version string
     * @param dependencies New dependencies array
     */
    function updateSchema(
        uint256 schemaId,
        string memory description,
        string memory schemaHash,
        string memory newVersion,
        string[] memory dependencies
    ) external validSchemaId(schemaId) onlySchemaOwner(schemaId) {
        require(bytes(schemaHash).length > 0, "Schema hash required");
        require(bytes(newVersion).length > 0, "Version required");
        
        // Validate dependencies
        for (uint i = 0; i < dependencies.length; i++) {
            uint256 depId = _stringToUint(dependencies[i]);
            require(depId > 0 && depId < nextSchemaId, "Invalid dependency");
            require(schemas[depId].active, "Dependency schema not active");
        }
        
        schemas[schemaId].description = description;
        schemas[schemaId].schemaHash = schemaHash;
        schemas[schemaId].version = newVersion;
        schemas[schemaId].updated = block.timestamp;
        schemas[schemaId].dependencies = dependencies;
        
        emit SchemaUpdated(
            schemaId,
            schemas[schemaId].issuerDID,
            newVersion,
            block.timestamp
        );
    }
    
    /**
     * @dev Deactivate a schema
     * @param schemaId The ID of the schema to deactivate
     */
    function deactivateSchema(uint256 schemaId) 
        external 
        validSchemaId(schemaId) 
        onlySchemaOwner(schemaId) 
    {
        schemas[schemaId].active = false;
        schemas[schemaId].updated = block.timestamp;
        
        emit SchemaDeactivated(
            schemaId,
            schemas[schemaId].issuerDID,
            block.timestamp
        );
    }
    
    /**
     * @dev Transfer ownership of a schema
     * @param schemaId The ID of the schema to transfer
     * @param newOwner The new owner address
     */
    function transferSchema(
        uint256 schemaId,
        address newOwner
    ) external validSchemaId(schemaId) onlySchemaOwner(schemaId) {
        require(newOwner != address(0), "Invalid new owner");
        require(newOwner != msg.sender, "Already owner");
        
        address oldOwner = msg.sender;
        schemas[schemaId].owner = newOwner;
        schemas[schemaId].updated = block.timestamp;
        
        emit SchemaTransferred(
            schemaId,
            schemas[schemaId].issuerDID,
            oldOwner,
            newOwner,
            block.timestamp
        );
    }
    
    /**
     * @dev Get a schema by ID
     * @param schemaId The schema ID
     * @return The schema struct
     */
    function getSchema(uint256 schemaId) 
        external 
        view 
        validSchemaId(schemaId)
        returns (CredentialSchema memory) 
    {
        return schemas[schemaId];
    }
    
    /**
     * @dev Get all schemas for an issuer
     * @param issuerDID The issuer DID
     * @return Array of schema IDs
     */
    function getSchemasByIssuer(string memory issuerDID) 
        external 
        view 
        returns (uint256[] memory) 
    {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        return issuerSchemas[issuerHash];
    }
    
    /**
     * @dev Get schema ID by issuer and name
     * @param issuerDID The issuer DID
     * @param name The schema name
     * @return The schema ID (0 if not found)
     */
    function getSchemaIdByName(
        string memory issuerDID,
        string memory name
    ) external view returns (uint256) {
        bytes32 issuerHash = keccak256(bytes(issuerDID));
        bytes32 nameHash = keccak256(bytes(name));
        return schemaNameToId[issuerHash][nameHash];
    }
    
    /**
     * @dev Get schemas by type
     * @param schemaType The type of schemas to retrieve
     * @return Array of schema IDs
     */
    function getSchemasByType(SchemaType schemaType) 
        external 
        view 
        returns (uint256[] memory) 
    {
        // Count matching schemas first
        uint256 count = 0;
        for (uint256 i = 1; i < nextSchemaId; i++) {
            if (schemas[i].active && schemas[i].schemaType == schemaType) {
                count++;
            }
        }
        
        // Create result array
        uint256[] memory result = new uint256[](count);
        uint256 index = 0;
        
        for (uint256 i = 1; i < nextSchemaId; i++) {
            if (schemas[i].active && schemas[i].schemaType == schemaType) {
                result[index] = i;
                index++;
            }
        }
        
        return result;
    }
    
    /**
     * @dev Check if a schema exists and is active
     * @param schemaId The schema ID to check
     * @return Whether the schema exists and is active
     */
    function schemaExists(uint256 schemaId) external view returns (bool) {
        return schemaId > 0 && schemaId < nextSchemaId && schemas[schemaId].active;
    }
    
    /**
     * @dev Get the total number of schemas registered
     * @return The total schema count
     */
    function getTotalSchemaCount() external view returns (uint256) {
        return nextSchemaId - 1;
    }
    
    /**
     * @dev Get schema dependencies
     * @param schemaId The schema ID
     * @return Array of dependency schema IDs as strings
     */
    function getSchemaDependencies(uint256 schemaId) 
        external 
        view 
        validSchemaId(schemaId)
        returns (string[] memory) 
    {
        return schemas[schemaId].dependencies;
    }
    
    /**
     * @dev Check if schema has circular dependencies
     * @param schemaId The schema ID to check
     * @return Whether the schema has circular dependencies
     */
    function hasCircularDependencies(uint256 schemaId) 
        external 
        view 
        validSchemaId(schemaId)
        returns (bool) 
    {
        return _checkCircularDependency(schemaId, new uint256[](0));
    }
    
    /**
     * @dev Internal function to check for circular dependencies
     * @param schemaId Current schema being checked
     * @param visited Array of visited schema IDs
     * @return Whether circular dependency exists
     */
    function _checkCircularDependency(
        uint256 schemaId,
        uint256[] memory visited
    ) internal view returns (bool) {
        // Check if this schema is already in the visited path
        for (uint i = 0; i < visited.length; i++) {
            if (visited[i] == schemaId) {
                return true; // Circular dependency found
            }
        }
        
        // Add current schema to visited path
        uint256[] memory newVisited = new uint256[](visited.length + 1);
        for (uint i = 0; i < visited.length; i++) {
            newVisited[i] = visited[i];
        }
        newVisited[visited.length] = schemaId;
        
        // Check all dependencies
        string[] memory dependencies = schemas[schemaId].dependencies;
        for (uint i = 0; i < dependencies.length; i++) {
            uint256 depId = _stringToUint(dependencies[i]);
            if (_checkCircularDependency(depId, newVisited)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * @dev Convert string to uint256 (simple implementation)
     * @param str The string to convert
     * @return The uint256 value
     */
    function _stringToUint(string memory str) internal pure returns (uint256) {
        bytes memory b = bytes(str);
        uint256 result = 0;
        
        for (uint i = 0; i < b.length; i++) {
            if (b[i] >= 0x30 && b[i] <= 0x39) {
                result = result * 10 + (uint256(uint8(b[i])) - 48);
            }
        }
        
        return result;
    }
}