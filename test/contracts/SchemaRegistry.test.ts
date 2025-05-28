import { expect } from "chai";
import { ethers } from "hardhat";
import { SchemaRegistry } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("SchemaRegistry", function () {
  let schemaRegistry: SchemaRegistry;
  let owner: SignerWithAddress;
  let issuer1: SignerWithAddress;
  let issuer2: SignerWithAddress;

  const issuerDID1 = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  const issuerDID2 = "did:key:z6MkpqCcLGrqpDjDHU8hqQQQP9ZGGd4VrMjGVTKGrqpDjDHU";
  
  const sampleSchema = {
    name: "BasicProfile",
    description: "Basic user profile schema",
    schemaHash: "QmSampleSchemaHash123",
    version: "1.0.0",
    schemaType: 0, // BasicProfile
    dependencies: []
  };

  beforeEach(async function () {
    [owner, issuer1, issuer2] = await ethers.getSigners();

    const SchemaRegistryFactory = await ethers.getContractFactory("SchemaRegistry");
    schemaRegistry = await SchemaRegistryFactory.deploy();
    await schemaRegistry.waitForDeployment();
  });

  describe("Schema Registration", function () {
    it("Should register a new schema successfully", async function () {
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          sampleSchema.name,
          sampleSchema.description,
          sampleSchema.schemaHash,
          issuerDID1,
          sampleSchema.version,
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      )
        .to.emit(schemaRegistry, "SchemaRegistered")
;

      const schema = await schemaRegistry.getSchema(1);
      expect(schema.name).to.equal(sampleSchema.name);
      expect(schema.description).to.equal(sampleSchema.description);
      expect(schema.schemaHash).to.equal(sampleSchema.schemaHash);
      expect(schema.issuerDID).to.equal(issuerDID1);
      expect(schema.version).to.equal(sampleSchema.version);
      expect(schema.owner).to.equal(issuer1.address);
      expect(schema.active).to.be.true;
    });

    it("Should fail to register schema with empty name", async function () {
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          "",
          sampleSchema.description,
          sampleSchema.schemaHash,
          issuerDID1,
          sampleSchema.version,
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      ).to.be.revertedWith("Schema name required");
    });

    it("Should fail to register schema with empty hash", async function () {
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          sampleSchema.name,
          sampleSchema.description,
          "",
          issuerDID1,
          sampleSchema.version,
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      ).to.be.revertedWith("Schema hash required");
    });

    it("Should fail to register schema with empty issuer DID", async function () {
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          sampleSchema.name,
          sampleSchema.description,
          sampleSchema.schemaHash,
          "",
          sampleSchema.version,
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      ).to.be.revertedWith("Issuer DID required");
    });

    it("Should fail to register schema with empty version", async function () {
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          sampleSchema.name,
          sampleSchema.description,
          sampleSchema.schemaHash,
          issuerDID1,
          "",
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      ).to.be.revertedWith("Version required");
    });

    it("Should fail to register duplicate schema name for same issuer", async function () {
      // Register first schema
      await schemaRegistry.connect(issuer1).registerSchema(
        sampleSchema.name,
        sampleSchema.description,
        sampleSchema.schemaHash,
        issuerDID1,
        sampleSchema.version,
        sampleSchema.schemaType,
        sampleSchema.dependencies
      );

      // Try to register schema with same name and issuer
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          sampleSchema.name,
          "Different description",
          "DifferentHash",
          issuerDID1,
          "2.0.0",
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      ).to.be.revertedWith("Schema name already exists for this issuer");
    });

    it("Should allow same schema name for different issuers", async function () {
      // Register schema for issuer1
      await schemaRegistry.connect(issuer1).registerSchema(
        sampleSchema.name,
        sampleSchema.description,
        sampleSchema.schemaHash,
        issuerDID1,
        sampleSchema.version,
        sampleSchema.schemaType,
        sampleSchema.dependencies
      );

      // Register schema with same name for issuer2
      await expect(
        schemaRegistry.connect(issuer2).registerSchema(
          sampleSchema.name,
          sampleSchema.description,
          "DifferentHash",
          issuerDID2,
          sampleSchema.version,
          sampleSchema.schemaType,
          sampleSchema.dependencies
        )
      ).to.not.be.reverted;

      expect(await schemaRegistry.getTotalSchemaCount()).to.equal(2);
    });
  });

  describe("Schema Dependencies", function () {
    beforeEach(async function () {
      // Register base schema
      await schemaRegistry.connect(issuer1).registerSchema(
        "BaseSchema",
        "Base schema",
        "BaseHash",
        issuerDID1,
        "1.0.0",
        0,
        []
      );
    });

    it("Should register schema with valid dependencies", async function () {
      const dependencies = ["1"]; // Reference to schema ID 1
      
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          "DependentSchema",
          "Schema with dependencies",
          "DependentHash",
          issuerDID1,
          "1.0.0",
          6, // Custom
          dependencies
        )
      ).to.not.be.reverted;

      const schema = await schemaRegistry.getSchema(2);
      const schemaDeps = await schemaRegistry.getSchemaDependencies(2);
      expect(schemaDeps).to.deep.equal(dependencies);
    });

    it("Should fail to register schema with invalid dependency", async function () {
      const dependencies = ["999"]; // Non-existent schema ID
      
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          "DependentSchema",
          "Schema with dependencies",
          "DependentHash",
          issuerDID1,
          "1.0.0",
          6,
          dependencies
        )
      ).to.be.revertedWith("Invalid dependency");
    });

    it("Should fail to register schema with inactive dependency", async function () {
      // Deactivate base schema
      await schemaRegistry.connect(issuer1).deactivateSchema(1);
      
      const dependencies = ["1"];
      
      await expect(
        schemaRegistry.connect(issuer1).registerSchema(
          "DependentSchema",
          "Schema with dependencies",
          "DependentHash",
          issuerDID1,
          "1.0.0",
          6,
          dependencies
        )
      ).to.be.revertedWith("Dependency schema not active");
    });
  });

  describe("Schema Updates", function () {
    beforeEach(async function () {
      await schemaRegistry.connect(issuer1).registerSchema(
        sampleSchema.name,
        sampleSchema.description,
        sampleSchema.schemaHash,
        issuerDID1,
        sampleSchema.version,
        sampleSchema.schemaType,
        sampleSchema.dependencies
      );
    });

    it("Should update schema successfully", async function () {
      const newDescription = "Updated description";
      const newHash = "UpdatedHash";
      const newVersion = "2.0.0";

      await expect(
        schemaRegistry.connect(issuer1).updateSchema(
          1,
          newDescription,
          newHash,
          newVersion,
          []
        )
      )
        .to.emit(schemaRegistry, "SchemaUpdated")
;

      const schema = await schemaRegistry.getSchema(1);
      expect(schema.description).to.equal(newDescription);
      expect(schema.schemaHash).to.equal(newHash);
      expect(schema.version).to.equal(newVersion);
    });

    it("Should fail to update schema by non-owner", async function () {
      await expect(
        schemaRegistry.connect(issuer2).updateSchema(
          1,
          "New description",
          "NewHash",
          "2.0.0",
          []
        )
      ).to.be.revertedWith("Not schema owner");
    });

    it("Should fail to update with empty hash", async function () {
      await expect(
        schemaRegistry.connect(issuer1).updateSchema(
          1,
          "New description",
          "",
          "2.0.0",
          []
        )
      ).to.be.revertedWith("Schema hash required");
    });

    it("Should fail to update with empty version", async function () {
      await expect(
        schemaRegistry.connect(issuer1).updateSchema(
          1,
          "New description",
          "NewHash",
          "",
          []
        )
      ).to.be.revertedWith("Version required");
    });
  });

  describe("Schema Deactivation", function () {
    beforeEach(async function () {
      await schemaRegistry.connect(issuer1).registerSchema(
        sampleSchema.name,
        sampleSchema.description,
        sampleSchema.schemaHash,
        issuerDID1,
        sampleSchema.version,
        sampleSchema.schemaType,
        sampleSchema.dependencies
      );
    });

    it("Should deactivate schema successfully", async function () {
      await expect(
        schemaRegistry.connect(issuer1).deactivateSchema(1)
      )
        .to.emit(schemaRegistry, "SchemaDeactivated")
;

      const schema = await schemaRegistry.getSchema(1);
      expect(schema.active).to.be.false;
      expect(await schemaRegistry.schemaExists(1)).to.be.false;
    });

    it("Should fail to deactivate schema by non-owner", async function () {
      await expect(
        schemaRegistry.connect(issuer2).deactivateSchema(1)
      ).to.be.revertedWith("Not schema owner");
    });

    it("Should fail to update deactivated schema", async function () {
      await schemaRegistry.connect(issuer1).deactivateSchema(1);
      
      await expect(
        schemaRegistry.connect(issuer1).updateSchema(
          1,
          "New description",
          "NewHash",
          "2.0.0",
          []
        )
      ).to.be.revertedWith("Schema is deactivated");
    });
  });

  describe("Schema Transfer", function () {
    beforeEach(async function () {
      await schemaRegistry.connect(issuer1).registerSchema(
        sampleSchema.name,
        sampleSchema.description,
        sampleSchema.schemaHash,
        issuerDID1,
        sampleSchema.version,
        sampleSchema.schemaType,
        sampleSchema.dependencies
      );
    });

    it("Should transfer schema ownership successfully", async function () {
      await expect(
        schemaRegistry.connect(issuer1).transferSchema(1, issuer2.address)
      )
        .to.emit(schemaRegistry, "SchemaTransferred")
;

      const schema = await schemaRegistry.getSchema(1);
      expect(schema.owner).to.equal(issuer2.address);
    });

    it("Should fail to transfer to zero address", async function () {
      await expect(
        schemaRegistry.connect(issuer1).transferSchema(1, ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid new owner");
    });

    it("Should fail to transfer to same owner", async function () {
      await expect(
        schemaRegistry.connect(issuer1).transferSchema(1, issuer1.address)
      ).to.be.revertedWith("Already owner");
    });

    it("Should fail to transfer by non-owner", async function () {
      await expect(
        schemaRegistry.connect(issuer2).transferSchema(1, issuer2.address)
      ).to.be.revertedWith("Not schema owner");
    });
  });

  describe("Schema Queries", function () {
    beforeEach(async function () {
      // Register multiple schemas
      await schemaRegistry.connect(issuer1).registerSchema(
        "Schema1",
        "First schema",
        "Hash1",
        issuerDID1,
        "1.0.0",
        0, // BasicProfile
        []
      );

      await schemaRegistry.connect(issuer1).registerSchema(
        "Schema2",
        "Second schema",
        "Hash2",
        issuerDID1,
        "1.0.0",
        1, // Educational
        []
      );

      await schemaRegistry.connect(issuer2).registerSchema(
        "Schema3",
        "Third schema",
        "Hash3",
        issuerDID2,
        "1.0.0",
        0, // BasicProfile
        []
      );
    });

    it("Should return schemas by issuer", async function () {
      const issuer1Schemas = await schemaRegistry.getSchemasByIssuer(issuerDID1);
      const issuer2Schemas = await schemaRegistry.getSchemasByIssuer(issuerDID2);

      expect(issuer1Schemas).to.have.lengthOf(2);
      expect(issuer1Schemas).to.deep.equal([1n, 2n]);
      
      expect(issuer2Schemas).to.have.lengthOf(1);
      expect(issuer2Schemas).to.deep.equal([3n]);
    });

    it("Should return schema ID by name", async function () {
      const schemaId = await schemaRegistry.getSchemaIdByName(issuerDID1, "Schema1");
      expect(schemaId).to.equal(1);

      const nonExistent = await schemaRegistry.getSchemaIdByName(issuerDID1, "NonExistent");
      expect(nonExistent).to.equal(0);
    });

    it("Should return schemas by type", async function () {
      const basicProfileSchemas = await schemaRegistry.getSchemasByType(0); // BasicProfile
      const educationalSchemas = await schemaRegistry.getSchemasByType(1); // Educational

      expect(basicProfileSchemas).to.have.lengthOf(2);
      expect(basicProfileSchemas).to.include(1n);
      expect(basicProfileSchemas).to.include(3n);

      expect(educationalSchemas).to.have.lengthOf(1);
      expect(educationalSchemas).to.include(2n);
    });

    it("Should check schema existence", async function () {
      expect(await schemaRegistry.schemaExists(1)).to.be.true;
      expect(await schemaRegistry.schemaExists(999)).to.be.false;
    });

    it("Should return total schema count", async function () {
      expect(await schemaRegistry.getTotalSchemaCount()).to.equal(3);
    });
  });

  describe("Schema Validation", function () {
    it("Should fail to get invalid schema ID", async function () {
      await expect(
        schemaRegistry.getSchema(999)
      ).to.be.revertedWith("Invalid schema ID");
    });

    it("Should fail to update invalid schema ID", async function () {
      await expect(
        schemaRegistry.connect(issuer1).updateSchema(
          999,
          "Description",
          "Hash",
          "1.0.0",
          []
        )
      ).to.be.revertedWith("Invalid schema ID");
    });

    it("Should fail to deactivate invalid schema ID", async function () {
      await expect(
        schemaRegistry.connect(issuer1).deactivateSchema(999)
      ).to.be.revertedWith("Invalid schema ID");
    });
  });
});