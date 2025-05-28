import { expect } from "chai";
import { ethers } from "hardhat";
import { DIDRegistry } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("DIDRegistry", function () {
  let didRegistry: DIDRegistry;
  let owner: SignerWithAddress;
  let addr1: SignerWithAddress;
  let addr2: SignerWithAddress;

  const sampleDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  const samplePublicKey = "0x" + "a".repeat(64); // 32 bytes of 'a'
  const sampleDocumentHash = "QmSomeIPFSHash123";

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();

    const DIDRegistryFactory = await ethers.getContractFactory("DIDRegistry");
    didRegistry = await DIDRegistryFactory.deploy();
    await didRegistry.waitForDeployment();
  });

  describe("DID Registration", function () {
    it("Should register a new DID successfully", async function () {
      await expect(
        didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash)
      ).to.emit(didRegistry, "DIDRegistered");

      const didDoc = await didRegistry.resolveDID(sampleDID);
      expect(didDoc.publicKey).to.equal(samplePublicKey);
      expect(didDoc.owner).to.equal(addr1.address);
      expect(didDoc.active).to.be.true;
      expect(didDoc.documentHash).to.equal(sampleDocumentHash);
    });

    it("Should fail to register DID with invalid public key length", async function () {
      const invalidPublicKey = "0x1234"; // Too short
      
      await expect(
        didRegistry.connect(addr1).registerDID(sampleDID, invalidPublicKey, sampleDocumentHash)
      ).to.be.revertedWith("Invalid public key length");
    });

    it("Should fail to register empty DID", async function () {
      await expect(
        didRegistry.connect(addr1).registerDID("", samplePublicKey, sampleDocumentHash)
      ).to.be.revertedWith("Invalid DID");
    });

    it("Should fail to register DID that already exists", async function () {
      await didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash);
      
      await expect(
        didRegistry.connect(addr2).registerDID(sampleDID, samplePublicKey, sampleDocumentHash)
      ).to.be.revertedWith("DID already exists");
    });

    it("Should fail to register DID that is too long", async function () {
      const longDID = "did:key:" + "a".repeat(250); // Too long
      
      await expect(
        didRegistry.connect(addr1).registerDID(longDID, samplePublicKey, sampleDocumentHash)
      ).to.be.revertedWith("DID too long");
    });
  });

  describe("DID Updates", function () {
    beforeEach(async function () {
      await didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash);
    });

    it("Should update DID public key successfully", async function () {
      const newPublicKey = "0x" + "b".repeat(64);
      const newDocumentHash = "QmNewIPFSHash456";

      await expect(
        didRegistry.connect(addr1).updateDID(sampleDID, newPublicKey, newDocumentHash)
      ).to.emit(didRegistry, "DIDUpdated");

      const didDoc = await didRegistry.resolveDID(sampleDID);
      expect(didDoc.publicKey).to.equal(newPublicKey);
      expect(didDoc.documentHash).to.equal(newDocumentHash);
    });

    it("Should fail to update DID by non-owner", async function () {
      const newPublicKey = "0x" + "b".repeat(64);
      
      await expect(
        didRegistry.connect(addr2).updateDID(sampleDID, newPublicKey, "hash")
      ).to.be.revertedWith("Not DID owner");
    });

    it("Should fail to update DID with invalid public key length", async function () {
      const invalidPublicKey = "0x1234";
      
      await expect(
        didRegistry.connect(addr1).updateDID(sampleDID, invalidPublicKey, "hash")
      ).to.be.revertedWith("Invalid public key length");
    });
  });

  describe("DID Deactivation", function () {
    beforeEach(async function () {
      await didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash);
    });

    it("Should deactivate DID successfully", async function () {
      await expect(
        didRegistry.connect(addr1).deactivateDID(sampleDID)
      ).to.emit(didRegistry, "DIDDeactivated");

      await expect(
        didRegistry.resolveDID(sampleDID)
      ).to.be.revertedWith("DID not found or deactivated");

      expect(await didRegistry.didExists(sampleDID)).to.be.false;
    });

    it("Should fail to deactivate DID by non-owner", async function () {
      await expect(
        didRegistry.connect(addr2).deactivateDID(sampleDID)
      ).to.be.revertedWith("Not DID owner");
    });

    it("Should fail to update deactivated DID", async function () {
      await didRegistry.connect(addr1).deactivateDID(sampleDID);
      
      await expect(
        didRegistry.connect(addr1).updateDID(sampleDID, samplePublicKey, "hash")
      ).to.be.revertedWith("DID is deactivated");
    });
  });

  describe("DID Transfer", function () {
    beforeEach(async function () {
      await didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash);
    });

    it("Should transfer DID ownership successfully", async function () {
      await expect(
        didRegistry.connect(addr1).transferDID(sampleDID, addr2.address)
      ).to.emit(didRegistry, "DIDTransferred");

      const didDoc = await didRegistry.resolveDID(sampleDID);
      expect(didDoc.owner).to.equal(addr2.address);

      // Check that addr2 is now in the owner's DID list
      const addr2DIDs = await didRegistry.getDIDsByOwner(addr2.address);
      expect(addr2DIDs).to.include(sampleDID);
    });

    it("Should fail to transfer to zero address", async function () {
      await expect(
        didRegistry.connect(addr1).transferDID(sampleDID, ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid new owner");
    });

    it("Should fail to transfer to same owner", async function () {
      await expect(
        didRegistry.connect(addr1).transferDID(sampleDID, addr1.address)
      ).to.be.revertedWith("Already owner");
    });

    it("Should fail to transfer by non-owner", async function () {
      await expect(
        didRegistry.connect(addr2).transferDID(sampleDID, addr2.address)
      ).to.be.revertedWith("Not DID owner");
    });
  });

  describe("DID Query Functions", function () {
    beforeEach(async function () {
      await didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash);
      await didRegistry.connect(addr1).registerDID(sampleDID + "2", samplePublicKey, sampleDocumentHash);
    });

    it("Should return correct DID count for owner", async function () {
      const count = await didRegistry.getDIDCountByOwner(addr1.address);
      expect(count).to.equal(2);
    });

    it("Should return all DIDs for owner", async function () {
      const dids = await didRegistry.getDIDsByOwner(addr1.address);
      expect(dids).to.have.lengthOf(2);
      expect(dids).to.include(sampleDID);
      expect(dids).to.include(sampleDID + "2");
    });

    it("Should check DID existence correctly", async function () {
      expect(await didRegistry.didExists(sampleDID)).to.be.true;
      expect(await didRegistry.didExists("nonexistent")).to.be.false;
    });
  });

  describe("DID Resolution", function () {
    beforeEach(async function () {
      await didRegistry.connect(addr1).registerDID(sampleDID, samplePublicKey, sampleDocumentHash);
    });

    it("Should resolve DID correctly", async function () {
      const didDoc = await didRegistry.resolveDID(sampleDID);
      
      expect(didDoc.publicKey).to.equal(samplePublicKey);
      expect(didDoc.owner).to.equal(addr1.address);
      expect(didDoc.active).to.be.true;
      expect(didDoc.documentHash).to.equal(sampleDocumentHash);
      expect(didDoc.created).to.be.greaterThan(0);
      expect(didDoc.updated).to.be.greaterThan(0);
    });

    it("Should fail to resolve nonexistent DID", async function () {
      await expect(
        didRegistry.resolveDID("nonexistent")
      ).to.be.revertedWith("DID not found or deactivated");
    });
  });
});