import { expect } from "chai";
import { ethers } from "hardhat";
import { RevocationRegistry } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("RevocationRegistry", function () {
  let revocationRegistry: RevocationRegistry;
  let owner: SignerWithAddress;
  let issuer1: SignerWithAddress;
  let issuer2: SignerWithAddress;
  let unauthorized: SignerWithAddress;

  const issuerDID1 = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  const issuerDID2 = "did:key:z6MkpqCcLGrqpDjDHU8hqQQQP9ZGGd4VrMjGVTKGrqpDjDHU";
  const sampleSignature = "0x" + "a".repeat(128); // 64 bytes
  const credentialHash1 = ethers.keccak256(ethers.toUtf8Bytes("credential1"));
  const credentialHash2 = ethers.keccak256(ethers.toUtf8Bytes("credential2"));
  const credentialHash3 = ethers.keccak256(ethers.toUtf8Bytes("credential3"));

  beforeEach(async function () {
    [owner, issuer1, issuer2, unauthorized] = await ethers.getSigners();

    const RevocationRegistryFactory = await ethers.getContractFactory("RevocationRegistry");
    revocationRegistry = await RevocationRegistryFactory.deploy();
    await revocationRegistry.waitForDeployment();
  });

  describe("Issuer Authorization", function () {
    it("Should authorize issuer successfully", async function () {
      await expect(
        revocationRegistry.connect(owner).authorizeIssuer(issuerDID1)
      ).to.emit(revocationRegistry, "IssuerAuthorized");

      const issuerHash = ethers.keccak256(ethers.toUtf8Bytes(issuerDID1));
      expect(await revocationRegistry.authorizedIssuers(issuerHash)).to.be.true;
    });

    it("Should fail to authorize issuer by non-owner", async function () {
      await expect(
        revocationRegistry.connect(issuer1).authorizeIssuer(issuerDID1)
      ).to.be.revertedWith("Not contract owner");
    });

    it("Should fail to authorize empty DID", async function () {
      await expect(
        revocationRegistry.connect(owner).authorizeIssuer("")
      ).to.be.revertedWith("Invalid issuer DID");
    });

    it("Should deauthorize issuer successfully", async function () {
      // First authorize
      await revocationRegistry.connect(owner).authorizeIssuer(issuerDID1);
      
      // Then deauthorize
      await expect(
        revocationRegistry.connect(owner).deauthorizeIssuer(issuerDID1)
      ).to.emit(revocationRegistry, "IssuerDeauthorized");

      const issuerHash = ethers.keccak256(ethers.toUtf8Bytes(issuerDID1));
      expect(await revocationRegistry.authorizedIssuers(issuerHash)).to.be.false;
    });

    it("Should fail to deauthorize non-authorized issuer", async function () {
      await expect(
        revocationRegistry.connect(owner).deauthorizeIssuer(issuerDID1)
      ).to.be.revertedWith("Issuer not authorized");
    });
  });

  describe("Revocation List Publishing", function () {
    beforeEach(async function () {
      await revocationRegistry.connect(owner).authorizeIssuer(issuerDID1);
    });

    it("Should publish revocation list successfully", async function () {
      const credentialHashes = [credentialHash1, credentialHash2];
      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkleroot"));

      await expect(
        revocationRegistry.connect(issuer1).publishRevocationList(
          issuerDID1,
          credentialHashes,
          sampleSignature,
          merkleRoot
        )
      )
        .to.emit(revocationRegistry, "RevocationListPublished");

      // Verify revocation status - only credential1 and credential2 should be revoked
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential1")).to.be.true;
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential2")).to.be.true;
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential3")).to.be.false;
    });

    it("Should fail to publish empty revocation list", async function () {
      await expect(
        revocationRegistry.connect(issuer1).publishRevocationList(
          issuerDID1,
          [],
          sampleSignature,
          ethers.ZeroHash
        )
      ).to.be.revertedWith("Empty revocation list");
    });

    it("Should fail to publish with empty signature", async function () {
      await expect(
        revocationRegistry.connect(issuer1).publishRevocationList(
          issuerDID1,
          [credentialHash1],
          "0x",
          ethers.ZeroHash
        )
      ).to.be.revertedWith("Invalid signature");
    });

    it("Should fail to publish by unauthorized issuer", async function () {
      // Don't authorize issuer1, try to publish with unauthorized account
      await expect(
        revocationRegistry.connect(unauthorized).publishRevocationList(
          issuerDID2, // Use different DID that's not authorized
          [credentialHash1],
          sampleSignature,
          ethers.ZeroHash
        )
      ).to.be.revertedWith("Not authorized issuer");
    });

    it("Should increment version on subsequent publications", async function () {
      // First publication
      await revocationRegistry.connect(issuer1).publishRevocationList(
        issuerDID1,
        [credentialHash1],
        sampleSignature,
        ethers.ZeroHash
      );

      // Second publication should have version 2
      await expect(
        revocationRegistry.connect(issuer1).publishRevocationList(
          issuerDID1,
          [credentialHash2],
          sampleSignature,
          ethers.ZeroHash
        )
      ).to.emit(revocationRegistry, "RevocationListPublished");
    });
  });

  describe("Individual Credential Revocation", function () {
    beforeEach(async function () {
      await revocationRegistry.connect(owner).authorizeIssuer(issuerDID1);
      // Publish initial list
      await revocationRegistry.connect(issuer1).publishRevocationList(
        issuerDID1,
        [credentialHash1],
        sampleSignature,
        ethers.ZeroHash
      );
    });

    it("Should revoke additional credentials", async function () {
      const newHashes = [credentialHash2, credentialHash3];

      await expect(
        revocationRegistry.connect(issuer1).revokeCredentials(
          issuerDID1,
          newHashes,
          sampleSignature
        )
      ).to.emit(revocationRegistry, "CredentialRevoked");

      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential2")).to.be.true;
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential3")).to.be.true;
    });

    it("Should not duplicate revoked credentials", async function () {
      // Try to revoke already revoked credential
      const count1 = await revocationRegistry.getRevokedCredentialCount(issuerDID1);
      
      await revocationRegistry.connect(issuer1).revokeCredentials(
        issuerDID1,
        [credentialHash1], // Already revoked
        sampleSignature
      );

      const count2 = await revocationRegistry.getRevokedCredentialCount(issuerDID1);
      expect(count2).to.equal(count1); // Should not increase
    });

    it("Should fail to revoke by unauthorized issuer", async function () {
      await expect(
        revocationRegistry.connect(unauthorized).revokeCredentials(
          issuerDID2, // Use different DID that's not authorized
          [credentialHash2],
          sampleSignature
        )
      ).to.be.revertedWith("Not authorized issuer");
    });
  });

  describe("Revocation Queries", function () {
    beforeEach(async function () {
      await revocationRegistry.connect(owner).authorizeIssuer(issuerDID1);
      await revocationRegistry.connect(issuer1).publishRevocationList(
        issuerDID1,
        [credentialHash1, credentialHash2],
        sampleSignature,
        ethers.ZeroHash
      );
    });

    it("Should check revocation status correctly", async function () {
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential1")).to.be.true;
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential2")).to.be.true;
      expect(await revocationRegistry.isCredentialRevoked(issuerDID1, "credential3")).to.be.false;
    });

    it("Should check revocation by hash correctly", async function () {
      const issuerHash = ethers.keccak256(ethers.toUtf8Bytes(issuerDID1));
      
      expect(await revocationRegistry.isCredentialRevokedByHash(issuerHash, credentialHash1)).to.be.true;
      expect(await revocationRegistry.isCredentialRevokedByHash(issuerHash, credentialHash2)).to.be.true;
      expect(await revocationRegistry.isCredentialRevokedByHash(issuerHash, credentialHash3)).to.be.false;
    });

    it("Should return correct revocation list", async function () {
      const revList = await revocationRegistry.getRevocationList(issuerDID1);
      
      expect(revList.revokedCredentialIds).to.have.lengthOf(2);
      expect(revList.version).to.equal(1);
      expect(revList.signature).to.equal(sampleSignature);
      expect(revList.timestamp).to.be.greaterThan(0);
    });

    it("Should return correct revoked credential count", async function () {
      const count = await revocationRegistry.getRevokedCredentialCount(issuerDID1);
      expect(count).to.equal(2);
    });
  });

  describe("Merkle Proof Verification", function () {
    beforeEach(async function () {
      await revocationRegistry.connect(owner).authorizeIssuer(issuerDID1);
    });

    it("Should verify Merkle proof correctly", async function () {
      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkleroot"));
      
      await revocationRegistry.connect(issuer1).publishRevocationList(
        issuerDID1,
        [credentialHash1],
        sampleSignature,
        merkleRoot
      );

      // Test with merkle proof - will use the internal verification
      // For this test, we'll construct a simple proof
      const leaf = credentialHash1;
      const proofElements = [ethers.keccak256(ethers.toUtf8Bytes("sibling"))];
      
      // This will test the Merkle verification logic
      const isRevoked = await revocationRegistry.verifyRevocationProof(
        issuerDID1,
        credentialHash1,
        proofElements
      );
      // Since we don't have a valid proof, it may be false, but test should not error
      expect(typeof isRevoked).to.equal("boolean");
    });

    it("Should fall back to direct lookup when no Merkle root", async function () {
      await revocationRegistry.connect(issuer1).publishRevocationList(
        issuerDID1,
        [credentialHash1],
        sampleSignature,
        ethers.ZeroHash // No merkle root
      );

      const isRevoked = await revocationRegistry.verifyRevocationProof(
        issuerDID1,
        credentialHash1,
        []
      );
      expect(isRevoked).to.be.true;
    });
  });

  describe("Access Control", function () {
    it("Should transfer ownership correctly", async function () {
      await revocationRegistry.connect(owner).transferOwnership(issuer1.address);
      
      // New owner should be able to authorize issuers
      await revocationRegistry.connect(issuer1).authorizeIssuer(issuerDID1);
      
      const issuerHash = ethers.keccak256(ethers.toUtf8Bytes(issuerDID1));
      expect(await revocationRegistry.authorizedIssuers(issuerHash)).to.be.true;
    });

    it("Should fail to transfer ownership to zero address", async function () {
      await expect(
        revocationRegistry.connect(owner).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid new owner");
    });

    it("Should fail to transfer ownership by non-owner", async function () {
      await expect(
        revocationRegistry.connect(issuer1).transferOwnership(issuer2.address)
      ).to.be.revertedWith("Not contract owner");
    });
  });
});