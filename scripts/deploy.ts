import { ethers } from "hardhat";
import * as fs from 'fs';
import * as path from 'path';

async function main() {
  console.log("Deploying contracts to", await ethers.provider.getNetwork());

  // Get deployer account
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", ethers.formatEther(await deployer.provider.getBalance(deployer.address)));

  // Deploy DID Registry
  console.log("\n1. Deploying DID Registry...");
  const DIDRegistryFactory = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistryFactory.deploy();
  await didRegistry.waitForDeployment();
  const didRegistryAddress = await didRegistry.getAddress();
  console.log("DID Registry deployed to:", didRegistryAddress);

  // Deploy Revocation Registry
  console.log("\n2. Deploying Revocation Registry...");
  const RevocationRegistryFactory = await ethers.getContractFactory("RevocationRegistry");
  const revocationRegistry = await RevocationRegistryFactory.deploy();
  await revocationRegistry.waitForDeployment();
  const revocationRegistryAddress = await revocationRegistry.getAddress();
  console.log("Revocation Registry deployed to:", revocationRegistryAddress);

  // Deploy Schema Registry
  console.log("\n3. Deploying Schema Registry...");
  const SchemaRegistryFactory = await ethers.getContractFactory("SchemaRegistry");
  const schemaRegistry = await SchemaRegistryFactory.deploy();
  await schemaRegistry.waitForDeployment();
  const schemaRegistryAddress = await schemaRegistry.getAddress();
  console.log("Schema Registry deployed to:", schemaRegistryAddress);

  // Create deployment configuration
  const network = await ethers.provider.getNetwork();
  const deploymentConfig = {
    network: {
      name: network.name,
      chainId: Number(network.chainId),
    },
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
    contracts: {
      didRegistry: didRegistryAddress,
      revocationRegistry: revocationRegistryAddress,
      schemaRegistry: schemaRegistryAddress,
    },
    gasUsed: {
      didRegistry: "TBD", // Would need to track actual gas used
      revocationRegistry: "TBD",
      schemaRegistry: "TBD",
    }
  };

  // Save deployment configuration
  const deploymentsDir = path.join(__dirname, '..', 'deployments');
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const configFileName = `deployment-${network.name}-${Date.now()}.json`;
  const configPath = path.join(deploymentsDir, configFileName);
  
  fs.writeFileSync(configPath, JSON.stringify(deploymentConfig, null, 2));
  console.log(`\nDeployment configuration saved to: ${configPath}`);

  // Also save as latest deployment for this network
  const latestConfigPath = path.join(deploymentsDir, `latest-${network.name}.json`);
  fs.writeFileSync(latestConfigPath, JSON.stringify(deploymentConfig, null, 2));
  console.log(`Latest deployment config saved to: ${latestConfigPath}`);

  console.log("\n🎉 All contracts deployed successfully!");
  console.log("\nContract Addresses:");
  console.log("==================");
  console.log("DID Registry:       ", didRegistryAddress);
  console.log("Revocation Registry:", revocationRegistryAddress);
  console.log("Schema Registry:    ", schemaRegistryAddress);

  console.log("\nNext steps:");
  console.log("1. Verify contracts on block explorer (if on testnet/mainnet)");
  console.log("2. Update your application configuration with these addresses");
  console.log("3. Test the deployment with the provided scripts");

  return deploymentConfig;
}

// Run deployment
main()
  .then((config) => {
    console.log("\nDeployment completed successfully");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Deployment failed:");
    console.error(error);
    process.exit(1);
  });