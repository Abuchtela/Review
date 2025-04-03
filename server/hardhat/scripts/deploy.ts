import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying contracts with the account: ${deployer.address}`);
  
  // Deploy OptimismPortalMock
  const OptimismPortalMock = await ethers.getContractFactory("OptimismPortalMock");
  const portalMock = await OptimismPortalMock.deploy();
  await portalMock.deployed();
  console.log(`OptimismPortalMock deployed to: ${portalMock.address}`);
  
  // Deploy L1CrossDomainMessenger
  const VulnerableMessenger = await ethers.getContractFactory("VulnerableL1CrossDomainMessenger");
  const messenger = await VulnerableMessenger.deploy(portalMock.address);
  await messenger.deployed();
  console.log(`VulnerableL1CrossDomainMessenger deployed to: ${messenger.address}`);
  
  // Deploy other contracts based on needs
  console.log("Base contracts deployed successfully");
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

export default main;
