import fs from "node:fs";
import path from "node:path";
import { network } from "hardhat";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const { ethers } = await network.getOrCreate();
  const [deployer] = await ethers.getSigners();
  const registry = await ethers.deployContract("ThreatRegistry");
  await registry.waitForDeployment();

  const networkDetails = await ethers.provider.getNetwork();
  const deployment = {
    contractAddress: await registry.getAddress(),
    chainId: networkDetails.chainId.toString(),
    deployerAddress: deployer.address
  };
  const outputDirectory = path.join(scriptDirectory, "..", "deployments");
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(
    path.join(outputDirectory, "localhost.json"),
    `${JSON.stringify(deployment, null, 2)}\n`,
    "utf8"
  );
  console.log(JSON.stringify(deployment));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
