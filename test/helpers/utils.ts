import hre from "hardhat";

export const getContractDeployedCode = async(contractName: string) => {
    const artifact = await hre.artifacts.readArtifact(contractName);

    return artifact.deployedBytecode;
}