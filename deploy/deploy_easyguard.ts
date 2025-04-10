import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, getNamedAccounts } = hre;
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  await deploy("EasyGuard", {
    from: deployer,
    args: [],
    log: true,
    autoMine: true,
  });
};

func.tags = ["EasyGuard"];
export default func;