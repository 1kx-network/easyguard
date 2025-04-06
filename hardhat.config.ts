import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";
import "hardhat-deploy";

const config: HardhatUserConfig = {
    solidity: {
        version: "0.8.28",
        settings: {
            optimizer: {
                enabled: true,
                runs: 200,
            },
        },
    },
    networks: {
        hardhat: {
            // For hardhat testing
            saveDeployments: true,
        }
    },
    namedAccounts: {
        deployer: {
            default: 0, // The first account is the deployer
        },
        users: {
            default: 1,
        },
    },
    paths: {
        deploy: "deploy",
    },
    mocha: {
        parallel: false,
        asyncOnly: true
    },
};

export default config;
