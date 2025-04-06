import { expect } from "chai";
// import "@nomicfoundation/hardhat-chai-matchers";
import { deployments } from "hardhat";
import Safe, {
    ContractNetworksConfig,
    PredictedSafeProps,
    SafeAccountConfig,
} from '@safe-global/protocol-kit';
import hre from "hardhat";
import { WalletClient, PublicClient, zeroAddress, parseEther, encodeFunctionData, toHex} from "viem";
import { MetaTransactionData, OperationType } from "@safe-global/types-kit";

// Safe ABI fragments we need
const SAFE_FACTORY_ABI = [
    {
        type: 'function',
        name: 'createProxyWithNonce',
        inputs: [
            { type: 'address', name: '_singleton' },
            { type: 'bytes', name: 'initializer' },
            { type: 'uint256', name: 'saltNonce' }
        ],
        outputs: [{ type: 'address', name: 'proxy' }],
        stateMutability: 'nonpayable'
    },
    {
        type: 'event',
        name: 'ProxyCreation',
        inputs: [{ type: 'address', indexed: false, name: 'proxy' }],
        anonymous: false
    }
];

const SAFE_ABI = [
    {
        type: 'function',
        name: 'setup',
        inputs: [
            { type: 'address[]', name: '_owners' },
            { type: 'uint256', name: '_threshold' },
            { type: 'address', name: 'to' },
            { type: 'bytes', name: 'data' },
            { type: 'address', name: 'fallbackHandler' },
            { type: 'address', name: 'paymentToken' },
            { type: 'uint256', name: 'payment' },
            { type: 'address', name: 'paymentReceiver' }
        ],
        outputs: [],
        stateMutability: 'nonpayable'
    },
    {
        type: 'function',
        name: 'getThreshold',
        inputs: [],
        outputs: [{ type: 'uint256' }],
        stateMutability: 'view'
    },
    {
        type: 'function',
        name: 'getOwners',
        inputs: [],
        outputs: [{ type: 'address[]' }],
        stateMutability: 'view'
    },
    {
        type: 'function',
        name: 'execTransaction',
        inputs: [
            { type: 'address', name: 'to' },
            { type: 'uint256', name: 'value' },
            { type: 'bytes', name: 'data' },
            { type: 'uint8', name: 'operation' },
            { type: 'uint256', name: 'safeTxGas' },
            { type: 'uint256', name: 'baseGas' },
            { type: 'uint256', name: 'gasPrice' },
            { type: 'address', name: 'gasToken' },
            { type: 'address', name: 'refundReceiver' },
            { type: 'bytes', name: 'signatures' }
        ],
        outputs: [{ type: 'bool', name: 'success' }],
        stateMutability: 'payable'
    },
    {
        type: 'function',
        name: 'getTransactionHash',
        inputs: [
            { type: 'address', name: 'to' },
            { type: 'uint256', name: 'value' },
            { type: 'bytes', name: 'data' },
            { type: 'uint8', name: 'operation' },
            { type: 'uint256', name: 'safeTxGas' },
            { type: 'uint256', name: 'baseGas' },
            { type: 'uint256', name: 'gasPrice' },
            { type: 'address', name: 'gasToken' },
            { type: 'address', name: 'refundReceiver' },
            { type: 'uint256', name: 'nonce' }
        ],
        outputs: [{ type: 'bytes32' }],
        stateMutability: 'view'
    },
    {
        type: 'function',
        name: 'nonce',
        inputs: [],
        outputs: [{ type: 'uint256' }],
        stateMutability: 'view'
    },
    {
        type: 'function',
        name: 'getGuard',
        inputs: [],
        outputs: [{ type: 'address' }],
        stateMutability: 'view'
    },
    {
        type: 'function',
        name: 'setGuard',
        inputs: [{ type: 'address', name: 'guard' }],
        outputs: [],
        stateMutability: 'nonpayable'
    }
];

const GUARD_ABI = [
    {
        type: 'function',
        name: 'setCheckerProgram',
        inputs: [
            { type: 'address', name: 'safe' },
            { type: 'bytes', name: 'newChecker' },
            { type: 'bool', name: '_disableLockoutCheck' }
        ],
        outputs: [],
        stateMutability: 'nonpayable'
    },
    {
        type: 'function',
        name: 'enableGuard',
        inputs: [
            { type: 'address', name: 'guard' },
            { type: 'bytes', name: 'program' },
            { type: 'bool', name: '_disableLockoutCheck' }
        ],
        outputs: [],
        stateMutability: 'nonpayable'
    }
];

describe("Safe with Guard", function () {
    let namedAccounts: { [name: string]: string };
    let accounts: WalletClient[];
    let safeAddress: `0x${string}`;
    let easyGuardAddress: `0x${string}`;

    let publicClient: PublicClient;
    let walletClient: WalletClient;
    let usersWalletClient: WalletClient;

    let safe: Safe;

    before(async function () {
        await deployments.fixture();

        // Get deployer account
        accounts = await hre.viem.getWalletClients();
        publicClient = await hre.viem.getPublicClient();

        // Configure for consistent gas estimation
        const originalEstimateGas = publicClient.estimateGas;
        publicClient.estimateGas = async (args: any) => {
            // Use a cached/fixed value for gas estimation
            return BigInt("0x1000000");
        };

        namedAccounts = await hre.getNamedAccounts();
        walletClient = accounts[0];
        usersWalletClient = accounts[1];

        const deployedSafe = await deployments.get("SafeL2");
        const deployedSafeFactory = await deployments.get("SafeProxyFactory");
        const deployedMultiSend = await deployments.get("MultiSend");
        const deployedMultiSendCallOnly = await deployments.get("MultiSendCallOnly");
        const deployedCompatibilityFallbackHandler = await deployments.get("CompatibilityFallbackHandler");
        const deployedSignMessageLib = await deployments.get("SignMessageLib");
        const deployedCreateCall = await deployments.get("CreateCall");
        const chainId: number = walletClient.chain.id;
        const chainIdStr = chainId.toString();
        console.log("chainId: ", chainIdStr);
        const contractNetworks: ContractNetworksConfig = {
            [chainIdStr]: {
                safeSingletonAddress: deployedSafe.address,
                safeProxyFactoryAddress: deployedSafeFactory.address,
                multiSendAddress: deployedMultiSend.address,
                multiSendCallOnlyAddress: deployedMultiSendCallOnly.address,
                fallbackHandlerAddress: deployedCompatibilityFallbackHandler.address,
                signMessageLibAddress: deployedSignMessageLib.address,
                createCallAddress: deployedCreateCall.address,
                simulateTxAccessorAddress: zeroAddress,
                safeWebAuthnSignerFactoryAddress: zeroAddress,
                safeWebAuthnSharedSignerAddress: zeroAddress,
            }
        };


        const safeAccountConfig: SafeAccountConfig =  {
            owners: [namedAccounts.users],
            threshold: 1,
        };
        const predictedSafe: PredictedSafeProps = {
            safeAccountConfig,
        };

        safe = await Safe.init({
            provider: walletClient.transport,
            predictedSafe,
            contractNetworks,
        });

        safeAddress = await safe.getAddress() as `0x${string}`;
        const deploymentTransaction = await safe.createSafeDeploymentTransaction();

        const transactionHash = await walletClient.sendTransaction({
            to: deploymentTransaction.to,
            value: parseEther(deploymentTransaction.value),
            data: deploymentTransaction.data as `0x${string}`,
        });

        const transactionReceipt = await publicClient.waitForTransactionReceipt({
            hash: transactionHash
        });

        expect(transactionReceipt.status).to.be.equal("success");
        console.log("Safe created at: ", safeAddress);
        expect(await safe.isSafeDeployed()).to.be.true;

        // Now when the Safe is deployed, reinitialize protocol-kit Safe wrapper as
        // initialized Safe.
        safe = await Safe.init({
            provider: usersWalletClient.transport,
            signer: usersWalletClient.account.address,
            safeAddress,
            contractNetworks,
        });

        const EasyGuardDeployment = await deployments.get("EasyGuard");
        easyGuardAddress = EasyGuardDeployment.address as `0x${string}`;

        console.log("EasyGuard deployed at:", easyGuardAddress);

        // Verify Safe is set up correctly
        const owners = await safe.getOwners();
        const threshold = await safe.getThreshold();
        expect(owners[0].toLowerCase()).to.equal(namedAccounts.users.toLowerCase());
        expect(threshold).to.equal(1);

    });

    it("Should Enable guard, and execute transactions", async function () {
        expect(await safe.isSafeDeployed()).to.be.true;

        // 2. Fund the safe
        await walletClient.sendTransaction({
            to: safeAddress,
            value: parseEther("1.0"),
        });


        // 3. Enable guard with empty program

        // Empty program bytecode (just returns true)
        const trueProgram = "0x600880805f395ff360205f80158152f3";

        // Enable guard via delegate call
        const enableGuardData = encodeFunctionData({
            abi: GUARD_ABI,
            functionName: 'enableGuard',
            args: [easyGuardAddress, trueProgram, false]
        });

        let transactions: MetaTransactionData[] = [
            {
                to: easyGuardAddress,
                data: enableGuardData,
                value: "0x0",
                operation: OperationType.DelegateCall,
            },
        ];

        let safeTransaction = await safe.createTransaction({ transactions });
        safeTransaction = await safe.signTransaction(safeTransaction);
        let txResponse = await safe.executeTransaction(safeTransaction);
        await txResponse.transactionResponse?.wait();

        // Check that guard is properly set
        const guardAddress = await safe.getGuard();
        expect(guardAddress.toLowerCase()).to.equal(easyGuardAddress.toLowerCase());

        const easyGuard = await hre.viem.getContractAt(
            "EasyGuard",
            easyGuardAddress);

        let checkerProgramAddress = await easyGuard.read.getCheckerProgram([safeAddress]);
        console.log("checker program address: ", checkerProgramAddress);

        let checkerProgram = await publicClient.getCode({address: checkerProgramAddress});
        console.log("checker program: ", checkerProgram);

        expect(checkerProgram.substring(2)).to.be.equal(trueProgram.substring(18));


        // 4. Execute a test transaction through the Safe
        const transferAmount = parseEther("0.1");

        transactions = [
            {
                to: walletClient.account.address,
                data: "0x",
                value: toHex(transferAmount),
            },
        ];
        safeTransaction = await safe.createTransaction({ transactions });
        safeTransaction = await safe.signTransaction(safeTransaction);
        txResponse = await safe.executeTransaction(safeTransaction);
        await txResponse.transactionResponse?.wait();


        // Verify transaction executed correctly by checking the safe's balance
        const safeBalance = await publicClient.getBalance({
            address: safeAddress,
        });

        // Expect that balance reduced by transfer amount
        expect(safeBalance == parseEther("0.9")).to.be.true;
    });

    it("Should Enable false guard, and fail to execute transactions", async function () {
        expect(await safe.isSafeDeployed()).to.be.true;

        // 3. Enable guard with empty program

        // Empty program bytecode (just returns true)
        const falseProgram = "0x600880805f395ff360205f808052f300";

        // Enable guard via delegate call
        const enableGuardData = encodeFunctionData({
            abi: GUARD_ABI,
            functionName: 'enableGuard',
            args: [easyGuardAddress, falseProgram, false]
        });

        let transactions: MetaTransactionData[] = [
            {
                to: easyGuardAddress,
                data: enableGuardData,
                value: "0x0",
                operation: OperationType.DelegateCall,
            },
        ];

        let safeTransaction = await safe.createTransaction({ transactions });
        safeTransaction = await safe.signTransaction(safeTransaction);
        let txResponse = await safe.executeTransaction(safeTransaction);
        await txResponse.transactionResponse?.wait();

        // Check that guard is properly set
        const guardAddress = await safe.getGuard();
        expect(guardAddress.toLowerCase()).to.equal(easyGuardAddress.toLowerCase());

        const easyGuard = await hre.viem.getContractAt(
            "EasyGuard",
            easyGuardAddress);

        let checkerProgramAddress = await easyGuard.read.getCheckerProgram([safeAddress]);
        console.log("checker program address: ", checkerProgramAddress);

        let checkerProgram = await publicClient.getCode({address: checkerProgramAddress});
        console.log("checker program: ", checkerProgram);

        expect(checkerProgram.substring(2)).to.be.equal(falseProgram.substring(18));


        // 4. Execute a test transaction through the Safe
        const transferAmount = parseEther("0.1");

        transactions = [
            {
                to: walletClient.account.address,
                data: "0x",
                value: toHex(transferAmount),
            },
        ];
        safeTransaction = await safe.createTransaction({ transactions });
        safeTransaction = await safe.signTransaction(safeTransaction);
        await expect(
            safe.executeTransaction(safeTransaction)
        ).to.be.rejectedWith("Guard: Transaction verification failed");
    });
});
