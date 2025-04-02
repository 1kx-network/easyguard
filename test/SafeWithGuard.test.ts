import { expect } from "chai";
import { deployments } from "hardhat";
import Safe, {
  ContractNetworksConfig,
  PredictedSafeProps,
    SafeAccountConfig,
    SafeFactory,
  SafeDeploymentConfig
} from '@safe-global/protocol-kit';
import hre from "hardhat";
import { WalletClient, PublicClient, zeroAddress, parseEther, encodeFunctionData, decodeEventLog, getContract, toHex, concat, keccak256 } from "viem";
import { hardhat } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
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
            provider: walletClient.transport,
            safeAddress,
            contractNetworks,
        });

        const EasyGuardDeployment = await deployments.get("EasyGuard");
        easyGuardAddress = EasyGuardDeployment.address as `0x${string}`;

        console.log("EasyGuard deployed at:", easyGuardAddress);
    });

    it("Should deploy a Safe, enable guard, and execute transactions", async function () {
        expect(await safe.isSafeDeployed()).to.be.true;

        // 2. Fund the safe
        await walletClient.sendTransaction({
            to: safeAddress,
            value: BigInt(1_000_000_000_000_000_000),
        });

        
        // Verify Safe is set up correctly
        const owners = await safe.getOwners();
        const threshold = await safe.getThreshold();
        expect(owners[0].toLowerCase()).to.equal(namedAccounts.users.toLowerCase());
        expect(threshold).to.equal(1);

        // 3. Enable guard with empty program

        // Empty program bytecode (just returns true)
        const emptyProgram = "0x60806040526000805460ff1916905534801561001a57600080fd5b5061027d806100296000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806384b0196e14610030575b600080fd5b61004361003e3660046101a8565b610055565b604051901515815260200160405180910390f35b60008054610100900460ff16156100755750600054610100900460ff1690506101a3565b60008054610100900460ff16158015610094575060005460ff166001145b156100a3576001600160ff19565b8281148015906100b35750600084115b156100c8576001600160ff1916176000555b6001805460208501356000146100e557828551101561010557610105565b6040516000906100f59061017c565b9081526020016040518091039020541461010557610105565b506001600160ff19161790556001805460408501356000146101505782835110156101345750505050600161010090046001600160ff1916178155919050565b600061014082860161021c565b5161014a91906101fc565b1415610170575050506001610100900460ff16600160ff19161790555b50506001610100900460ff1616156101905750600054610100900460ff165b50506001610100900460ff161690505b92915050565b6000806000606084860312156101bd57600080fd5b833567ffffffffffffffff8111156101d457600080fd5b6101e086828701610248565b9660208601359650604086013596939550919350505050565b602080825281016001600160a01b03841681835280604085015280856060860137600060608385010152600060608285010152600060608185015250601f909101601f19168301905092915050565b60006060828403121561022e57600080fd5b50919050565b634e487b7160e01b600052604160045260246000fd5b600080600060608486031215610245600084fd5b833567ffffffffffffffff81111561025d57600080fd5b84016060818703121561026f57600080fd5b94935050505056";

        // Enable guard via delegate call
        const enableGuardData = encodeFunctionData({
            abi: GUARD_ABI,
            functionName: 'enableGuard',
            args: [easyGuardAddress, emptyProgram, false]
        });

        const transactions: MetaTransactionData[] = [
            {
                to: safeAddress,
                data: enableGuardData,
                value: "0x0",
                operation: OperationType.DelegateCall,
            },
        ];

        const safeTransaction = await safe.createTransaction({ transactions });
        expect(await safe.isSafeDeployed()).to.be.true;

        const txResponse = await safe.executeTransaction(safeTransaction);
        await txResponse.transactionResponse?.wait();

        // Check that guard is properly set
        const guardAddress = await safe.getGuard();
        expect(guardAddress.toLowerCase()).to.equal(easyGuardAddress.toLowerCase());

        // // 4. Execute a test transaction through the Safe
        // const transferAmount = parseEther("0.1");

        // // Create transaction to transfer ETH to the deployer
        // const transferNonce = await safe.read.nonce();

        // // Get transaction hash
        // const transferTxHash = await safe.read.getTransactionHash([
        //     namedAccounts.deployer, // to
        //     transferAmount, // value
        //     "0x", // data
        //     0n, // operation (0 = Call)
        //     0n, // safeTxGas
        //     0n, // baseGas
        //     0n, // gasPrice
        //     "0x0000000000000000000000000000000000000000", // gasToken
        //     "0x0000000000000000000000000000000000000000", // refundReceiver
        //     transferNonce // nonce
        // ]);

        // // Sign the transaction
        // const transferSignature = await walletClient.signMessage({
        //     message: { raw: transferTxHash },
        //     account: namedAccounts.users as `0x${string}`,
        // });

        // // Format the signature as expected by Safe (address + signature)
        // // Get the r, s, v values from the signature
        // const transferR = transferSignature.slice(0, 66);
        // const transferS = '0x' + transferSignature.slice(66, 130);
        // const transferV = parseInt(transferSignature.slice(130, 132), 16);
        
        // // Convert to Safe's signature format (65 bytes)
        // const transferAdjustedV = (transferV + 4).toString(16).padStart(2, '0'); // Add 4 to v as per Safe docs
        // const transferAdjustedSignature = transferR + transferS.slice(2) + transferAdjustedV;

        // // Execute the transfer transaction
        // const transferExecTx = await safe.write.execTransaction([
        //     namedAccounts.deployer, // to
        //     transferAmount, // value
        //     "0x", // data
        //     0n, // operation (0 = Call)
        //     0n, // safeTxGas
        //     0n, // baseGas
        //     0n, // gasPrice
        //     "0x0000000000000000000000000000000000000000", // gasToken
        //     "0x0000000000000000000000000000000000000000", // refundReceiver
        //     transferAdjustedSignature // signatures
        // ]);

        // await publicClient.waitForTransactionReceipt({ hash: transferExecTx });
        // console.log("Test transaction executed successfully");

        // // Verify transaction executed correctly by checking the safe's balance
        // const safeBalance = await publicClient.getBalance({
        //     address: safeAddress,
        // });

        // console.log("Safe balance after transfer:", safeBalance);

        // // Expect that balance reduced by transfer amount plus gas
        // expect(safeBalance < parseEther("0.9")).to.be.true;
        // expect(safeBalance > parseEther("0.8")).to.be.true;
    });
});
