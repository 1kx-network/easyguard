import { expect } from "chai";
// import "@nomicfoundation/hardhat-chai-matchers";
import { deployments } from "hardhat";
import Safe, {
    ContractNetworksConfig,
    PredictedSafeProps,
    SafeAccountConfig,
} from '@safe-global/protocol-kit';
import hre from "hardhat";
import { WalletClient, PublicClient, zeroAddress, parseEther, encodeFunctionData, toHex, fromHex, concatHex } from "viem";
import { MetaTransactionData, OperationType } from "@safe-global/types-kit";
import EasyGuardArtifact from "../artifacts/contracts/Guard.sol/EasyGuard.json";

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

    describe("Direct code verification", function () {


        it("Should verify a program that only returns true", async function() {
            const easyGuard = await hre.viem.getContractAt(
                "EasyGuard",
                easyGuardAddress);
             // Empty program bytecode (just returns true)
             const trueProgram = "0x60205f80158152f3";

             let result = await easyGuard.read.checkEvmByteCode([trueProgram]);
             expect(result).to.be.true;
         });

         it("Should verify a program that only returns false", async function() {
             const easyGuard = await hre.viem.getContractAt(
                 "EasyGuard",
                 easyGuardAddress);
             // Empty program bytecode (just returns false)
             const falseProgram = "0x60205f808052f300";
             let result = await easyGuard.read.checkEvmByteCode([falseProgram]);
             expect(result).to.be.true;
         });

        describe("Should accept allowed instructions", function() {
            async function checkAccept(instruction) {
                const stackfillers = '0x600180808080808080808080808080808080';
                const program = concatHex([
                    stackfillers,
                    instruction.startsWith('0x') ? instruction : `0x${instruction}`
                ]);
                const easyGuard = await hre.viem.getContractAt(
                    "EasyGuard",
                    easyGuardAddress);
                let result = await easyGuard.read.checkEvmByteCode([program]);
                expect(result).to.be.true;
            }

            it("STOP", async function() { await checkAccept("0x00"); });
            it("ADD", async function() { await checkAccept("0x01"); });
            it("MUL", async function() { await checkAccept("0x02"); });
            it("SUB", async function() { await checkAccept("0x03"); });
            it("DIV", async function() { await checkAccept("0x04"); });
            it("SDIV", async function() { await checkAccept("0x05"); });
            it("MOD", async function() { await checkAccept("0x06"); });
            it("SMOD", async function() { await checkAccept("0x07"); });
            it("ADDMOD", async function() { await checkAccept("0x08"); });
            it("MULMOD", async function() { await checkAccept("0x09"); });
            it("EXP", async function() { await checkAccept("0x0A"); });
            it("SIGNEXTEND", async function() { await checkAccept("0x0B"); });
        });

        describe("Should reject programs with forbidden instructions", function() {
            async function checkReject(instruction) {
                const stackfillers = '0x5F5F5F5F5F';
                const program = concatHex([
                    stackfillers,
                    instruction.startsWith('0x') ? instruction : `0x${instruction}`
                ]);
                const easyGuard = await hre.viem.getContractAt(
                    "EasyGuard",
                    easyGuardAddress);
                await expect(easyGuard.read.checkEvmByteCode([program])).to.be.rejected;
            }
            it("0x0C", async function() { await checkReject("0x0C"); });
            it("0x0D", async function() { await checkReject("0x0D"); });
            it("0x0E", async function() { await checkReject("0x0E"); });
            it("0x0F", async function() { await checkReject("0x0F"); });
            it("0x1E", async function() { await checkReject("0x1E"); });
            it("0x1F", async function() { await checkReject("0x1F"); });

            it("EXTCODESIZE", async function() { await checkReject("0x3B"); });
            it("EXTCODECOPY", async function() { await checkReject("0x3C"); });
            it("RETURNDATASIZE", async function() { await checkReject("0x3D"); });
            it("RETURNDATACOPY", async function() { await checkReject("0x3E"); });
            it("EXTCODEHASH", async function() { await checkReject("0x3F"); });

            it("BASEFEE", async function() { await checkReject("0x48"); });
            it("BLOBHASH", async function() { await checkReject("0x49"); });
            it("BLOBBASEFEE", async function() { await checkReject("0x4A"); });

            // 0x5C - 0x5D are undefined
            it("TLOAD", async function() { await checkReject("0x5C"); });
            it("TSTORE", async function() { await checkReject("0x5D"); });

            it("LOG0", async function() { await checkReject("0xA0"); });
            it("LOG1", async function() { await checkReject("0xA1"); });
            it("LOG2", async function() { await checkReject("0xA2"); });
            it("LOG3", async function() { await checkReject("0xA3"); });
            it("LOG4", async function() { await checkReject("0xA4"); });
            // 0xA5 - 0xAF are undefined

            for (let instr=0xA5; instr <= 0xEF; instr++) {
                it(toHex(instr), async function() { await checkReject(toHex(instr)); });
            }

            it("CREATE", async function() { await checkReject("0xF0"); });
            it("CALL", async function() { await checkReject("0xF1"); });
            it("CALLCODE", async function() { await checkReject("0xF2"); });
            // F3 is RETURN (allowed)
            it("DELEGATECALL", async function() { await checkReject("0xF4"); });
            it("CREATE2", async function() { await checkReject("0xF5"); });
            // 0xF6 - 0xF9 are undefined
            it("STATICCALL", async function() { await checkReject("0xFA"); });
            // 0xFB - 0xFC are undefined
            // FD is REVERT (allowed)
            it("INVALID", async function() { await checkReject("0xFE"); });
            it("SELFDESTRUCT", async function() { await checkReject("0xFF"); });
        });
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
        const trueProgram = "0x60205f80158152f3";

        // Enable guard via delegate call
        const enableGuardData = encodeFunctionData({
            abi: EasyGuardArtifact.abi,
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

        expect(checkerProgram).to.be.equal(trueProgram);


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

        // Empty program bytecode (just returns false)
        // const falseProgram = "0x600880805f395ff360205f808052f300";
        const falseProgram = "0x60205f808052f300";

        // Enable guard via delegate call
        const enableGuardData = encodeFunctionData({
            abi: EasyGuardArtifact.abi,
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

        expect(checkerProgram).to.be.equal(falseProgram);

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
