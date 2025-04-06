// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import "@safe-global/safe-contracts/contracts/common/SignatureDecoder.sol";
import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/interfaces/IERC165.sol";
import "@safe-global/safe-contracts/contracts/interfaces/ISignatureValidator.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "hardhat/console.sol";

interface GuardProgramVerification {
    struct TransactionContext {
        Safe safe;
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address payable refundReceiver;
        address msgSender;
    }

    function verify(TransactionContext calldata context, address[] calldata owners, address[] calldata signers) external view returns (bool);
}

/**
 * @title Easy Guard
 * @notice This contract is a transaction guard for Safe ^1.3.0
 */
contract EasyGuard is
    BaseGuard,
    SignatureDecoder
{
    mapping(Safe => address) private checkerProgram;
    mapping(Safe => bool) private disableLockoutCheck;
    uint8[256] private opcodeTable;

    uint8 constant VALID_OPCODE = 0x10;  // Bit mask for valid opcodes in opcodeTable

    constructor() {
        // Initialize opcode table
        // Format: (allowed << 4) | (consumed << 2) | produced

        // Stop and arithmetic operations
        opcodeTable[0x00] = 0x10; // STOP: 0/0
        opcodeTable[0x01] = 0x15; // ADD: 2/1
        opcodeTable[0x02] = 0x15; // MUL: 2/1
        opcodeTable[0x03] = 0x15; // SUB: 2/1
        opcodeTable[0x04] = 0x15; // DIV: 2/1
        opcodeTable[0x05] = 0x15; // SDIV: 2/1
        opcodeTable[0x06] = 0x15; // MOD: 2/1
        opcodeTable[0x07] = 0x15; // SMOD: 2/1
        opcodeTable[0x08] = 0x17; // ADDMOD: 3/1
        opcodeTable[0x09] = 0x17; // MULMOD: 3/1
        opcodeTable[0x0A] = 0x15; // EXP: 2/1

        // Comparison & bitwise logic operations
        opcodeTable[0x10] = 0x15; // LT: 2/1
        opcodeTable[0x11] = 0x15; // GT: 2/1
        opcodeTable[0x12] = 0x15; // SLT: 2/1
        opcodeTable[0x13] = 0x15; // SGT: 2/1
        opcodeTable[0x14] = 0x15; // EQ: 2/1
        opcodeTable[0x15] = 0x11; // ISZERO: 1/1
        opcodeTable[0x16] = 0x15; // AND: 2/1
        opcodeTable[0x17] = 0x15; // OR: 2/1
        opcodeTable[0x18] = 0x15; // XOR: 2/1
        opcodeTable[0x19] = 0x11; // NOT: 1/1

        // SHA3
        opcodeTable[0x20] = 0x15; // SHA3: 2/1

        // Environmental Information
        opcodeTable[0x30] = 0x14; // ADDRESS: 0/1
        opcodeTable[0x31] = 0x14; // BALANCE: 1/1
        opcodeTable[0x32] = 0x14; // ORIGIN: 0/1
        opcodeTable[0x33] = 0x14; // CALLER: 0/1
        opcodeTable[0x34] = 0x14; // CALLVALUE: 0/1
        opcodeTable[0x35] = 0x11; // CALLDATALOAD: 1/1
        opcodeTable[0x36] = 0x14; // CALLDATASIZE: 0/1
        opcodeTable[0x37] = 0x17; // CALLDATACOPY: 3/0
        opcodeTable[0x38] = 0x14; // CODESIZE: 0/1
        opcodeTable[0x39] = 0x17; // CODECOPY: 3/0
        opcodeTable[0x3A] = 0x14; // GASPRICE: 0/1

        // Block Information
        opcodeTable[0x40] = 0x14; // BLOCKHASH: 1/1
        opcodeTable[0x41] = 0x14; // COINBASE: 0/1
        opcodeTable[0x42] = 0x14; // TIMESTAMP: 0/1
        opcodeTable[0x43] = 0x14; // NUMBER: 0/1
        opcodeTable[0x44] = 0x14; // DIFFICULTY: 0/1
        opcodeTable[0x45] = 0x14; // GASLIMIT: 0/1

        // Stack, Memory, Storage and Flow Operations
        opcodeTable[0x50] = 0x11; // POP: 1/0
        opcodeTable[0x51] = 0x11; // MLOAD: 1/1
        opcodeTable[0x52] = 0x15; // MSTORE: 2/0
        opcodeTable[0x53] = 0x15; // MSTORE8: 2/0
        opcodeTable[0x54] = 0x11; // SLOAD: 1/1
        opcodeTable[0x55] = 0x15; // SSTORE: 2/0
        opcodeTable[0x56] = 0x11; // JUMP: 1/0
        opcodeTable[0x57] = 0x12; // JUMPI: 2/0
        opcodeTable[0x58] = 0x14; // PC: 0/1
        opcodeTable[0x59] = 0x14; // MSIZE: 0/1
        opcodeTable[0x5B] = 0x10; // JUMPDEST: 0/0

        // Push operations (0x5F-0x7F)
        for (uint8 i = 0x5F; i <= 0x7F; i++) {
            opcodeTable[i] = 0x14; // PUSH1-PUSH32: 0/1
        }

        // Duplication operations (0x80-0x8F)
        for (uint8 i = 0x80; i <= 0x8F; i++) {
            opcodeTable[i] = 0x14; // DUP1-DUP16: 1/2 (duplicates top stack item)
        }

        // Exchange operations (0x90-0x9F)
        for (uint8 i = 0x90; i <= 0x9F; i++) {
            opcodeTable[i] = 0x12; // SWAP1-SWAP16: 2/2 (swaps stack items)
        }

        // Logging operations are not allowed
        // Calls are not allowed
        // TODO: we may allow STATICCALL to a whitelist of contracts and methods.

        // RETURN is allowed
        opcodeTable[0xF3] = 0x15; // RETURN: 2/0
        // System operations: REVERT is allowed
        opcodeTable[0xFD] = 0x15; // REVERT: 2/0
    }

    // solhint-disable-next-line payable-fallback
    fallback() external {}

    function setCheckerProgram(
        Safe safe,
        bytes calldata newChecker,
        bool _disableLockoutCheck
    ) external {
        require(checkEvmByteCode(newChecker), "Invalid program bytecode");

        // Deploy the new contract using CREATE
        address contractAddress;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)

            // Copy the bytecode to memory
            calldatacopy(ptr, newChecker.offset, newChecker.length)

            // Create the contract and store the address
            contractAddress := create(0, ptr, newChecker.length)
        }

        // Ensure contract creation was successful
        require(contractAddress != address(0), "Contract creation failed");

        // Store the contract address and lockout setting
        checkerProgram[safe] = contractAddress;
        disableLockoutCheck[safe] = _disableLockoutCheck;
    }

    function getCheckerProgram(
        Safe safe
    ) external view returns (address) {
        return checkerProgram[safe];
    }

    /**
     * This function should be called by Safe to enable the guard.
     * It must be called as DELEGATE_CALL.
     *
     * @param guard     the address of the guard
     * @param program   the program to be executed by the guard
     */
    function enableGuard(
        address guard,
        bytes calldata program,
        bool _disableLockoutCheck
    ) external {
        Safe safe = Safe(payable(address(this)));
        safe.setGuard(guard);
        EasyGuard(guard).setCheckerProgram(safe, program, _disableLockoutCheck);
    }

    /**
     *
     * @dev This function is an implementation of the Guard interface from the @gnosis.pm package.
     * @param txHash            the hash of the transaction
     * @param signatures        the signatures of the transaction
     */
    function findAllSigners(
        bytes32 txHash,
        bytes memory signatures
    ) internal pure returns (address[] memory signers) {
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;

        uint256 numSignatures = signatures.length / 0x41;
        signers = new address[](numSignatures);

        for (i = 0; i < numSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);

            if (v == 0) {
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));
            } else if (v == 1) {
                // If v is 1 then it is an approved hash
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint160(uint256(r)));
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n32",
                            txHash
                        )
                    ),
                    v - 4,
                    r,
                    s
                );
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(txHash, v, r, s);
            }

            signers[i] = currentOwner;
        }
    }

    function getTxHash(
        GuardProgramVerification.TransactionContext memory context
    ) internal view returns (bytes32) {
        uint256 nonce = context.safe.nonce() - 1;
        bytes memory txHashData = context.safe.encodeTransactionData(
            // Transaction info
            context.to,
            context.value,
            context.data,
            context.operation,
            context.safeTxGas,
            // Payment info
            context.baseGas,
            context.gasPrice,
            context.gasToken,
            context.refundReceiver,
            // Signature info
            nonce
        );
        return keccak256(txHashData);
    }

    struct StackEntry {
        bool isConstant;
        uint256 value;
    }

    struct ExecutionContext {
        uint256 pc;
        StackEntry[] stack;
    }

    /**
     * This function checks that the given EVM bytecode is safe to execute to
     * evaluate a conditon.
     *
     *  1. It must not contain any CALL* related opcodes. It is not that those
     *      can wreak havoc - they can't, as we'll calling them as STAICCALL.
     *      But calling external functions means the condition depends on some
     *      uncertain state, which is hard to reason about. Therefore we forbid
     *      it.
     *
     *  2. Branching is allowed.  However, to evaluate all branches, we need to
     *     know where the code *may* jump.  In general, it is hard to fully
     *     determine, therefore we are making a simplifying assumption: an
     *     address on the stack before the JUMP/JUMPI must be known during
     *     analysis, either from PUSH*, or from PC. This will cover most
     *     contracts, except hand crafted hackish corner cases.
     */
    function checkEvmByteCode(bytes memory code) public view returns (bool) {
        // Load opcode table into memory at the start
        uint8[256] memory opcodeTableMem;
        for (uint256 i = 0; i < 8; i += 1) {
            bytes32 packed;
            assembly {
                packed := sload(add(opcodeTable.slot, i))
            }
            for (uint256 j = 0; j < 32 && i * 32 + j < 256; j++) {
                opcodeTableMem[i * 32 + j] = uint8(uint256(packed >> (j * 8)) & 0xFF);
            }
        }

        // A bitmap of visited opcodes.
        uint256[] memory visited = new uint256[]((code.length + 255) / 256);

        // Queue of contexts to process
        ExecutionContext[] memory contextQueue = new ExecutionContext[](16); // Fixed size for simplicity
        uint256 queueStart = 0;
        uint256 queueEnd = 1;

        // Initialize first context
        contextQueue[0] = ExecutionContext(0, new StackEntry[](64)); // Fixed stack size
        uint256 stackSize = 0;

        while (queueStart < queueEnd) {
            ExecutionContext memory context = contextQueue[queueStart++];
            uint256 pc = context.pc;
            StackEntry[] memory stack = context.stack;

            while (pc < code.length) {
                uint8 opcode = uint8(code[pc]);
                uint8 info = opcodeTableMem[opcode];
                visited[pc / 256] |= (1 << (pc % 256));

                // If it is an invalid
                if ((info & VALID_OPCODE) == 0) {
                    console.log("Disallowed or invalid opcode: ", info);
                    return false;
                }

                // Handle PUSH operations (0x60 to 0x7F)
                if (opcode >= 0x60 && opcode <= 0x7F) {
                    uint8 pushBytes = opcode - 0x5F;
                    uint256 value = 0;

                    // Read the pushed value
                    for (uint256 i = 0; i < pushBytes; i++) {
                        value = (value << 8) | uint8(code[pc + 1 + i]);
                    }

                    // Push constant value to stack
                    stack[stackSize] = StackEntry(true, value);
                    stackSize++;
                    pc += pushBytes;
                }
                // Handle JUMP
                else if (opcode == 0x56) { // JUMP
                    if (stackSize < 1) return false;
                    StackEntry memory target = stack[stackSize - 1];
                    stackSize--;

                    // Only allow jumps to constant values
                    if (!target.isConstant) return false;

                    // Validate jump destination
                    if (target.value >= code.length) return false;
                    if (uint8(code[target.value]) != 0x5B) return false; // JUMPDEST

                    // Continue with jump path if it is not yet visited
                    if ((visited[target.value / 256] & (1 << (target.value % 256))) != 0) {
                        break;
                    }
                    pc = target.value;
                    continue;
                }
                // Handle JUMPI
                else if (opcode == 0x57) { // JUMPI
                    if (stackSize < 2) return false;
                    StackEntry memory target = stack[stackSize - 2];
                    // We ignore the condition in stack[stackSize - 1], because we look at both branches
                    stackSize -= 2;

                    // Only allow jumps to constant values
                    if (!target.isConstant) return false;

                    // Validate jump destination
                    if (target.value >= code.length) return false;
                    if (uint8(code[target.value]) != 0x5B) return false; // JUMPDEST

                    // Add fallthrough path to queue
                    if (queueEnd < contextQueue.length) {
                        uint256 new_pc = pc + 1;
                        if ((visited[new_pc / 256] & (1 << (new_pc % 256))) == 0) {
                            contextQueue[queueEnd] = ExecutionContext(new_pc, stack);
                            queueEnd++;
                        }
                    }

                    // Continue with jump path if it is not yet visited
                    if ((visited[target.value / 256] & (1 << (target.value % 256))) != 0) {
                        break;
                    }
                    pc = target.value;
                    continue;
                }
                // Handle PC
                else if (opcode == 0x58) { // PC
                    // Since we know the PC, it is also kind of predictable, just as PUSH* constants.
                    stack[stackSize] = StackEntry(true, pc);
                    stackSize++;
                }
                // Handle DUP operations (0x80 to 0x8F)
                else if (opcode >= 0x80 && opcode <= 0x8F) {
                    uint256 dupIndex = opcode - 0x7F; // DUP1 = 1, DUP2 = 2, etc.
                    if (stackSize < dupIndex) return false;

                    // Copy the stack entry, preserving its constant/value status
                    stack[stackSize] = stack[stackSize - dupIndex];
                    stackSize++;
                }
                // Handle SWAP operations (0x90 to 0x9F)
                else if (opcode >= 0x90 && opcode <= 0x9F) {
                    uint256 swapIndex = opcode - 0x8F; // SWAP1 = 1, SWAP2 = 2, etc.
                    if (stackSize <= swapIndex) return false;

                    // Swap the top stack item with the nth item
                    StackEntry memory temp = stack[stackSize - 1];
                    stack[stackSize - 1] = stack[stackSize - 1 - swapIndex];
                    stack[stackSize - 1 - swapIndex] = temp;
                }
                // Handle other operations by pushing non-constant values
                else {
                    uint256 consumed = info & 0x03;
                    uint256 produced = (info >> 2) & 0x03;

                    if (stackSize < consumed) return false;
                    stackSize -= consumed;

                    // Push non-constant results
                    for (uint256 i = 0; i < produced; i++) {
                        stack[stackSize] = StackEntry(false, 0);
                        stackSize++;
                    }
                }

                pc++;
            }
        }

        return true;
    }

    /**
     * Checking transaction before it is executed, by running an associated checker program
     *
     * @param to                 the contract which is getting called by the transaction
     * @param value              the value field of the transaction
     * @param data               the data field of the transaction
     * @param operation          transaction type: DIRECT_CALL or DELEGATE
     * @param safeTxGas          used by the safe
     * @param baseGas            used by the safe
     * @param gasPrice           used by the safe
     * @param gasToken           used by the safe
     * @param refundReceiver     used by the safe
     * @param signatures         the signatures from all the signers
     * @param msgSender          the original msg.sender of the transaction
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external view override {
        GuardProgramVerification.TransactionContext memory context = GuardProgramVerification.TransactionContext(
            Safe(payable(msg.sender)),
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            msgSender
        );

        // Make sure we can always remove the guard, to protect us against lock out.
        if (!disableLockoutCheck[context.safe]) {
            if (
                to == address(context.safe) &&
                operation == Enum.Operation.DelegateCall &&
                data.length == 24
            ) {
                (bytes4 selector, address target) = abi.decode(
                    data,
                    (bytes4, address)
                );
                if (selector == bytes4(keccak256("setGuard(address)")) && target == address(0)) {
                    return;
                }
            }
        }

        address[] memory owners;
        address[] memory signers;

        GuardProgramVerification program = GuardProgramVerification(checkerProgram[context.safe]);

        // Get the signers from the signatures
        signers = findAllSigners(getTxHash(context), signatures);
        // Get the list of owners from the safe
        owners = context.safe.getOwners();

        bool result;
        bytes memory inputData = abi.encodeWithSelector(
                GuardProgramVerification.verify.selector,  // will be ignored
                context,
                owners,
                signers
        );

        assembly {
            let ptr := mload(0x40) // get free memory pointer
            let success := staticcall(gas(), program, add(inputData, 32), mload(inputData), ptr, 32)

             switch success
                case 0 {
                     revert(0, 0) // or handle failure differently
                }
                case 1 {
                     // Load 32 bytes of return data into result
                     result := iszero(iszero(mload(ptr)))
                }
        }

        // Call the program as staticcall and revert if verification fails
        require(result, "Guard: Transaction verification failed");
    }

    function checkAfterExecution(bytes32 txHash, bool success) external {
        // nothing to do here
    }
}
