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
    // =========================================================================
    // Errors
    // =========================================================================
    error PcOutOfBounds(uint256 pc, uint256 codeLength);
    error IterationLimitExceeded(uint256 limit);
    error OpcodeNotAllowed(uint8 opcode, uint256 pc);
    error StackUnderflow(uint8 opcode, uint256 pc, uint256 stackDepth, uint8 required);
    error StackOverflow(uint8 opcode, uint256 pc, uint256 newStackDepth, uint256 limit);
    error PushOutOfBounds(uint256 pc, uint256 pushEnd, uint256 codeLength);
    error InvalidJumpDestination(uint256 targetPc, uint256 pc); // Target PC is not a JUMPDEST opcode
    error JumpTargetOutOfBounds(uint256 targetPc, uint256 pc, uint256 codeLength);
    error JumpToNonConstantAddress(uint256 pc);
    error CycleDetected(uint256 pc);
    error PcExceedsUint16Limit(uint256 pc);
    error InvalidOpcodeInfoPacking(uint8 opcode, uint8 value, string reason); // For constructor checks
    error DupStackDepthError(uint8 n, uint256 pc, uint256 stackDepth); // Specific error for DUP
    error SwapStackDepthError(uint8 n, uint256 pc, uint256 stackDepth); // Specific error for SWAP

    mapping(Safe => address) private checkerProgram;
    mapping(Safe => bool) private disableLockoutCheck;

    // Bitmask: 1 = allowed, 0 = disallowed. Bit N corresponds to opcode N.
    uint256 immutable public allowedBitmask;

    // Packed Consumed/Produced: 4 bits per opcode [CCC|P] (Consumed 0-7 removed | Produced 0-1 added)
    // Stored across 4 uint256 words (4 * 256 bits / 4 bits/opcode = 256 opcodes)
    uint256 immutable public packedConsumedProduced0;
    uint256 immutable public packedConsumedProduced1;
    uint256 immutable public packedConsumedProduced2;
    uint256 immutable public packedConsumedProduced3;

    // =========================================================================
    // Constants
    // =========================================================================
    uint256 public constant MAX_STACK_SIZE = 1024;
    uint256 public constant MAX_ITERATIONS = 10000; // Adjust as needed

    // =========================================================================
    // Structs
    // =========================================================================
    // State for the iterative DFS control stack
    struct State {
        uint256 pc;
        uint256[] stack;
        uint16[] visited; // Tracks PCs (as uint16) visited on the path
    }

    // Helper struct for defining rules before packing
    struct TempOpInfo {
        bool allowed;
        uint8 consumed; // Items REMOVED
        uint8 produced; // Items ADDED
        // Optional: Required stack depth if different from consumed (for DUP/SWAP)
        // We don't store this optional field, it's handled by bespoke checks later
    }

    constructor() {
        // Build the immutable rule tables in memory first
        uint256 buildAllowedBitmask = 0;
        uint256[4] memory buildPackedConsumedProduced; // Zero-initialized

        // Define rules for all 256 opcodes
        // This is verbose but necessary for immutable setup
        TempOpInfo[256] memory rules;

        // Stop and arithmetic operations
        rules[0x00] = TempOpInfo(true, 0, 0); // STOP
        rules[0x01] = TempOpInfo(true, 2, 1); // ADD
        rules[0x02] = TempOpInfo(true, 2, 1); // MUL
        rules[0x03] = TempOpInfo(true, 2, 1); // SUB
        rules[0x04] = TempOpInfo(true, 2, 1); // DIV
        rules[0x05] = TempOpInfo(true, 2, 1); // SDIV
        rules[0x06] = TempOpInfo(true, 2, 1); // MOD
        rules[0x07] = TempOpInfo(true, 2, 1); // SMOD
        rules[0x08] = TempOpInfo(true, 3, 1); // ADDMOD
        rules[0x09] = TempOpInfo(true, 3, 1); // MULMOD
        rules[0x0A] = TempOpInfo(true, 2, 1); // EXP

        // Comparison & bitwise logic operations
        rules[0x10] = TempOpInfo(true, 2, 1); // LT
        rules[0x11] = TempOpInfo(true, 2, 1); // GT
        rules[0x12] = TempOpInfo(true, 2, 1); // SLT
        rules[0x13] = TempOpInfo(true, 2, 1); // SGT
        rules[0x14] = TempOpInfo(true, 2, 1); // EQ
        rules[0x15] = TempOpInfo(true, 1, 1); // ISZERO
        rules[0x16] = TempOpInfo(true, 2, 1); // AND
        rules[0x17] = TempOpInfo(true, 2, 1); // OR
        rules[0x18] = TempOpInfo(true, 2, 1); // XOR
        rules[0x19] = TempOpInfo(true, 1, 1); // NOT
        rules[0x1A] = TempOpInfo(true, 2, 1); // BYTE
        rules[0x1B] = TempOpInfo(true, 2, 1); // SHL
        rules[0x1C] = TempOpInfo(true, 2, 1); // SHR
        rules[0x1D] = TempOpInfo(true, 2, 1); // SAR

        // SHA3
        rules[0x20] = TempOpInfo(true, 2, 1); // SHA3

        // Environmental Information
        rules[0x30] = TempOpInfo(true, 0, 1); // ADDRESS
        rules[0x31] = TempOpInfo(true, 1, 1); // BALANCE
        rules[0x32] = TempOpInfo(true, 0, 1); // ORIGIN
        rules[0x33] = TempOpInfo(true, 0, 1); // CALLER
        rules[0x34] = TempOpInfo(true, 0, 1); // CALLVALUE
        rules[0x35] = TempOpInfo(true, 1, 1); // CALLDATALOAD
        rules[0x36] = TempOpInfo(true, 0, 1); // CALLDATASIZE
        rules[0x37] = TempOpInfo(true, 3, 0); // CALLDATACOPY
        rules[0x38] = TempOpInfo(true, 0, 1); // CODESIZE
        rules[0x39] = TempOpInfo(true, 3, 0); // CODECOPY
        rules[0x3A] = TempOpInfo(true, 0, 1); // GASPRICE

        // Block Information
        rules[0x40] = TempOpInfo(true, 1, 1); // BLOCKHASH
        rules[0x41] = TempOpInfo(true, 0, 1); // COINBASE
        rules[0x42] = TempOpInfo(true, 0, 1); // TIMESTAMP
        rules[0x43] = TempOpInfo(true, 0, 1); // NUMBER
        rules[0x44] = TempOpInfo(true, 0, 1); // DIFFICULTY/PREVRANDAO
        rules[0x45] = TempOpInfo(true, 0, 1); // GASLIMIT
        rules[0x46] = TempOpInfo(true, 0, 1); // CHAINID
        rules[0x47] = TempOpInfo(true, 0, 1); // SELFBALANCE

        // Stack, Memory, Storage and Flow Operations
        rules[0x50] = TempOpInfo(true, 1, 0); // POP
        rules[0x51] = TempOpInfo(true, 1, 1); // MLOAD
        rules[0x52] = TempOpInfo(true, 2, 0); // MSTORE
        rules[0x53] = TempOpInfo(true, 2, 0); // MSTORE8
        rules[0x54] = TempOpInfo(true, 1, 1); // SLOAD
        rules[0x55] = TempOpInfo(true, 2, 0); // SSTORE
        rules[0x56] = TempOpInfo(true, 1, 0); // JUMP
        rules[0x57] = TempOpInfo(true, 2, 0); // JUMPI
        rules[0x58] = TempOpInfo(true, 0, 1); // PC
        rules[0x59] = TempOpInfo(true, 0, 1); // MSIZE
        rules[0x5A] = TempOpInfo(true, 0, 1); // GAS
        rules[0x5B] = TempOpInfo(true, 0, 0); // JUMPDEST
        rules[0x5E] = TempOpInfo(true, 3, 0); // MCOPY

        // Push operations (0x5F-0x7F) -> (t 0 1)
        for (uint8 i = 0x5F; i <= 0x7F; i++) {
            rules[i] = TempOpInfo(true, 0, 1); // PUSH0-PUSH32
        }

        // Duplication operations (0x80-0x8F) -> (t 0 1)
        for (uint8 i = 0x80; i <= 0x8F; i++) {
            rules[i] = TempOpInfo(true, 0, 1); // DUP1-DUP16
        }

        // Exchange operations (0x90-0x9F) -> (t 1 1)
        for (uint8 i = 0x90; i <= 0x9F; i++) {
            rules[i] = TempOpInfo(true, 1, 1); // SWAP1-SWAP16 (Simplified rule)
        }

        // RETURN is allowed
        rules[0xF3] = TempOpInfo(true, 2, 0); // RETURN
        // System operations: REVERT is allowed
        rules[0xFD] = TempOpInfo(true, 2, 0); // REVERT


        // --- Pack the rules into the immutable variables ---
        for (uint256 i = 0; i < 256; i++) {
            TempOpInfo memory rule = rules[i];

            // Set allowed bit
            if (rule.allowed) {
                buildAllowedBitmask |= (uint256(1) << i);
            }

            // Validate constraints for packing Consumed/Produced
            // (Should have been caught by rule definitions, but double check)
            if (rule.consumed > 7) revert InvalidOpcodeInfoPacking(uint8(i), rule.consumed, "Consumed > 7");
            if (rule.produced > 1) revert InvalidOpcodeInfoPacking(uint8(i), rule.produced, "Produced > 1");

            // Pack Consumed (CCC) and Produced (P) -> CCCP
            uint256 packedValue = (uint256(rule.consumed) << 1) | uint256(rule.produced);

            // Store packed value in the correct word and position
            uint256 wordIndex = i / 64;
            uint256 bitShift = (i % 64) * 4;
            buildPackedConsumedProduced[wordIndex] |= (packedValue << bitShift);
        }

        // Assign to immutable variables
        allowedBitmask = buildAllowedBitmask;
        packedConsumedProduced0 = buildPackedConsumedProduced[0];
        packedConsumedProduced1 = buildPackedConsumedProduced[1];
        packedConsumedProduced2 = buildPackedConsumedProduced[2];
        packedConsumedProduced3 = buildPackedConsumedProduced[3];
    }        

    /*
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
    
    */

    // solhint-disable-next-line payable-fallback
    fallback() external {}

    function setCheckerProgram(
        Safe safe,
        bytes calldata newChecker,
        bool _disableLockoutCheck
    ) external {
        require(checkEvmByteCode(newChecker), "Invalid program bytecode");

        uint16 length = uint16(newChecker.length);
        /**
          The bytecode below means the following (length will be replaced at checker construction).
          It just returns the code immediately following it.

          PUSH2 <LENGTH>  // 0x61 <length> Length newChecker    | stack = [length]
          DUP1            // 0x80 Duplicate length.             | stack = [length, length]
          PUSH1 10        // 0x600a  Push 10
                          //         (length of this bytecode)  | stack = [10, length, length]
          PUSH0           // 0x5f Push 0                        | stack = [0, 10, length, length]
          CODECOPY        // 0x39 copy code from [10:10+length]
                          // to memory[0:length]                | stack = [length]
          PUSH0           // 0x5f Push 0                        | stack = [0, length]
          RETURN          // 0xf3 returns memory[0:length]      | stack = []

        */
        // Deploy the new contract using CREATE
        address contractAddress;
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Below we have the above bytecode as a single 256-bit constant, to be copied to
            // memory in one mstore instruction. The bytecode is 10 bytes, they need to be
            // the most significant bytes, to be put into beginning of memory in big-endian.
            // Therefore we need to shift it left by 256 - (10 * 8) = 176 bits.
            mstore(ptr, shl(176, 0x61000080600a5f395ff3))   // the constructor bytecode described above.
            // Store the length (which fits into two bytes in any case) into those two bytes
            // arguments of the first PUSH2 bytecode instruction.
            mstore8(add(ptr, 1), shr(8, length))
            mstore8(add(ptr, 2), length)
            // Copy the bytecode to memory
            calldatacopy(add(ptr, 10), newChecker.offset, length)

            // Create the contract and store the address
            contractAddress := create(0, ptr, add(10, length))
        }

        // Ensure contract creation was successful
        require(contractAddress != address(0), "Contract creation failed");

        // Store the contract address and lockout setting
        checkerProgram[safe] = contractAddress;
        console.log("contractAddress", contractAddress);
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

    function isInVisited(uint256 _pc, uint16[] memory _visited) internal pure returns (bool found) {
        if (_pc > type(uint16).max)
            revert PcExceedsUint16Limit(_pc);
        uint16 pc16 = uint16(_pc);
        uint256 len = _visited.length;
        for (uint256 i = 0; i < len; i++) {
            if (_visited[i] == pc16) return true;
        }
        return false;
    }

    function createNextVisited(uint256 _pc, uint16[] memory _visited) internal pure returns (uint16[] memory nextVisited) {
        if (_pc > type(uint16).max)
            revert PcExceedsUint16Limit(_pc);
        uint16 pc16 = uint16(_pc);
        nextVisited = new uint16[](_visited.length + 1);
        for (uint256 i = 0; i < _visited.length; i++) {
            nextVisited[i] = _visited[i];
        }
        nextVisited[_visited.length] = pc16;
    }

    function swapStack(uint256[] memory stack, uint8 n) internal pure returns (uint256[] memory newStack) {
        // Note: Caller must ensure stack.length >= n + 1
        newStack = new uint256[](stack.length);
        uint256 top = stack[0];
        uint256 nth = stack[n];
        newStack[0] = nth;
        for(uint i = 1; i < n; ++i) {
            newStack[i] = stack[i];
        }
        newStack[n] = top;
        for(uint i = n + 1; i < stack.length; ++i) {
            newStack[i] = stack[i];
        }
    }

    // =========================================================================
    // Bytecode Validation Logic
    // =========================================================================

    struct EvmCheckerContext {
        State[] controlStack;
        uint256 controlStackPtr;
        uint256 iterationCount;
    }

    function unpackConsumedProduced(uint256 opcode) private view returns (uint8 consumed, uint8 produced) {
        // Unpack Consumed/Produced
        uint256 wordIndex = uint256(opcode) / 64;
        uint256 bitShift = (uint256(opcode) % 64) * 4;
        uint256 packedWord = (wordIndex == 0 ? packedConsumedProduced0 :
                              wordIndex == 1 ? packedConsumedProduced1 :
                              wordIndex == 2 ? packedConsumedProduced2 : packedConsumedProduced3);
        uint256 packedValue = (packedWord >> bitShift) & 0xF; // Read 4 bits [CCC|P]
        consumed = uint8((packedValue >> 1) & 7); // Unpack 3 bits (Items Removed)
        produced = uint8(packedValue & 1);      // Unpack 1 bit (Items Added)
    }        

    function checkConsumedProduced(uint8 opcode, uint256 stack_length, uint256 pc) private view returns (uint8 consumed, uint8 produced) {

        (consumed, produced) = unpackConsumedProduced(opcode);
        // --- Stack Checks ---
        // Generic underflow check based on items *removed*
        if (stack_length < consumed) {
            revert StackUnderflow(opcode, pc, stack_length, consumed);
        }
        
        // Bespoke stack depth requirement checks for DUP/SWAP
        if (opcode >= 0x80 && opcode <= 0x8F) { // DUPx
            uint8 n = opcode - 0x80 + 1;
            if (stack_length < n)
                revert DupStackDepthError(n, pc, stack_length);
        } else if (opcode >= 0x90 && opcode <= 0x9F) { // SWAPx
            uint8 n = opcode - 0x90 + 1;
            if (stack_length < n + 1)
                revert SwapStackDepthError(n, pc, stack_length);
        }
        
        // Overflow check based on net change
        uint256 newStackDepth = stack_length - consumed + produced;
        if (newStackDepth > MAX_STACK_SIZE)
            revert StackOverflow(opcode, pc, newStackDepth, MAX_STACK_SIZE);
    }

    /**
     * @notice Validates EVM bytecode using iterative DFS with cycle detection (uint16 visited path).
     * @dev Uses packed immutable opcode rules loaded directly from bytecode. Checks rules based on [CCC|P] packing.
     * WARNING: High gas cost due to cycle detection's memory array copying. Assumes PC fits in uint16.
     * WARNING: Uses a simplified opcode ruleset where standard EVM rules don't fit packing constraints (e.g., LOGs).
     * @param _code The bytecode to validate.
     * @return valid True if the bytecode passes validation checks within limits.
     */
    function checkEvmByteCode(bytes memory _code) public view returns (bool valid) {
        if (_code.length == 0) return true;
        if (_code.length > 24576) {
            revert PcExceedsUint16Limit(_code.length);
        }
        EvmCheckerContext memory ctx = EvmCheckerContext({
            controlStack: new State[](MAX_ITERATIONS),
                    controlStackPtr: 0,
                    iterationCount: 0});

        // --- Iterative DFS Setup ---
        ctx.controlStack[ctx.controlStackPtr++] = State({pc: 0, stack: new uint256[](0), visited: new uint16[](0)});

        // --- Main DFS Loop ---
        while (ctx.controlStackPtr > 0) {
            if (ctx.iterationCount >= MAX_ITERATIONS)
                revert IterationLimitExceeded(MAX_ITERATIONS);
            ctx.iterationCount++;

            ctx.controlStackPtr--; // Point to the element we want to process
            State memory currentState = ctx.controlStack[ctx.controlStackPtr]; // Read the current top element
            
            // --- State Validation ---
            if (currentState.pc >= _code.length)
                continue;
            if (isInVisited(currentState.pc, currentState.visited))
                revert CycleDetected(currentState.pc);

            // --- Get Opcode and Unpack Info from Immutable Vars ---
            uint8 opcode = uint8(_code[currentState.pc]);

            // Check Allowed using bitmask
            bool allowed = ((allowedBitmask >> uint256(opcode)) & 1) == 1;
            if (!allowed)
                revert OpcodeNotAllowed(opcode, currentState.pc);

            (uint8 consumed, uint8 produced) = checkConsumedProduced(opcode, currentState.stack.length, currentState.pc);

            // --- Opcode Processing & State Transition ---
            uint256 nextPc = currentState.pc + 1;
            uint16[] memory nextVisited = createNextVisited(currentState.pc, currentState.visited);
            uint256[] memory nextStackBase = new uint256[](currentState.stack.length - consumed);
            for(uint i = 0; i < nextStackBase.length; ++i) {
                nextStackBase[i] = currentState.stack[i + consumed];
            }

            uint256 code_length = _code.length;

            // Terminating Opcodes
            if (opcode == 0x00 || opcode == 0xf3 || opcode == 0xfd || opcode == 0xfe) {
                continue;
            }
            // PUSH0-PUSH32
            else if (opcode >= 0x5F && opcode <= 0x7F) {
                if (currentState.pc + 1 > code_length - uint256(opcode - 0x5F)) {
                    revert PushOutOfBounds(currentState.pc, currentState.pc + 1 + uint256(opcode - 0x5F), _code.length);
                }
                uint256 value = 0;
                for (uint256 i = 0; i < uint256(opcode - 0x5F); i++) {
                    value = (value << 8) | uint8(_code[currentState.pc + 1 + i]);
                }
                uint256[] memory newStack = new uint256[](nextStackBase.length + produced); // produced should be 1
                newStack[0] = value;
                for(uint i = 0; i < nextStackBase.length; ++i) {
                    newStack[i+produced] = nextStackBase[i];
                }
                if (ctx.controlStackPtr >= MAX_ITERATIONS)
                    revert IterationLimitExceeded(MAX_ITERATIONS);
                ctx.controlStack[ctx.controlStackPtr++] = State(currentState.pc + 1 + uint256(opcode - 0x5F), newStack, nextVisited);
            }
            // JUMPDEST
            else if (opcode == 0x5B) {
                 uint256[] memory newStack = nextStackBase; // produced=0
                 if (ctx.controlStackPtr >= MAX_ITERATIONS)
                     revert IterationLimitExceeded(MAX_ITERATIONS);
                 ctx.controlStack[ctx.controlStackPtr++] = State(nextPc, newStack, nextVisited);
            }
            // JUMP
            else if (opcode == 0x56) {
                uint256 targetPc = currentState.stack[0];
                if (targetPc == 0)  // We assume that jump to PC 0 cannot be legal, so we use value 0 as "unknown" or "not constant".
                    revert JumpToNonConstantAddress(currentState.pc);
                if (targetPc >= _code.length)
                    revert JumpTargetOutOfBounds(targetPc, currentState.pc, _code.length);
                if (uint8(_code[targetPc]) != 0x5B)
                    revert InvalidJumpDestination(targetPc, currentState.pc);
                ctx.controlStack[ctx.controlStackPtr++] = State(targetPc, nextStackBase, nextVisited);
            }
            // JUMPI
            else if (opcode == 0x57) {
                uint256 targetPc = currentState.stack[0];
                if (targetPc == 0)  // We assume that jump to PC 0 cannot be legal, so we use value 0 as "unknown" or "not constant".
                    revert JumpToNonConstantAddress(currentState.pc);
                if (targetPc >= _code.length)
                    revert JumpTargetOutOfBounds(targetPc, currentState.pc, _code.length);
                if (uint8(_code[targetPc]) != 0x5B)
                    revert InvalidJumpDestination(targetPc, currentState.pc);
                ctx.controlStack[ctx.controlStackPtr++] = State(nextPc, nextStackBase, nextVisited);
                ctx.controlStack[ctx.controlStackPtr++] = State(targetPc, nextStackBase, nextVisited);
            }
            // PC
            else if (opcode == 0x58) {
                uint256[] memory newStack = new uint256[](nextStackBase.length + produced); // produced=1
                newStack[0] = currentState.pc;
                for(uint i = 0; i < nextStackBase.length; ++i) {
                    newStack[i + produced] = nextStackBase[i];
                }
                ctx.controlStack[ctx.controlStackPtr++] = State(nextPc, newStack, nextVisited);
            }
            // DUPx
            else if (opcode >= 0x80 && opcode <= 0x8F) {
                // Bespoke depth check already done
                uint8 n = opcode - 0x80 + 1;
                uint256 dupValue = currentState.stack[n-1];
                uint256[] memory newStack = new uint256[](nextStackBase.length + produced); // produced=1
                newStack[0] = dupValue;
                for (uint i = 0; i < nextStackBase.length; ++i) {
                    newStack[i+produced] = nextStackBase[i];
                }
                ctx.controlStack[ctx.controlStackPtr++] = State(nextPc, newStack, nextVisited);
            }
            // SWAPx
            else if (opcode >= 0x90 && opcode <= 0x9F) {
                // Bespoke depth check already done
                uint8 n = opcode - 0x90 + 1;
                uint256[] memory newStack = swapStack(currentState.stack, n); // Performs swap, size unchanged (produced=0)
                ctx.controlStack[ctx.controlStackPtr++] = State(nextPc, newStack, nextVisited);
            }
             // Default Case (Arithmetic, Logic, CALL, LOG, etc.)
            else {
                // Assumes produced is 0 or 1 based on packed value
                uint256[] memory newStack = new uint256[](nextStackBase.length + produced);
                // Add placeholders (zeros are default)
                // Copy base after placeholders
                for (uint i = 0; i < nextStackBase.length; ++i) {
                    newStack[i + produced] = nextStackBase[i];
                }
                ctx.controlStack[ctx.controlStackPtr++] = State(nextPc, newStack, nextVisited);
            }
        } // End while loop

        // If the loop finishes without reverting, the code is considered valid (DAG) within the limits
        valid = true;
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

        bytes memory inputData = abi.encodeWithSelector(
                GuardProgramVerification.verify.selector,  // will be ignored
                context,
                owners,
                signers
        );

        (bool success, bytes memory returnData) = address(program).staticcall(inputData);
        bool result = abi.decode(returnData, (bool));

        // Call the program as staticcall and revert if verification fails
        require(success && result, "Guard: Transaction verification failed");
    }

    function checkAfterExecution(bytes32 txHash, bool success) external {
        // nothing to do here
    }
}
