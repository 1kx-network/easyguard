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

    function verify(TransactionContext calldata context, address[] calldata owners, address[] calldata signers) external returns (bool);
}

    /**
 * @title Easy Guard
 * @notice This contract is a transaction guard for Safe ^1.3.0
 */
contract EasyGuard is
    BaseGuard,
    ISignatureValidatorConstants,
    SignatureDecoder
{
    mapping(Safe => address) private checkerProgram;
    mapping(Safe => bool) private disableLockoutCheck;

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

    function checkEvmByteCode(bytes memory code) public pure returns (bool) {
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
                
                // Check for disallowed opcodes
                if (
                    // External calls
                    (opcode == 0xF0) || // CREATE
                    (opcode == 0xF1) || // CALL
                    (opcode == 0xF2) || // CALLCODE
                    (opcode == 0xF4) || // DELEGATECALL
                    (opcode == 0xF5) || // CREATE2
                    (opcode == 0xFA) || // STATICCALL
                    
                    // External code access
                    (opcode == 0x3B) || // EXTCODECOPY
                    (opcode == 0x3C) || // EXTCODESIZE
                    (opcode == 0x3F) || // EXTCODEHASH
                    
                    // Return data
                    (opcode == 0x3D) || // RETURNDATASIZE
                    (opcode == 0x3E) || // RETURNDATACOPY
                    
                    // LOG operations
                    (opcode == 0xA0) || // LOG0
                    (opcode == 0xA1) || // LOG1
                    (opcode == 0xA2) || // LOG2
                    (opcode == 0xA3) || // LOG3
                    (opcode == 0xA4) || // LOG4
                    
                    // Self destruct
                    (opcode == 0xFF) || // SELFDESTRUCT
                    
                    // Other dangerous opcodes
                    (opcode == 0xFE)    // INVALID
                ) {
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
                    
                    pc = target.value;
                    continue;
                }
                // Handle JUMPI
                else if (opcode == 0x57) { // JUMPI
                    if (stackSize < 2) return false;
                    StackEntry memory target = stack[stackSize - 2];
                    StackEntry memory condition = stack[stackSize - 1];
                    stackSize -= 2;
                    
                    // Only allow jumps to constant values
                    if (!target.isConstant) return false;
                    
                    // Validate jump destination
                    if (target.value >= code.length) return false;
                    if (uint8(code[target.value]) != 0x5B) return false; // JUMPDEST
                    
                    // Add fallthrough path to queue
                    if (queueEnd < contextQueue.length) {
                        contextQueue[queueEnd] = ExecutionContext(pc + 1, stack);
                        queueEnd++;
                    }
                    
                    // Continue with jump path
                    pc = target.value;
                    continue;
                }
                // Handle PC
                else if (opcode == 0x58) { // PC
                    stack[stackSize] = StackEntry(true, pc);
                    stackSize++;
                }
                // Handle other operations by pushing non-constant values
                else {
                    // Simple stack manipulation based on opcode
                    uint256 consumed = 0;
                    uint256 produced = 0;
                    
                    // Add stack effect for common operations
                    if (opcode >= 0x01 && opcode <= 0x0B) { // Arithmetic
                        consumed = 2;
                        produced = 1;
                    } else if (opcode >= 0x10 && opcode <= 0x1B) { // Comparison
                        consumed = 2;
                        produced = 1;
                    }
                    // Add more cases as needed
                    
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

        // Make sure we can always remove the guard, to protect against lock out.
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

        // Call the program as staticcall and revert if verification fails
        (bool success, bytes memory returnData) = address(program).staticcall(
            abi.encodeWithSelector(
                GuardProgramVerification.verify.selector,  // will be ignored
                context,
                owners,
                signers
            )
        );

        require(success && abi.decode(returnData, (bool)), "Guard: Transaction verification failed");
    }

    function checkAfterExecution(bytes32 txHash, bool success) external {
        // nothing to do here
    }
}
