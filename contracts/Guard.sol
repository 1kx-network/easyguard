// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import "@safe-global/safe-contracts/contracts/common/SignatureDecoder.sol";
import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/interfaces/IERC165.sol";
import "@safe-global/safe-contracts/contracts/interfaces/ISignatureValidator.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./ConditionCheck.sol";

enum Opcode {
    TRUE,
    FALSE,
    TO,
    FROM,
    VALUE,
    CALLDATA,
    CONSTANT,
    ADDRESS,
    DUP,
    SWAP,
    MSGSENDER,
    LT,
    GT,
    EQ,
    ISZERO,
    NOT,
    AND,
    OR,
    PLUS,
    MINUS,
    MUL,
    DIV,
    MOD,
    ISSIGNER,
    ISOWNER
}

/**
 * @title Restricted Transaction Guard
 * @notice This contract is a transaction guard for Safe ^1.3.0
 *         It allows the safe to exclude particular owners from signing a transaction
 */
contract RestrictedTransactionGuard is BaseGuard(), ISignatureValidatorConstants, SignatureDecoder {
 
    /**
     * @dev stores the address for the contract which checks if the restricted wallets are allowed to execute a
     * transaction
     */
    mapping(Safe => bytes32[]) private checkerProgram;

    /**
     * @dev taken from a guard example from the gnosis repo.
     *      To prevent a revert on fallback, we define it empty. This will avoid issues in case of a Safe upgrade
     *      E.g. the expected check method might change and theen the Safe would be locked.
     */
    // solhint-disable-next-line payable-fallback
    fallback() external {}

    /**
     * @notice sets the restrictedTransactionChecker, a contract which does additional checks if the safe is
     * allowed to execute the given transaction. This checker is only called if there are not enough unrestricted
     * signers in the transaction.
     */
    function setCheckerProgram(Safe safe, bytes32[] calldata newChecker) external  {
        checkerProgram[safe] = newChecker;
    }

    function getConditionChecker(Safe safe) external view returns (bytes32[] memory) {
        return checkerProgram[safe];
    }

    /** 
     *
     * @dev This function is an implementation of the Guard interface from the @gnosis.pm package.
     * @param txHash            the hash of the transaction
     * @param signatures        the signatures of the transaction
     */
    function findAllSigners(bytes32 txHash, bytes memory signatures) internal pure returns (address[] memory signers) {
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
                currentOwner =
                    ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(txHash, v, r, s);
            }

            signers[i] = currentOwner;
        }
    }

    function getTxHash(TransactionContext memory context) internal view returns (bytes32) {
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
    
    uint256 public constant MAX_STACK_SIZE = 32;

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

    /**
     * @dev This function is an implementation of the Guard interface from the @gnosis.pm package.
     *      It calculates the public keys from the signatures and checks if they are restricted. When we remove the
     *      restricted signers and don't meet the safe threshold, the transaction gets reverted. This function is
     *      getting called by the Safe.
     *
     *      The whole part of extracting the signature is directly copied from Safe.sol (see comments in the code).
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
        TransactionContext memory context = TransactionContext(Safe(payable(msg.sender)), to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, msgSender);

        // Make sure we can always remove the guard, to protect against lock out.
        if (to == address(context.safe) && operation == Enum.Operation.DelegateCall && data.length == 24 && bytes4(data) == 0xe19a9dd9) {
            return;
        }

        bytes32[] memory program = checkerProgram[context.safe];
        if (program.length == 0) {
            return;
        }

        bool signersInitialized = false;
        address[] memory signers;

        bytes32[MAX_STACK_SIZE] memory stack;
        uint256 sp = 0;  // For convenience, there will be one empty slot on the stack
        uint256 pc = 0;
        for (;;) {
            bytes32 instruction = program[pc++];
            Opcode opcode = Opcode(uint8(bytes1(instruction)));
            if (opcode == Opcode.TRUE) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(uint256(1));
            } else if (opcode == Opcode.FALSE) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(0);
            } else if (opcode == Opcode.TO) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(uint256(uint160(context.to)));
            } else if (opcode == Opcode.FROM) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(uint256(uint160(context.msgSender)));
            } else if (opcode == Opcode.VALUE) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(context.value);
            } else if (opcode == Opcode.CALLDATA) {
                require(sp >= 2, "Stack underflow");
                uint256 offset = uint256(stack[sp - 1]);
                uint256 length = uint256(stack[sp]);
                require(context.data.length >= offset + length, "Data out of bounds");
                bytes memory extractedData = new bytes(length);
                for (uint256 j = 0; j < length; j++) {
                    extractedData[j] = context.data[offset + j];
                }
                stack[++sp] = bytes32(abi.decode(extractedData, (uint256)));
            } else if (opcode == Opcode.CONSTANT) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = program[uint256(program[pc++])];
            } else if (opcode == Opcode.ADDRESS) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(uint256(instruction) >> 8);
            } else if (opcode == Opcode.DUP) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                require(sp >= 1, "Stack underflow");
                stack[++sp] = stack[sp];
            } else if (opcode == Opcode.SWAP) {
                require(sp >= 2, "Stack underflow");
                (stack[sp], stack[sp - 1]) = (stack[sp - 1], stack[sp]);
            } else if (opcode == Opcode.MSGSENDER) {
                require(sp < MAX_STACK_SIZE, "Stack overflow");
                stack[++sp] = bytes32(uint256(uint160(msgSender)));
            } else if (opcode == Opcode.LT) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) < uint256(stack[sp]) ? uint256(1) : uint256(0));
                sp--;
            } else if (opcode == Opcode.GT) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) > uint256(stack[sp]) ? uint256(1) : uint256(0));
                sp--;
            } else if (opcode == Opcode.EQ) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) == uint256(stack[sp]) ? 1 : uint256(0));
                sp--;
            } else if (opcode == Opcode.ISZERO) {
                require(sp >= 1, "Stack underflow");
                stack[sp] = bytes32(uint256(stack[sp]) == 0 ? uint256(1) : uint256(0));
            } else if (opcode == Opcode.NOT) {
                require(sp >= 1, "Stack underflow");
                stack[sp] = bytes32(uint256(stack[sp]) == 0 ? uint256(1) : uint256(0));
            } else if (opcode == Opcode.AND) {
                require(sp >= 2, "Stack underflow");
                bool op1 = (uint256(stack[sp - 1]) != 0);
                bool op2 = (uint256(stack[sp]) != 0);
                stack[sp - 1] = bytes32(uint256(op1 && op2 ? 1 : 0));
                sp--;
            } else if (opcode == Opcode.OR) {
                require(sp >= 2, "Stack underflow");
                bool op1 = (uint256(stack[sp - 1]) != 0);
                bool op2 = (uint256(stack[sp]) != 0);
                stack[sp - 1] = bytes32(uint256(op1 || op2 ? 1 : 0));
                sp--;
            } else if (opcode == Opcode.PLUS) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) + uint256(stack[sp]));
                sp--;
            } else if (opcode == Opcode.MINUS) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) - uint256(stack[sp]));
                sp--;
            } else if (opcode == Opcode.MUL) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) * uint256(stack[sp]));
                sp--;
            } else if (opcode == Opcode.DIV) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) / uint256(stack[sp]));
                sp--;
            } else if (opcode == Opcode.MOD) {
                require(sp >= 2, "Stack underflow");
                stack[sp - 1] = bytes32(uint256(stack[sp - 1]) % uint256(stack[sp]));
                sp--;
            } else if (opcode == Opcode.ISSIGNER) {
                require(sp >= 1, "Stack underflow");
                if (!signersInitialized == false) {
                    bytes32 txHash = getTxHash(context);
                    signers = findAllSigners(txHash, signatures);
                    signersInitialized = true;
                }
                address signer = address(uint160(uint256(stack[sp])));
                stack[sp] = bytes32(0);
                for (uint256 i = 0; i < signers.length; i++) {
                    if (signers[i] == signer) {
                        stack[sp] = bytes32(uint256(1));
                        break;
                    }
                }
            } else if (opcode == Opcode.ISOWNER) {
                require(sp >= 1, "Stack underflow");
                address owner = address(uint160(uint256(stack[sp])));
                address[] memory owners = context.safe.getOwners();
                stack[sp] = bytes32(0);
                for (uint256 i = 0; i < owners.length; i++) {
                    if (owners[i] == owner) {
                        stack[sp] = bytes32(uint256(1));
                        break;
                    }
                }
            } else {
                revert("Invalid opcode");
            }
        }
    }
    
    function checkAfterExecution(bytes32 txHash, bool success) external
    {
        // nothing to do here
    }
}
