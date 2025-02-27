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
    mapping(Safe => address) private conditionCheckerAddress;

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
    function setConditionChecker(Safe safe, address newChecker) external  {
        conditionCheckerAddress[safe] = newChecker;
    }

    function getConditionChecker(Safe safe) external view returns (address) {
        return conditionCheckerAddress[safe];
    }
    
    /** 
     *
     * @dev This function is an implementation of the Guard interface from the @gnosis.pm package.
     * @param safe              the safe which is calling the guard
     * @param addresses         the array of to check presence in the set of signers
     * @param txHash            the hash of the transaction
     * @param signatures        the signatures of the transaction
     */
    function addressSignatureMask(Safe safe, address[] memory addresses, bytes32 txHash, bytes memory signatures) external view returns (uint256 addressMask) {
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        
        addressMask = 0;
        uint numOwner = safe.getOwners().length;
        for (i = 0; i < numOwner; i++) {
            (v, r, s) = signatureSplit(signatures, i);

            /*
                * Modification of the original code.
                * The original code can just check as much signatures as the threshold is. Unfortunately, we cannot do
                * this, since some signatures might not be valid. So we need to find a way to abort the signature
                * check. When there is no signature left to check, the value of r is just 0. This means this can be
                * our abort condition to leave the for loop.
                */
            if (uint256(r) == 0) {
                break;
            }

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

            for (uint256 j = 0; j < addresses.length; j++) {
                if (addresses[j] == currentOwner) {
                    addressMask |= (1 << j);
                }
            }
        }        
    }

    function getTxHash(
        Safe safe,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) external view returns (bytes32) {
        uint256 nonce = safe.nonce() - 1;
        bytes memory txHashData = safe.encodeTransactionData(
            // Transaction info
            to,
            value,
            data,
            operation,
            safeTxGas,
            // Payment info
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            // Signature info
            nonce
        );
        return keccak256(txHashData);
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
        /*
         * This part is directly copied from: https://github.com/safe-global/safe-contracts/blob/186a21a74b327f17fc41217a927dea7064f74604/contracts/Safe.sol#L125
         *
         * We need to calculate the transaction hash to restore the public keys from the signers
         */
        Safe safe = Safe(payable(msg.sender));

        if (to == address(safe) && operation == Enum.Operation.DelegateCall && data.length == 24 && bytes4(data) == 0xe19a9dd9) {
            // This is setting the Guard - this should always be possible for a valid Safe transaction,
            // to prevent lock out.
            return;
        }
        
        // We have to make sure the Safe is only used to pay for transactions

        // At this point, we have checked all signatures and the threshold is not reached with unrestricted signatures.
        // The restricted signers could have the possibility to also sign a transaction, depending on the bot on which
        // this guard is used. To check this, we ask the conditionCheck, if defined, to raise the threshold if
        // allowed.
        if (conditionCheckerAddress[safe] != address(0)) {
            ConditionCheck checker = ConditionCheck(conditionCheckerAddress[safe]);


            require(
                checker.checkTransaction(safe,
                to,
                value,
                data,
                operation,
                safeTxGas,
                // Payment info
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                // Signature info
                signatures,
                msgSender
                ),
                "this transaction is not allowed by the guard checker"
            );
        }
    }
    
    function checkAfterExecution(bytes32 txHash, bool success) external
    {
        // nothing to do here
    }

}
