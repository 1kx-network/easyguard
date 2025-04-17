// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./Guard.sol";
import "hardhat/console.sol";

contract EvenValueGuard is GuardProgramVerification {
    function verify(
        TransactionContext calldata context,
        address[] calldata /*owners*/,
        address[] calldata /*signers*/
    ) external pure override returns (bool) {
        // Check if the `value` is divisible by 2
        if (context.value % 2 != 0) {
            return false;
        }
        return true;
    }
}
