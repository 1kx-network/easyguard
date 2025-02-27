// SPDX-License-Identifier: None
pragma solidity >=0.8.0 <0.9.0;

import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";

interface ConditionCheck {
    function checkTransaction(
        Safe safe,
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
        address msgSender) external view returns (bool);
}
