// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract TestContract {
    uint256 private value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
} 