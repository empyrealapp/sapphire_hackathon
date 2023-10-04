// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IKeyManager {
    function encryptForUser(
        address user,
        bytes memory message
    ) external view returns (bytes memory, bytes32);

    function signingAddress() external view returns (address);
}
