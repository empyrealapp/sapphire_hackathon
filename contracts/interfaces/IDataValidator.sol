// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IDataValidator {
    function validateData(
        address owner,
        address caller,
        address invokedContract,
        bytes memory data
    ) external returns (bool);
}
