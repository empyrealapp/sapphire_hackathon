// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface INonCustodialWalletManager {
    struct ContractGrants {
        bool allMethods;
        /// @dev these are grants that allow for a specific selector to be invoked
        bytes8[] selectors;
        /// @dev these are grants that allow for an external address to validate the data in the call using IDataValidator
        address[] validator;
    }

    struct Grants {
        bool hasOpenAccess;
        mapping(address => ContractGrants) contractGrants;
        mapping(address => uint256) ethGrants;
        mapping(address => mapping(address => uint256)) tokenGrants;
    }

    struct Wallets {
        Wallet[] wallets;
        address owner;
    }
    struct Wallet {
        address publicKeyAddress;
        bytes32 secretKey;
    }

    event SetWallet(uint256 userId, uint256 index);
    event OwnerSet(uint256 userId, address owner);
}
