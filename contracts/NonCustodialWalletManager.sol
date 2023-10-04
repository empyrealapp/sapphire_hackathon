// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Sapphire} from "./libraries/Sapphire.sol";
import {EthereumUtils, SignatureRSV} from "./libraries/EthereumUtils.sol";
import {RLPEncode} from "./libraries/RlpEncode.sol";
import {CustomEIP712} from "./types/CustomEIP712.sol";

import {INonCustodialWalletManager} from "./interfaces/INonCustodialWalletManager.sol";

import {IKeyManager} from "./interfaces/IKeyManager.sol";

interface IStrategy {
    function validate(
        uint nonce,
        uint gasPrice,
        uint gasLimit,
        address to,
        uint value,
        bytes memory data,
        uint chainId,
        bytes memory additionalEvidence
    ) external returns (bool);
}

contract NonCustodialWalletManager is
    Ownable,
    CustomEIP712,
    INonCustodialWalletManager
{
    IKeyManager keyManager;
    // address pubkeyAddr;
    // bytes32 public secretKey;
    uint256 private enclaveChainId;
    address private enclaveAddress;
    uint256 private frontendChainId;
    address private frontendAddress;

    struct Strategy {
        address signer;
        bytes32 name;
        address strategy;
        uint256 nonce;
    }

    struct Reveal {
        address signer;
        bytes32 name;
        uint256 nonce;
    }
    bytes32 private constant REVEAL_TYPEHASH =
        keccak256(
            abi.encodePacked(
                "Reveal(address signer,bytes32 name,uint256 nonce)"
            )
        );
    bytes32 private constant STRATEGY_TYPEHASH =
        keccak256(
            abi.encodePacked(
                "Strategy(address signer,bytes32 name,address strategy,uint256 nonce)"
            )
        );

    mapping(address => mapping(bytes32 => Wallet)) wallets;
    mapping(address => bytes32[]) userKeysList;
    mapping(address => mapping(uint256 => bool)) private nonces;
    mapping(address => mapping(bytes32 => IStrategy)) strategies;
    mapping(address => mapping(bytes32 => uint256)) public walletNonces;

    constructor(
        uint256 _frontendChainId,
        address _frontendAddress,
        uint256 _enclaveChainId,
        address _enclaveAddress,
        IKeyManager _keyManager
    ) CustomEIP712("Empyreal", "0.1") {
        keyManager = _keyManager;
        frontendChainId = _frontendChainId;
        frontendAddress = _frontendAddress;
        enclaveChainId = _enclaveChainId;
        enclaveAddress = _enclaveAddress;
    }

    function signForUser(
        address user,
        bytes32 name,
        uint gasPrice,
        uint gasLimit,
        address to,
        uint value,
        bytes memory data,
        uint chainId,
        bytes memory evidence
    ) external onlyOwner returns (bytes memory) {
        IStrategy strategy = strategies[user][name];
        uint256 nonce = walletNonces[user][name];
        if (
            !strategy.validate(
                nonce,
                gasPrice,
                gasLimit,
                to,
                value,
                data,
                chainId,
                evidence
            )
        ) {
            revert("Invalid Invocation");
        }
        bytes memory signature = encodeTx(
            user,
            name,
            nonce,
            gasPrice,
            gasLimit,
            to,
            value,
            data,
            chainId
        );
        walletNonces[user][name]++;
        return signature;
    }

    function setStrategy(
        Strategy calldata strategy,
        bytes memory signature,
        bool _isEnclave
    ) external {
        require(!nonces[strategy.signer][strategy.nonce], "nonce already used");
        bytes32 digest = _hashStrategy(_isEnclave, strategy);
        require(
            _verifySignature(strategy.signer, signature, digest),
            "invalid signer"
        );

        nonces[strategy.signer][strategy.nonce] = true;
        strategies[strategy.signer][strategy.name] = IStrategy(
            strategy.strategy
        );
    }

    function makeNewKey(bytes32 name) external {
        (address pubkeyAddr, bytes32 secretKey) = EthereumUtils
            .generateKeypair();

        require(
            wallets[msg.sender][name].publicKeyAddress == address(0),
            "name already set"
        );
        wallets[msg.sender][name] = Wallet({
            publicKeyAddress: pubkeyAddr,
            secretKey: secretKey
        });
        userKeysList[msg.sender].push(name);
    }

    function sign(
        address user,
        bytes32 name,
        bytes32 data
    ) internal view returns (SignatureRSV memory) {
        Wallet memory _wallet = wallets[user][name];
        return
            EthereumUtils.sign(
                _wallet.publicKeyAddress,
                _wallet.secretKey,
                data
            );
    }

    function revealPrivateKey(
        Reveal calldata reveal,
        bytes memory signature,
        bool _isEnclave
    ) external returns (bytes memory, bytes32) {
        // TODO: ensure typedData is signed by owner
        // TODO: check typed data and signature are owner

        require(!nonces[reveal.signer][reveal.nonce], "nonce already used");
        bytes32 digest = _hashReveal(_isEnclave, reveal);
        require(
            _verifySignature(reveal.signer, signature, digest),
            "invalid signer"
        );

        nonces[reveal.signer][reveal.nonce] = true;
        Wallet storage userWallet = wallets[reveal.signer][reveal.name];
        return
            keyManager.encryptForUser(
                reveal.signer,
                abi.encode(userWallet.secretKey)
            );
    }

    function verify(
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 digest,
        address pubkeyAddr
    ) external pure returns (bool) {
        return ecrecover(digest, v, r, s) == pubkeyAddr;
    }

    function encodeTx(
        address user,
        bytes32 name,
        uint nonce,
        uint gasPrice,
        uint gasLimit,
        address to,
        uint value,
        bytes memory data,
        uint chainId
    ) internal view returns (bytes memory) {
        bytes memory encodedTx;
        bytes[] memory lst = new bytes[](9);
        {
            bytes memory encodedNonce = RLPEncode.encodeUint(nonce);
            bytes memory encodedGasPrice = RLPEncode.encodeUint(gasPrice);
            bytes memory encodedGasLimit = RLPEncode.encodeUint(gasLimit);
            bytes memory encodedAddress = RLPEncode.encodeAddress(to);
            bytes memory encodedValue = RLPEncode.encodeUint(value);
            bytes memory encodedData = RLPEncode.encodeBytes(data);
            bytes memory encodedChainId = RLPEncode.encodeUint(chainId);
            lst[0] = encodedNonce;
            lst[1] = encodedGasPrice;
            lst[2] = encodedGasLimit;
            lst[3] = encodedAddress;
            lst[4] = encodedValue;
            lst[5] = encodedData;
            lst[6] = encodedChainId;
            lst[7] = RLPEncode.encodeBytes("");
            lst[8] = RLPEncode.encodeBytes("");

            encodedTx = RLPEncode.encodeList(lst);
        }

        SignatureRSV memory signature = sign(user, name, keccak256(encodedTx));

        {
            lst[6] = RLPEncode.encodeUint(chainId * 2 + 35 + signature.v - 27);
            lst[7] = RLPEncode.encodeUint(uint(signature.r));
            lst[8] = RLPEncode.encodeUint(uint(signature.s));
        }

        return RLPEncode.encodeList(lst);
    }

    function _getDomainSeperator(
        bool isEnclave
    ) private view returns (bytes32) {
        if (isEnclave) {
            return _buildEnclaveDomainSeparator();
        }
        return _buildFrontendDomainSeparator();
    }

    function _hashReveal(
        bool _isEnclave,
        Reveal calldata _msg
    ) internal view returns (bytes32) {
        return
            ECDSA.toTypedDataHash(
                _getDomainSeperator(_isEnclave),
                keccak256(
                    abi.encode(
                        REVEAL_TYPEHASH,
                        _msg.signer,
                        _msg.name,
                        _msg.nonce
                    )
                )
            );
    }

    function _hashStrategy(
        bool _isEnclave,
        Strategy calldata _msg
    ) internal view returns (bytes32) {
        return
            ECDSA.toTypedDataHash(
                _getDomainSeperator(_isEnclave),
                keccak256(
                    abi.encode(
                        STRATEGY_TYPEHASH,
                        _msg.signer,
                        _msg.name,
                        _msg.strategy,
                        _msg.nonce
                    )
                )
            );
    }

    function verifyReveal(
        bool _isEnclave,
        Reveal calldata _revealRequest,
        bytes calldata signature
    ) public view returns (bool) {
        bytes32 digest = _hashReveal(_isEnclave, _revealRequest);
        return _verifySignature(_revealRequest.signer, signature, digest);
    }

    function verifyStrategy(
        bool _isEnclave,
        Strategy calldata _strategyRequest,
        bytes calldata signature
    ) public view returns (bool) {
        bytes32 digest = _hashStrategy(_isEnclave, _strategyRequest);
        return _verifySignature(_strategyRequest.signer, signature, digest);
    }

    function _verifySignature(
        address signer,
        bytes memory signature,
        bytes32 digest
    ) internal pure returns (bool) {
        return signer == ECDSA.recover(digest, signature);
    }

    function _buildEnclaveDomainSeparator() private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _TYPE_HASH,
                    _hashedName,
                    _hashedVersion,
                    enclaveChainId,
                    enclaveAddress
                )
            );
    }

    function _buildFrontendDomainSeparator() private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _TYPE_HASH,
                    _hashedName,
                    _hashedVersion,
                    frontendChainId,
                    frontendAddress
                )
            );
    }
}
