// contracts/Bridge.sol
// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.25;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./WrappedToken.sol";

contract Bridge is ReentrancyGuard {
    event TokensLockedEvent(
        address from,
        address token,
        uint256 amount,
        uint256 payment,
        string relayer,
        string recipient,
        string metadata,
        uint256 blocktime,
        uint32 chain
    );

    event TransferCompletedEvent(
        bytes txId,
        uint256 operationId
    );

    event RequestNewSignaturesEvent(
        bytes txId,
        uint256 blocktime
    );

    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);

    event SupportedWrappedTokenAdded(address indexed token);
    event SupportedWrappedTokenSetFee(address indexed token);
    event SupportedWrappedTokenRemoved(address indexed token);
    event SupportedWrappedTokenClaimFees(address indexed token);

    event SupportedTokenAdded(address indexed token);
    event SupportedTokenSetFee(address indexed token);
    event SupportedTokenRemoved(address indexed token);
    event SupportedTokenClaimFees(address indexed token);

    enum ActionId {
        ReservedAction,
        AddValidator,
        RemoveValidator,
        AddSupportedToken,
        RemoveSupportedToken,
        AddSupportedWrappedToken,
        RemoveSupportedWrappedToken,
        SetPause,
        CompleteTransfer,
        SetFeeSupportedToken,
        SetFeeSupportedWrappedToken,
        ClaimFeesSupportedToken,
        ClaimFeesSupportedWrappedToken
    }

    uint32 public chainId;
    uint256 public nonce = 1;
    mapping(bytes32 => bool) public isTransferCompleted;

    // validators
    address[] public validators;
    mapping(address => bool) public isValidator;
    mapping(address => bool) hasValidatorAlreadySigned;

    // suport tokens
    address[] public supportedTokens;
    mapping(address => bool) public isSupportedToken;
    mapping(address => uint256) public feeSupportedToken;
    mapping(address => uint256) public balanceSupportedToken;

    // suport wrapped tokens
    address[] public supportedWrappedTokens;
    mapping(address => bool) public isSupportedWrappedToken;
    mapping(address => uint256) public feeSupportedWrappedToken;
    mapping(address => uint256) public balanceSupportedWrappedToken;


    event Pause();
    event Unpause();

    bool public paused = false;

    // Address of the official WETH contract
    address public WETHAddress;

    constructor(address[] memory initialValidators, address WETHAddress_, uint256 feeWETH, uint32 _chainId) {
        require(initialValidators.length > 0, "Validators required");

        for (uint256 i = 0; i < initialValidators.length; i++) {
            address validator = initialValidators[i];

            require(validator != address(0), "Invalid validator");
            require(!isValidator[validator], "Validator not unique");

            isValidator[validator] = true;
            validators.push(validator);
        }

        WETHAddress = WETHAddress_;
        isSupportedToken[WETHAddress] = true;
        feeSupportedToken[WETHAddress] = feeWETH;
        chainId = _chainId;
    }

    function RequestNewSignatures(bytes memory txId) external whenNotPaused {
        emit RequestNewSignaturesEvent(txId, block.timestamp * 1000);
    }

    function wrapAndTransferETH(
        uint256 payment,
        string memory relayer,
        string memory recipient,
        uint32 toChain
    )
        external
        payable
        whenNotPaused
        nonReentrant
    {
        uint256 amount = msg.value;

        // add fee to balance to be claimed at some point in the future
        if(feeSupportedToken[WETHAddress] > 0) {
            require(
                amount > feeSupportedToken[WETHAddress],
                "amount must be greater than fee of bridge"
            );
            amount -= feeSupportedToken[WETHAddress];
            balanceSupportedToken[WETHAddress] += feeSupportedToken[WETHAddress];
        }

        // normalize amount, we only want to handle 8 decimals maximum on Koinos
        uint256 normalizedAmount = normalizeAmount(amount, 18);
        uint256 normalizedPayment = normalizeAmount(payment, 18);

        require(
            normalizedAmount > 0,
            "normalizedAmount amount must be greater than 0"
        );
        require(
            normalizedAmount > normalizedPayment,
            "normalizedAmount amount must be greater than normalizedPayment"
        );

        // refund dust
        uint256 dust = amount - deNormalizeAmount(normalizedAmount, 18);
        if (dust > 0) {
            payable(msg.sender).transfer(dust);
        }

        // deposit into WETH
        WETH(WETHAddress).deposit{value: amount - dust}();

        emit TokensLockedEvent(msg.sender, WETHAddress, normalizedAmount, normalizedPayment, relayer, recipient, block.timestamp * 1000, toChain);
    }

    function transferTokens(
        address token,
        uint256 amount,
        uint256 payment,
        string memory relayer,
        string memory recipient,
        string memory metadata,
        uint32 toChain
    ) external whenNotPaused nonReentrant {
        require(
            isSupportedWrappedToken[token] || isSupportedToken[token],
            "token is not supported"
        );

        // query tokens decimals
        (, bytes memory queriedDecimals) = token.staticcall(abi.encodeWithSignature("decimals()"));
        uint8 decimals = abi.decode(queriedDecimals, (uint8));

        // don't deposit dust that can not be bridged due to the decimal shift
        amount = deNormalizeAmount(normalizeAmount(amount, decimals), decimals);

        // init process
        if (isSupportedWrappedToken[token]) {
            SafeERC20.safeTransferFrom(
                IERC20(token),
                msg.sender,
                address(this),
                amount
            );

            // add fee to balance to be claimed at some point in the future
            if(feeSupportedWrappedToken[token] > 0) {
                require(
                    amount > feeSupportedWrappedToken[token],
                    "amount must be greater than fee of bridge"
                );
                amount -= feeSupportedWrappedToken[token];
                balanceSupportedWrappedToken[token] += feeSupportedWrappedToken[token];
            }

            // burn tokens after update amount
            WrappedToken(token).burn(address(this), amount);
        } else {
            // query own token balance before transfer
            (, bytes memory queriedBalanceBefore) = token.staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)));
            uint256 balanceBefore = abi.decode(queriedBalanceBefore, (uint256));

            // transfer tokens
            SafeERC20.safeTransferFrom(
                IERC20(token),
                msg.sender,
                address(this),
                amount
            );

            // query own token balance after transfer
            (, bytes memory queriedBalanceAfter) = token.staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)));
            uint256 balanceAfter = abi.decode(queriedBalanceAfter, (uint256));

            // correct amount for potential transfer fees
            amount = balanceAfter - balanceBefore;

            // add fee to balance to be claimed at some point in the future
            if(feeSupportedToken[token] > 0) {
                require(
                    amount > feeSupportedToken[token],
                    "amount must be greater than fee of bridge"
                );
                amount -= feeSupportedToken[token];
                balanceSupportedToken[token] += feeSupportedToken[token];
            }
        }

        // normalize amounts, we only want to handle 8 decimals
        uint256 normalizedAmount = normalizeAmount(amount, decimals);
        uint256 normalizedPayment = normalizeAmount(payment, decimals);

        require(
            normalizedAmount > 0,
            "normalizedAmount amount must be greater than 0"
        );
        require(
            normalizedAmount > normalizedPayment,
            "normalizedAmount amount must be greater than normalizedPayment"
        );

        emit TokensLockedEvent(msg.sender, token, normalizedAmount, normalizedPayment, relayer, recipient, metadata, block.timestamp * 1000, toChain);
    }

    function completeTransfer(
        bytes memory txId,
        uint256 operationId,
        address token,
        address relayer,
        address recipient,
        uint256 value,
        uint256 payment,
        bytes[] memory signatures,
        string memory metadata,
        uint expiration,
    ) external whenNotPaused nonReentrant {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        require(
            isSupportedWrappedToken[token] || isSupportedToken[token],
            "token is not supported"
        );

        require(
            msg.sender == relayer || msg.sender == recipient,
            "tokens can only be claimed by the recipient or relayer"
        );

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(
                abi.encodePacked(
                    uint(ActionId.CompleteTransfer),
                    txId,
                    operationId,
                    token,
                    relayer,
                    recipient,
                    value,
                    payment,
                    metadata,
                    address(this),
                    expiration,
                    chainId
                )
            )
        );

        // calculate transaction hash
        bytes32 transactionHash = getEthereumMessageHash(
            keccak256(
                abi.encodePacked(
                    txId,
                    operationId
                )
            )
        );

        require(
            !isTransferCompleted[transactionHash],
            "transfer already completed"
        );
        isTransferCompleted[transactionHash] = true;

        verifySignatures(signatures, messageHash);

        // query decimals
        (, bytes memory queriedDecimals) = token.staticcall(abi.encodeWithSignature("decimals()"));
        uint8 decimals = abi.decode(queriedDecimals, (uint8));

        // denormalize amount, we only want to handle 8 decimals
        uint256 transferAmount = deNormalizeAmount(value, decimals);

        // transfer bridged amount to recipient
        if (isSupportedWrappedToken[token]) {

            // mint wrapped asset
            WrappedToken(token).mint(address(this), transferAmount);

            // transfer asset to relayer
            if(msg.sender == relayer && payment > 0) {
                SafeERC20.safeTransfer(IERC20(token), relayer, payment);
                transferAmount -= payment;
            }

            // transfer asset to user
            SafeERC20.safeTransfer(IERC20(token), recipient, transferAmount);
        } else {

            if(token == WETHAddress) {
                // withdraw ETH from contract
                WETH(WETHAddress).withdraw(transferAmount);

                // transfer ETH to relayer
                if(msg.sender == relayer && payment > 0) {
                    safeTransferETH(recipient, payment);
                    transferAmount -= payment;
                }

                // transfer ETH to user
                safeTransferETH(recipient, transferAmount);
            } else {
                // transfer tokens to relayer
                if(msg.sender == relayer && payment > 0) {
                    SafeERC20.safeTransfer(IERC20(token), relayer, payment);
                    transferAmount -= payment;
                }

                // transfer tokens to user
                SafeERC20.safeTransfer(IERC20(token), recipient, transferAmount);
            }
        }

        emit TransferCompletedEvent(txId, operationId);
    }

    function addSupportedToken(bytes[] memory signatures, address token, uint256 fee, uint expiration)
        external
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        require(!isSupportedToken[token], "Token already exists");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.AddSupportedToken), token, fee, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);

        isSupportedToken[token] = true;
        feeSupportedToken[token] = fee;
        supportedTokens.push(token);
        nonce += 1;

        emit SupportedTokenAdded(token);
        (token);
    }

    function setFeeSupportedToken(bytes[] memory signatures, address token, uint256 fee, uint expiration)
        external
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        require(isSupportedToken[token], "Token does not exist");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.SetFeeSupportedToken), token, fee, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);
        feeSupportedToken[token] = fee;
        nonce += 1;
        emit SupportedTokenSetFee(token);
    }

    function removeSupportedToken(bytes[] memory signatures, address token, uint expiration)
        external
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        require(isSupportedToken[token], "Token does not exist");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.RemoveSupportedToken), token, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);

        isSupportedToken[token] = false;
        feeSupportedToken[token] = 0;
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) removeSupportedTokenByIndex(i);
        }
        nonce += 1;

        emit SupportedTokenRemoved(token);
    }

    function addSupportedWrappedToken(bytes[] memory signatures, address token, uint256 fee, uint expiration)
        external
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );
    
        require(!isSupportedWrappedToken[token], "Token already exists");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.AddSupportedWrappedToken), token, fee, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);

        isSupportedWrappedToken[token] = true;
        feeSupportedWrappedToken[token] = fee;
        supportedWrappedTokens.push(token);
        nonce += 1;

        emit SupportedWrappedTokenAdded(token);
    }

    function setFeeSupportedWrappedToken(bytes[] memory signatures, address token, uint256 fee, uint expiration)
        external 
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );
    
        require(isSupportedWrappedToken[token], "Token does not exist");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.SetFeeSupportedWrappedToken), token, fee, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);

        feeSupportedWrappedToken[token] = fee;
        nonce += 1;
        emit SupportedWrappedTokenSetFee(token);
    }

    function removeSupportedWrappedToken(
        bytes[] memory signatures,
        address token,
        uint expiration
    ) external {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        require(isSupportedWrappedToken[token], "Token does not exist");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.RemoveSupportedWrappedToken), token, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);

        isSupportedWrappedToken[token] = false;
        feeSupportedWrappedToken[token] = 0;
        for (uint256 i = 0; i < supportedWrappedTokens.length; i++) {
            if (supportedWrappedTokens[i] == token)
                removeSupportedWrappedTokenByIndex(i);
        }
        nonce += 1;

        emit SupportedWrappedTokenRemoved(token);
    }

    function addValidator(bytes[] memory signatures, address validator, uint expiration)
        external
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        require(!isValidator[validator], "Validator already exists");

        bytes32 messageHash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.AddValidator), validator, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, messageHash);

        isValidator[validator] = true;
        validators.push(validator);
        nonce += 1;

        emit ValidatorAdded(validator);
    }

    function removeValidator(bytes[] memory signatures, address validator, uint expiration)
        external
    {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );
    
        require(isValidator[validator], "Validator does not exist");

        bytes32 hash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.RemoveValidator), validator, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, hash);

        isValidator[validator] = false;
        nonce += 1;

        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == validator) removeValidatorByIndex(i);
        }

        emit ValidatorRemoved(validator);
    }

    function claimFeeTokens(bytes[] memory signatures, address token, address wallet, uint expiration) external {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        // verify signatures
        bytes32 hash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.ClaimFeesSupportedToken), token, wallet, nonce, address(this), expiration, chainId))
        );
        verifySignatures(signatures, hash);
        uint256 balance = balanceSupportedToken[token];
        require( balance > 0, "balance must be greater than 0");
        SafeERC20.safeTransfer(IERC20(token), wallet, balance);
        balanceSupportedToken[token] = 0;
        nonce += 1;
        emit SupportedTokenClaimFees(token);
    }

    function claimFeeWrappTokens(bytes[] memory signatures, address token, address wallet, uint expiration) external {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        // verify signatures
        bytes32 hash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.ClaimFeesSupportedWrappedToken), token, wallet, nonce, address(this), expiration, chainId))
        );
        verifySignatures(signatures, hash);
        uint256 balance = balanceSupportedWrappedToken[token];
        require( balance > 0, "balance must be greater than 0");
        SafeERC20.safeTransfer(IERC20(token), wallet, balance);
        balanceSupportedWrappedToken[token] = 0;
        nonce += 1;
        emit SupportedWrappedTokenClaimFees(token);
    }


    function verifySignatures(bytes[] memory signatures, bytes32 hash)
        internal
    {
        require(
            signatures.length >= (validators.length * 5 + 10) / 9,
            "quorum not met"
        );

        bool approved = true;

        address[] memory signers = new address[](signatures.length);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(hash, signatures[i]);
            if (isValidator[signer] && !hasValidatorAlreadySigned[signer]) {
                hasValidatorAlreadySigned[signer] = true;
                signers[i] = signer;
            } else {
                approved = false;
            }
        }

        require(approved, "invalid signatures");

        for (uint256 i = 0; i < signers.length; i++) {
            hasValidatorAlreadySigned[signers[i]] = false;
        }
    }

    function recoverSigner(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length != 65) {
            return (address(0));
        }

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            return ecrecover(hash, v, r, s);
        }
    }

    function getEthereumMessageHash(bytes32 hash)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    function normalizeAmount(uint256 amount, uint8 decimals)
        internal
        pure
        returns (uint256)
    {
        if (decimals > 8) {
            amount /= 10**(decimals - 8);
        }

        if ( decimals < 8 ) {
            amount *= 10**(8 - decimals);
        }

        return amount;
    }

    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'safeTransferETH: ETH transfer failed');
    }

    function deNormalizeAmount(uint256 amount, uint8 decimals)
        internal
        pure
        returns (uint256)
    {
        if (decimals > 8) {
            amount *= 10**(decimals - 8);
        }

        if (decimals < 8) {
            amount /= 10**(8 - decimals);
        }

        return amount;
    }

    function removeSupportedTokenByIndex(uint256 index) internal {
        require(index < supportedTokens.length, "index out of bound");

        for (uint256 i = index; i < supportedTokens.length - 1; i++) {
            supportedTokens[i] = supportedTokens[i + 1];
        }
        supportedTokens.pop();
    }

    function removeSupportedWrappedTokenByIndex(uint256 index) internal {
        require(index < supportedWrappedTokens.length, "index out of bound");

        for (uint256 i = index; i < supportedWrappedTokens.length - 1; i++) {
            supportedWrappedTokens[i] = supportedWrappedTokens[i + 1];
        }
        supportedWrappedTokens.pop();
    }

    function removeValidatorByIndex(uint256 index) internal {
        require(index < validators.length, "index out of bound");

        for (uint256 i = index; i < validators.length - 1; i++) {
            validators[i] = validators[i + 1];
        }
        validators.pop();
    }

    function getSupportedTokensLength() public view returns (uint256) {
        return supportedTokens.length;
    }

    function getSupportedWrappedTokensLength() public view returns (uint256) {
        return supportedWrappedTokens.length;
    }

    function getValidatorsLength() public view returns (uint256) {
        return validators.length;
    }


    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     */
    modifier whenNotPaused() {
        require(!paused, "Bridge is paused");
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     */
    modifier whenPaused() {
        require(paused, "Bridge is not paused");
        _;
    }

    function pause(bytes[] memory signatures, uint expiration) public whenNotPaused {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );

        bytes32 hash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.SetPause), true, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, hash);

        paused = true;
        nonce += 1;

        emit Pause();
    }

    function unpause(bytes[] memory signatures, uint expiration) public whenPaused {
        require(
            expiration >= block.timestamp * 1000,
            "expired signatures"
        );
    
        bytes32 hash = getEthereumMessageHash(
            keccak256(abi.encodePacked(uint(ActionId.SetPause), false, nonce, address(this), expiration, chainId))
        );

        verifySignatures(signatures, hash);

        paused = true;
        nonce += 1;

        paused = false;
        emit Unpause();
    }

    fallback() external payable {
        revert("please use wrapAndTransferETH to transfer ETH to Koinos");
    }

    receive() external payable {
        revert("please use wrapAndTransferETH to transfer ETH to Koinos");
    }
}

interface WETH is IERC20 {
    function deposit() external payable;

    function withdraw(uint256 amount) external;
}
