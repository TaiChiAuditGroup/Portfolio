| Severity | Title |
| -------- | -------- | 
|H-01 |Incorrect approve usage in `TokenManager::_transfer` and Missing Approve Call in `TokenManager::withdraw`|
|H-02 |Memory Struct Changes Doesn't Reflect on Storage for `originOfferInfo`|
|H-03 |Inconsistency in Update and Usage of `ReferralInfo`|
|H-04 |`userTokenBalanceMap` is Not Changed After `Withdraw`|
|M-01 |`WrappedNativeToken` Can Only Work in `NativeToken` Mode|
|M-02 |Current Accounting Incompatible With Some ERC20s|


## [H-01] Incorrect approve usage in `TokenManager::_transfer` and Missing Approve Call in `TokenManager::withdraw`

## Vulnerability details
### Description
The `CapitalPool::approve` function is intended to approve the `tokenAddr` for maximum allowance to the `tokenManager`. However, in the `TokenManager::_transfer` function, an incorrect argument `address(this)` is passed to `ICapitalPool(_capitalPoolAddr).approve`, which should actually be `_token`. This mistake causes the approval to revert unexpectedly. Furthermore, the `TokenManager::withdraw` function fails to call approve when `_tokenAddress != wrappedNativeToken` when the allowance is 0, potentially leading to issues when `CapitalPool::approve` has not been called for this `_tokenAddress` before.

**Issue 1: Incorrect Argument in TokenManager::\_transfer**

The `CapitalPool::approve` function receives `tokenAddr` and calls `tokenAddr.approve(tokenManager, type(uint256).max)`:

```solidity
    /**
     * @dev Approve token for token manager
     * @notice only can be called by token manager
     * @param tokenAddr address of token
     */
    function approve(address tokenAddr) external {
        address tokenManager = tadleFactory.relatedContracts(
            RelatedContractLibraries.TOKEN_MANAGER
        );
 @=>    (bool success, ) = tokenAddr.call(
            abi.encodeWithSelector(
                APPROVE_SELECTOR,
                tokenManager,
                type(uint256).max
            )
        );

        if (!success) {
            revert ApproveFailed();
        }
    }
```

However, in the `TokenManager::_transfer` function, the following code calls `ICapitalPool(_capitalPoolAddr).approve(address(this))`:

```solidity
        if (
            _from == _capitalPoolAddr &&
            IERC20(_token).allowance(_from, address(this)) == 0x0
        ) {
            ICapitalPool(_capitalPoolAddr).approve(address(this)); 
        }
```

In this code, the `address(this)` argument passed to `approve` is incorrect; it should be `_token` instead. Passing `address(this)` as the argument results in the approval being called on the wrong address, which will not allow the `tokenManager` to spend tokens as intended. This mistake causes the approval process to fail and the transaction to revert unexpectedly.

The PoC is shown below:

```solidity
    function test_approve_fails() public {
        test_ask_offer_turbo_eth();
        vm.prank(user);
        tokenManager.withdraw(address(weth9), TokenBalanceType.SalesRevenue);
    }
```

The log shows the `approve` call fails since there is no `approve` in the contract `TokenManager`.

```Solidity
...
WETH9::allowance(UpgradeableProxy: [0x76006C4471fb6aDd17728e9c9c8B67d5AF06cDA0], UpgradeableProxy: [0x6891e60906DEBeA401F670D74d01D117a3bEAD39]) [staticcall]
    │   │   │   └─ ← [Return] 0
    │   │   ├─ [9999] UpgradeableProxy::approve(UpgradeableProxy: [0x6891e60906DEBeA401F670D74d01D117a3bEAD39])
    │   │   │   ├─ [4983] CapitalPool::approve(UpgradeableProxy: [0x6891e60906DEBeA401F670D74d01D117a3bEAD39]) [delegatecall]
    │   │   │   │   ├─ [534] TadleFactory::relatedContracts(5) [staticcall]
    │   │   │   │   │   └─ ← [Return] UpgradeableProxy: [0x6891e60906DEBeA401F670D74d01D117a3bEAD39]
    │   │   │   │   ├─ [708] UpgradeableProxy::approve(UpgradeableProxy: [0x6891e60906DEBeA401F670D74d01D117a3bEAD39], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77])
    │   │   │   │   │   ├─ [192] TokenManager::approve(UpgradeableProxy: [0x6891e60906DEBeA401F670D74d01D117a3bEAD39], 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Revert] EvmError: Revert
    │   │   │   │   │   └─ ← [Revert] EvmError: Revert
    │   │   │   │   └─ ← [Revert] ApproveFailed()
    │   │   │   └─ ← [Revert] ApproveFailed()
    │   │   └─ ← [Revert] ApproveFailed()
    │   └─ ← [Revert] ApproveFailed()
    └─ ← [Revert] ApproveFailed()
```

**Issue 2: Missing Allowance Check and Approval Call in TokenManager::withdraw**

In the `TokenManager::withdraw` function, the `approve` function is not called when `_tokenAddress != wrappedNativeToken`. The code directly attempts to transfer tokens from the `capitalPoolAddr` without checking if the `CapitalPool::approve` has been called for the specific `_tokenAddress` to have sufficient allowance.

```solidity
        if (_tokenAddress == wrappedNativeToken) {
@=>	        _transfer( // Check and Call Approve Here
                wrappedNativeToken,
                capitalPoolAddr,
                address(this),
                claimAbleAmount,
                capitalPoolAddr
            );
            ...
        } else {
            /**
             * @dev token is ERC20 token
             * @dev transfer from capital pool to msg sender
             */
@=>          _safe_transfer_from( // No check and No approve
                _tokenAddress,
                capitalPoolAddr,
                _msgSender(),
                claimAbleAmount
            );
        }
```

## Recommended Mitigation Steps
* Modify the `TokenManager::_transfer` function to pass the correct `_token` parameter to the `approve` function, ensuring that the approval is correctly set up for the intended token:
* Ensure that the `approve` function is also called within `TokenManager::withdraw` when `_tokenAddress != wrappedNativeToken`. This can be done by checking the allowance and approving the necessary amount before performing the token transfer.


## [H-02] Memory Struct Changes Doesn't Reflect on Storage for `originOfferInfo`

## Vulnerability details
### Description

In the `PreMarkets::listOffer` function, the `originOfferInfo.abortOfferStatus` is intended to be updated to `AbortOfferStatus.SubOfferListed` to prevent the offer from being aborted. However, because `originOfferInfo` is a memory copy rather than a storage reference, changes made to `originOfferInfo` do not persist in the `offerInfoMap[originOffer].` This oversight leads to the `abortOfferStatus` update having no effect, allowing the check in `abortAskOffer` to be bypassed and resulting in the potential incorrect abortion of the ask offer.

The vulnerability arises from the following code in the `PreMarkets::listOffer` function:

```solidity
        if (makerInfo.offerSettleType == OfferSettleType.Turbo) {
            address originOffer = makerInfo.originOffer;
@=>         OfferInfo memory originOfferInfo = offerInfoMap[originOffer];

            if (_collateralRate != originOfferInfo.collateralRate) {
                revert InvalidCollateralRate();
            }
@=>         originOfferInfo.abortOfferStatus = AbortOfferStatus.SubOfferListed; // status if not written back
        }
```

Here, the `originOfferInfo` variable is declared as a memory reference, which creates a copy of the data from `offerInfoMap[originOffer]` rather than a reference to the actual storage data. When `originOfferInfo.abortOfferStatus` is updated, the change is made to the in-memory copy, not the actual storage value in `offerInfoMap`.

As a result, the update to `abortOfferStatus` does not persist, and the `abortOfferStatus` remains unchanged in storage.

The unchanged `abortOfferStatus` is later checked in the `abortAskOffer function`:

```solidity
function abortAskOffer(address _stock, address _offer) external {
	...
	if (offerInfo.abortOfferStatus != AbortOfferStatus.Initialized) {
		revert InvalidAbortOfferStatus(
			AbortOfferStatus.Initialized,
			offerInfo.abortOfferStatus
		);
	}
	...
}
```

Because the `abortOfferStatus` was not correctly updated, this check can be bypassed, allowing an offer to be incorrectly aborted, potentially causing disruptions or unexpected behavior in the market.

The impact of this vulnerability is significant as it undermines the logic designed to prevent the incorrect abortion of ask offers. By bypassing the `abortOfferStatus` check, offers that should not be aborted can be aborted, leading to potential financial loss or market instability.


## Recommended Mitigation Steps
To fix this issue, the `originOfferInfo` should be a storage reference rather than a memory copy. This ensures that any updates to `originOfferInfo` are directly reflected in the `offerInfoMap` storage.



## [H-03] Inconsistency in Update and Usage of `ReferralInfo`


## Vulnerability details
### Description
In the `SystemConfig::updateReferrerInfo` function, the `referralInfoMap` is mistakenly updated for the `_referrer` instead of the `_msgSender()`. This allows anyone to modify the `referralInfo` for other users, which results in several issues:

1. Anyone can modify another user’s `referralInfoMap`.
2. When a user tries to update his own `referralInfo`, the update is ineffective.
3. If a `_referrer` later uses `PreMarkets::createTaker`, the `referrerReferralBonus` could be wrongly attributed to himself, leading to incorrect self-referral bonuses.

In the `SystemConfig::updateReferrerInfo` function, the following code incorrectly updates the `referralInfoMap`:

```solidity
    function updateReferrerInfo(
        address _referrer,
        uint256 _referrerRate,
        uint256 _authorityRate
    ) external {
@=>     if (_msgSender() == _referrer) {
            revert InvalidReferrer(_referrer);
        }
        ...
@=>     ReferralInfo storage referralInfo = referralInfoMap[_referrer];
@=>     referralInfo.referrer = _referrer;
        referralInfo.referrerRate = _referrerRate;
        referralInfo.authorityRate = _authorityRate;
        ...
    }	
```

This causes the `referralInfoMap` to be incorrectly updated for `_referrer`, not `_msgSender()`. This becomes problematic when `referralInfoMap` is later queried in `PreMarkets::createTaker`:

```solidity
function createTaker(address _offer, uint256 _points) external payable {
	...
	
	ReferralInfo memory referralInfo = systemConfig.getReferralInfo(
@=>		_msgSender()
	);

	...

	uint256 remainingPlatformFee = _updateReferralBonus(
		platformFee,
		depositAmount,
		stockAddr,
		makerInfo,
@=>		referralInfo,
		tokenManager
	);
	
}


    function _updateReferralBonus(
        uint256 platformFee,
        uint256 depositAmount,
        address stockAddr,
        MakerInfo storage makerInfo,
        ReferralInfo memory referralInfo,
        ITokenManager tokenManager
    ) internal returns (uint256 remainingPlatformFee) {
		...
		tokenManager.addTokenBalance(
			TokenBalanceType.ReferralBonus,
@=>			referralInfo.referrer,
			makerInfo.tokenAddress,
			referrerReferralBonus
		);	
		...
	}
```

The assignment and usage of `referralInfoMap` is actually inconsistent:\
\- User `A` could set `referralInfoMap` info for User `B`, and he can't set it for himself.\
\- When User `A` calls `createTaker`, `referralInfoMap[A]` is queried instead of `referralInfoMap[B]`.

This inconsistency causes several problems:

1. Anyone can modify the `referralInfoMap` for any other user.
2. Updates by users to their own referral information are ineffective.
3. If `_referrer` uses `PreMarkets::createTaker`, the referral bonus could wrongly go to himself, creating an invalid self-referral scenario.

This issue could have a **Medium to High** impact:

1. Anyone can modify the `referralInfoMap` for any other user.
2. Updates by users to their own referral information are ineffective.
3. If `_referrer` uses `PreMarkets::createTaker`, the referral bonus could wrongly go to himself, creating an invalid self-referral scenario.


## Recommended Mitigation Steps
To resolve this issue, modify the` updateReferrerInfo` function so that it updates `referralInfoMap` for `_msgSender()` instead of `_referrer`. This will ensure that users can only update their own referral info and prevent the issues described above. Otherwise, refactor how the `ReferralInfo` is being used.



## [H-04] `userTokenBalanceMap` is Not Changed After `Withdraw`



## Vulnerability details
### Description

The `TokenManager::withdraw` function in the `Tadle` system allows users to withdraw claimable funds from the `CapitalPool`. However, the function fails to update the `userTokenBalanceMap` after a withdrawal, allowing users to repeatedly withdraw the same funds multiple times. This oversight can lead to the complete draining of the `CapitalPool`.

The `userTokenBalanceMap` in the `TokenManager` contract tracks the claimable token balance for each user. The `TokenManager::withdraw` function allows users to withdraw these claimable funds. However, the function does not update the `userTokenBalanceMap` after a withdrawal is made, which creates a critical vulnerability.

```solidity
    function withdraw(
        address _tokenAddress,
        TokenBalanceType _tokenBalanceType
    ) external whenNotPaused {
@=>     uint256 claimAbleAmount = userTokenBalanceMap[_msgSender()][
            _tokenAddress
        ][_tokenBalanceType];

        if (claimAbleAmount == 0) {
            return;
        }

        address capitalPoolAddr = tadleFactory.relatedContracts(
            RelatedContractLibraries.CAPITAL_POOL
        );

        if (_tokenAddress == wrappedNativeToken) {
            /**
             * @dev token is native token
             * @dev transfer from capital pool to msg sender
             * @dev withdraw native token to token manager contract
             * @dev transfer native token to msg sender
             */
            _transfer(
                wrappedNativeToken,
                capitalPoolAddr,
                address(this),
                claimAbleAmount,
                capitalPoolAddr
            );

            IWrappedNativeToken(wrappedNativeToken).withdraw(claimAbleAmount);
            payable(msg.sender).transfer(claimAbleAmount);
        } else {
            /**
             * @dev token is ERC20 token
             * @dev transfer from capital pool to msg sender
             */
            _safe_transfer_from(
                _tokenAddress,
                capitalPoolAddr,
                _msgSender(),
                claimAbleAmount
            );
        }

        emit Withdraw(
            _msgSender(),
            _tokenAddress,
            _tokenBalanceType,
            claimAbleAmount
        );
    }
```

The function retrieves the claimable amount from `userTokenBalanceMap` but does not reset this balance after the withdrawal. As a result, users can repeatedly call the withdraw function to withdraw the same amount of tokens multiple times. This oversight can lead to the complete draining of the `CapitalPool`for a specific ERC20 token.

The vulnerability has a **high impact** as it allows users to repeatedly withdraw funds, leading to the potential depletion of the `CapitalPool`. This could result in significant financial losses and a complete failure of the system’s economic model.

## Recommended Mitigation Steps
The `userTokenBalanceMap` should be updated after a withdrawal to prevent further claims on the same funds. Specifically, set the user’s balance to zero after the withdrawal.


## [M-01] `WrappedNativeToken` Can Only Work in `NativeToken` Mode

In the `TokenManager::tillIn` function, if `_tokenAddress` is equal to `wrappedNativeToken`, the function directly assumes that a native token is being used and checks `msg.value` for sufficient funds. This approach limits the functionality of `wrappedNativeToken` when it is used as an ERC-20 token, leading to unintended transaction reverts even when the user has approved sufficient funds.

The `TokenManager::tillIn` function has a conditional check that determines if the `_tokenAddress` is equal to `wrappedNativeToken`. If this condition is met, the function assumes that the transaction involves the native token (e.g., ETH) and checks if `msg.value` is greater than or equal to `_amount`. If `msg.value` is insufficient, the transaction reverts:

```solidity
        if (_tokenAddress == wrappedNativeToken) {
            /**
             * @dev token is native token
             * @notice check msg value
             * @dev if msg value is less than _amount, revert
             * @dev wrap native token and transfer to capital pool
             */
            if (msg.value < _amount) {
                revert Errors.NotEnoughMsgValue(msg.value, _amount);
            }
            IWrappedNativeToken(wrappedNativeToken).deposit{value: _amount}();
            _safe_transfer(wrappedNativeToken, capitalPoolAddr, _amount);
        } 
```

This implementation does not consider cases where `wrappedNativeToken` (e.g., `WETH`) is being used as a regular ERC-20 token in functions like `PreMarkets::createOffer`. In such cases, even if the user has already approved sufficient `WETH`, the transaction would still revert due to the insufficient `msg.value`, causing unintended reverts.

Consider the following case:

1. A user intends to use `wrappedNativeToken` (e.g., `WETH`) directly in `PreMarkets::createOffer`.
2. Despite having approved enough `WETH`, the transaction would still revert because `msg.value` does not match the `_amount` required, leading to an unintended failure.

This issue restricts the flexibility of using `wrappedNativeToken` as an ERC-20 token and can lead to unintended transaction failures. Users attempting to interact with the contract using `wrappedNativeToken` which is a normal/frequent case may face unexpected reverts, hindering the user experience and limiting contract functionality.


## Recommended Mitigation Steps
To address this issue, it is recommended to introduce a separate address that explicitly represents the native token (e.g., `ETH`). For example, the commonly used address `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` could be utilized to signify the native token. The condition should then differentiate between `wrappedNativeToken` (used as an ERC-20 token) and the native token (ETH) itself:


## [M-02] Current Accounting Incompatible With Some ERC20s

The `Tadle` system is expected to be compatible with `ETH, WETH, and any token following the ERC20 standard`. However, the current implementation is incompatible with certain types of ERC20 tokens, such as **Fee-on-transfer tokens, Rebase tokens, stETH, and tokens that return false instead of reverting on failure**. This incompatibility can lead to accounting issues, unexpected transaction failures, and potential denial-of-service (DoS) on the system.

According to the documentation, Tadle should support the [following token types](https://github.com/Cyfrin/2024-08-tadle/blob/04fd8634701697184a3f3a5558b41c109866e5f8/README.md#L104-L107):

```solidity
  Tokens:
      - ETH
      - WETH
      - ERC20 (any token that follows the ERC20 standard)
```

However, the system fails to account for certain types of tokens, even if they technically adhere to the ERC20 standard. The following issues arise:

**Case 1: Fee-on-transfer Tokens**

Fee-on-transfer tokens deduct a certain fee during transfers. The current implementation of `TokenManager::_transfer` checks the `toBalanceBef` and `toBalanceAft` as follows:

```solidity
        if (toBalanceAft != toBalanceBef + _amount) {
            revert TransferFailed();
        }
```

This logic fails with **Fee-on-transfer** tokens because the amount transferred to the recipient will be less than `_amount` due to the `fee`. As a result, the transaction will revert with a `TransferFailed` error, making the system incompatible with these tokens.

**Case 2: Rebase Tokens**

Rebase tokens automatically adjust the balance of users over time. In such cases, the deposited amount may not directly correspond to the `withdrawal share`, leading to discrepancies in accounting. This could result in funds being locked in the contract or users losing access to their full balance.

**Case 3: stETH**

It is known for `stETH` that is has [1 wei corner case](https://github.com/lidofinance/lido-dao/issues/442) where a discrepancy of 1 wei may occur during transfers. The current implementation of `TokenManager::_transfer` strictly checks the sender’s balance before and after the transfer:`TokenManager::_transfer`:

```solidity
        if (fromBalanceAft != fromBalanceBef - _amount) {
            revert TransferFailed();
        }
```

When this corner case occurs, the transaction will fail, making the system incompatible with `stETH`.

**Case 4: Tokens that return `False` instead of reverting.**\
Some tokens, such as [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code) and [EURS](https://etherscan.io/token/0xdb25f211ab05b1c97d595516f45794528a807ad8#code), do not revert on failure but instead return false. The current implementation in `Rescue::_safe_transfer` and `Rescue::_safe_transfer_from` which is used in `TokenManager` does not account for this behavior:

```solidity
        (bool success, ) = token.call(
            abi.encodeWithSelector(TRANSFER_FROM_SELECTOR, from, to, amount)
        );

        if (!success) {
            revert TransferFailed();
        }
```

If the token returns false instead of reverting, the function will not revert as expected, leading to unintended consequences such as incorrect token transfers or accounting errors.

The issues identified can cause significant problems, including:

1. **Incompatibility with Fee-on-Transfer Tokens:** Transactions involving these tokens will fail, making the system unusable for users holding such tokens.
2. **Accounting Issues with Rebase Tokens:** Users may lose access to their full balances due to incorrect accounting, leading to potential loss of funds.
3. **Failure with `stETH`:** The 1 wei corner case can cause transactions to fail, preventing users from transferring or withdrawing stETH.
4. **Unintended Consequences with Non-Reverting Tokens:** Tokens that return false instead of reverting can cause the system to behave unexpectedly, leading to incorrect token transfers or failed operations.


## Recommended Mitigation Steps
1. **Revise the Design of Accounting:** The system should be updated to handle the unique behaviors of Fee-on-transfer tokens, Rebase tokens, stETH, and tokens that return false on failure. This may involve implementing specific logic to handle these cases.
2. **Update Documentation:** If supporting these tokens is not feasible, the documentation should be updated to clearly state the limitations and specify which types of tokens are supported.








