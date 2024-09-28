| Severity | Title |
| -------- | -------- | 
|M-01 |Blacklisted user could still mint `USD0`|
|L-01 |`requiredUsd0Amount` and `totalUsd0Provided` difference will lead to unexpected revert|


## [M-01] Blacklisted user could still mint `USD0`

## Vulnerability details
### Description
In the DaoCollateral contract, if a user is blacklisted by the `USD0` token, they are prevented from performing swap or redeem operations, as they cannot mint or burn `USD0` to/in their address. However, these restrictions do not apply to the `swapRWAtoStbc` and `swapRWAtoStbcIntent` functions, allowing a blacklisted user to temporarily mint `USD0` on the `DaoCollateral` contract address and swap Real World Assets (RWA) for `USDC`. This bypasses the blacklist mechanism and undermines the intended restrictions on blacklisted users as a blacklisted user can use the protocol to swap `RWA` for `USDC`, even minting `USD0` (though not directly to their address).

### Proof of Concept

In the `DaoCollateral` contract, if a user is blacklisted by the `USD0` token, they cannot swap or redeem since they are unable to mint or burn USD0. However, the functions `swapRWAtoStbc` and `swapRWAtoStbcIntent` do not check the blacklist status of the user. As a result, a blacklisted user can still mint USD0 temporarily on the DaoCollateral contract address to swap RWA for USDC.

This is because in function `_swapRWAtoStbc`, the USD0 is minted on `address(this)` which is not blacklisted.
```solidity
    $.usd0.mint(address(this), wadRwaQuoteInUSD);
    ...
    $.usd0.burnFrom(address(this), wadRwaNotTakenInUSD);
```
This allows a blacklisted user to bypass the blacklist mechanism and use the protocol to swap RWA for USDC, even minting USD0 (though not directly to their address).

## Recommended Mitigation Steps
Add a blacklist check in the `swapRWAtoStbc` and `swapRWAtoStbcIntent` functions to ensure that blacklisted users are unable to perform these operations.




## [L-01] `requiredUsd0Amount` and `totalUsd0Provided` difference will lead to unexpected revert

## Vulnerability details
### Description
The `provideUsd0ReceiveUSDC` and `provideUsd0ReceiveUSDCWithPermit` functions calculate requiredUsd0Amount using `_getUsd0WadEquivalent(amountUsdcToTakeInNativeDecimals, usdcWadPrice)`. Due to rounding issues in `_getUsd0WadEquivalent`, this value does not strictly equal `totalUsd0Provided`. Consequently, transactions that should have succeed may unexpectedly revert due to strict checks, leading to unexpected protocol behavior and reverts.
### Proof of Concept

In the `provideUsd0ReceiveUSDC` and `provideUsd0ReceiveUSDCWithPermit` functions, `requiredUsd0Amount` is calculated as follows:`
```solidity
        uint256 requiredUsd0Amount =

            _getUsd0WadEquivalent(amountUsdcToTakeInNativeDecimals, usdcWadPrice);
```
However, the actual amount of Usd0 spent is calculated using `totalUsd0Provided`, which is the sum of `usd0Amount` in `_provideUsd0ReceiveUSDC`:
```solidity
        uint256 usd0Amount = _getUsd0WadEquivalent(amountOfUsdcFromOrder, usdcWadPrice);

        totalUsd0Provided += usd0Amount;
```
The contract strictly assumes that: `$.usd0.balanceOf(msg.sender) >= requiredUsd0Amount` and `$.usd0.balanceOf(msg.sender) >= requiredUsd0Amount && usd0ToPermit >= requiredUsd0Amount`.
```solidity
        if ($.usd0.balanceOf(msg.sender) < requiredUsd0Amount || usd0ToPermit < requiredUsd0Amount)
        {
            revert InsufficientUSD0Balance();
        }
```
Due to rounding issues in `wadAmountByPrice`, `_getUsd0WadEquivalent` function can cause discrepancies:
```solidity
    usd0WadEquivalent = usdcWad.wadAmountByPrice(usdcWadPrice);
    function wadAmountByPrice(uint256 wadAmount, uint256 wadPrice)
        internal
        pure
        returns (uint256)
    {
        return Math.mulDiv(wadAmount, wadPrice, SCALAR_ONE, Math.Rounding.Floor);
    }
```
So, the calculation will be `usdcAmount * 1e12 * wadPrice / 1e18`.

For example:

1. if `wadPrice = 1e18 -1 = 999,999,999,999,999,999` (almost $1), `usdc = 100,000,571` (about $100), the result is `100,000,570,999,999,999,899.999429`(about $100), rounded to `100,000,570,999,999,999,899`.

2. For `2` orders with `[100,000,571,100,000,571]` in USDC. We will have `requiredUsd0Amount = (100,000,571 × 2) × 999,999,999,999,999,999 / 1,000,000 = 200,001,141,999,999,999,799.998858`, rounded to  `200,001,141,999,999,999,799`.

However, `totalUsd0Provided` is `2 * 100,000,570,999,999,999,899 = 200,001,141,999,999,999,798` which differs from `requiredUsd0Amount`.

Thus, if a user correctly calculates `totalUsd0Provided` and approves or permits the correct amount, his transaction could still revert due to `Rounding(sum(Arr)) != sum(Rounding(Arr[i]))`.

## Recommended Mitigation Steps
To mitigate this issue, consider the following:

- Remove the check, in fact, the function will revert if there is no enough balance or approval.
- Calculate `requiredUsd0Amount` in the same way as `totalUsd0Provided`.


