| Severity | Title |
| -------- | -------- | 
|M-01 |using 18 decimals ERC20 tokens as reference token will cause overflow in price calculation|
|M-02 |Wrong globalLendLimit check|



## [M-01]  using 18 decimals ERC20 tokens as reference token will cause overflow in price calculation

## Vulnerability details
when using 18 decimals token as (TWAP) reference token, token price above 19 of chainlink reference token will overflow and revert in getValue ,and cause many vault function can't use.


### Impact
It will cause function getValue of oracle revert，and cause many function using _requireLoanIsHealthy or _checkLoanIsHealthy to getValue can't use.

It include function transform,borrow ,decreaseLiquidityAndCollectand liquidate.User can't transform loan,borrow asset decrease liiquidity and liquadate portion.
### Proof of Concept
https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Oracle.sol#L304-L305
For convenience, we use DAI as (TWAP) reference token（18 decimals) and 0 address (USD) as chainlink reference token，

In _getReferenceTokenPriceX96,it calculate price in Q96:
```
function _getReferenceTokenPriceX96(address token, uint256 cachedChainlinkReferencePriceX96)
        internal
        view
        returns (uint256 priceX96, uint256 chainlinkReferencePriceX96)
    {
        if (token == referenceToken) {
            return (Q96, chainlinkReferencePriceX96);
        }

        TokenConfig memory feedConfig = feedConfigs[token];

        if (feedConfig.mode == Mode.NOT_SET) {
            revert NotConfigured();
        }

        uint256 verifyPriceX96;

        bool usesChainlink = (
            feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY || feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY
                || feedConfig.mode == Mode.CHAINLINK
        );
        bool usesTWAP = (
            feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY || feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY
                || feedConfig.mode == Mode.TWAP
        );

        if (usesChainlink) {
            uint256 chainlinkPriceX96 = _getChainlinkPriceX96(token);
            chainlinkReferencePriceX96 = cachedChainlinkReferencePriceX96 == 0
                ? _getChainlinkPriceX96(referenceToken)
                : cachedChainlinkReferencePriceX96;
            chainlinkPriceX96 = (10 ** referenceTokenDecimals) * chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96
                / (10 ** feedConfig.tokenDecimals);

            if (feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY) {
                verifyPriceX96 = chainlinkPriceX96;
            } else {
                priceX96 = chainlinkPriceX96;
            }
        }

        if (usesTWAP) {
            uint256 twapPriceX96 = _getTWAPPriceX96(feedConfig);
            if (feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY) {
                verifyPriceX96 = twapPriceX96;
            } else {
                priceX96 = twapPriceX96;
            }
        }

        if (feedConfig.mode == Mode.CHAINLINK_TWAP_VERIFY || feedConfig.mode == Mode.TWAP_CHAINLINK_VERIFY) {
            _requireMaxDifference(priceX96, verifyPriceX96, feedConfig.maxDifference);
        }
    }
```
there is the revert code:
```
            chainlinkPriceX96 = (10 ** referenceTokenDecimals) * chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96
                / (10 ** feedConfig.tokenDecimals);
```
in this formulation,any token price upper 19 USD will overflow，because：

$$
10^{referenceTokenDecimals} * chainlinkPriceX96 * Q_{96} \ge 10^{18} * 19 * Q_{96} * Q_{96} = 19 * 10^{18} * Q_{192}
$$
and :

$$
Q_{64} = 2^{64} = 18446744073709551616 \lt 19 * 10^{18}
$$
So ：
$$
10^{referenceTokenDecimals} * chainlinkPriceX96 * Q_{96} \gt Q_{192} * Q_{64} = Q_{256} = 2^{256}
$$
Therefore the previous multiplication operation will cause overflow, and the price query function getValue will revert:
https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Oracle.sol#L106-L117
```
 function getValue(uint256 tokenId, address token)
        external
        view
        override
        returns (uint256 value, uint256 feeValue, uint256 price0X96, uint256 price1X96)
    {
    ...	
        (price0X96, cachedChainlinkReferencePriceX96) =
            _getReferenceTokenPriceX96(token0, cachedChainlinkReferencePriceX96);
        (price1X96, cachedChainlinkReferencePriceX96) =
            _getReferenceTokenPriceX96(token1, cachedChainlinkReferencePriceX96);

        uint256 priceTokenX96;
        if (token0 == token) {
            priceTokenX96 = price0X96;
        } else if (token1 == token) {
            priceTokenX96 = price1X96;
        } else {
            (priceTokenX96,) = _getReferenceTokenPriceX96(token, cachedChainlinkReferencePriceX96);
        }
		...
    }

```
It will cause transform,borrow ,decreaseLiquidityAndCollectand liquidate can't use.Because bad debt cannot be liquidated, so I think it is high severity.

One possible liquidation scenario is that the postion NFT‘s token0 price rises above 19USD, and token1 falls (still less than 18USD), which then causes the entire position NFT's collateral value to drop to the liquidation standard. Since the price of token1 will cause revert during liquidation, the user's postion NFT cannot be liquidated in time.

By the way,i don't think this is an issue caused by an administrator configuration error,because I didn't find any configuration about reference token in the white paper and c4 page.At the same time, 18 decimals are more commonly used in standard ERC20 tokens than other decimals tokens,It should be taken into account.
## Recommended Mitigation Steps
Use the FullMath.sol in the uniswap v3 library to perform 512-bit calculations(for example,mulDiv) to prevent overflow.

## [M-02]  Wrong globalLendLimit check

## Vulnerability details
In V3vault deposit, lend share instead of amount is mistakenly used to check whether the globalLendLimit is exceeded. As time increases, the total max available deposit amount will become more and more.
### Impact
As time increases, the total max available deposit amount will become more and more.
### Proof of Concept
https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L906-L908
In white paper:

 globalLendLimit: Limits the total lending token amount that can be deposited. It limits new deposits but does not affect existing ones.

and it is used correctly in maxDeposit and maxMint:
```
function maxDeposit(address) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        uint256 value = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up);
        if (value >= globalLendLimit) {
            return 0;
        } else {
            return globalLendLimit - value;
        }
    }
```
```
    /// @inheritdoc IERC4626
    function maxMint(address) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        uint256 value = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up);
        if (value >= globalLendLimit) {
            return 0;
        } else {
            return _convertToShares(globalLendLimit - value, lendExchangeRateX96, Math.Rounding.Down);
        }
    }
```
but it used incorrectly in function _deposit:

https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Oracle.sol#L106-L117
```
    function _deposit(address receiver, uint256 amount, bool isShare, bytes memory permitData)
        internal
        returns (uint256 assets, uint256 shares)
    {
     ···
        if (totalSupply() > globalLendLimit) {
            revert GlobalLendLimit();
        }

        if (assets > dailyLendIncreaseLimitLeft) {
            revert DailyLendIncreaseLimit();
        } else {
            dailyLendIncreaseLimitLeft -= assets;
        }

        emit Deposit(msg.sender, receiver, assets, shares);
    }
```
because vault is positive rebase token,one share represents more and more amount as time increases.So in fixed globalLendLimit,the total max available deposit amount will become more and more with time increases。

This error breaks the protocol's lend limit, so I consider it is a medium severity finding.
## Recommended Mitigation Steps
Use this in check：
```
function _deposit(address receiver, uint256 amount, bool isShare, bytes memory permitData)
    internal
    returns (uint256 assets, uint256 shares)
{
 ···
      uint256 totalAsset = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up);
      if (totalAsset > globalLendLimit) {
          revert GlobalLendLimit();
      }

    if (assets > dailyLendIncreaseLimitLeft) {
        revert DailyLendIncreaseLimit();
    } else {
        dailyLendIncreaseLimitLeft -= assets;
    }

    emit Deposit(msg.sender, receiver, assets, shares);
}
```