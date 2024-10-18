| Severity | Title |
| -------- | -------- | 
|H-01 |When price is within within position's range, deposit at TokenisableRange can cause loss of fund|



## [H-01]  

## Vulnerability details
### Impact
When slot0 price is within the range of tokenized position, function deposit needs to be called with both parameters, n0 and n1, greater than zero. However, if price moves outside the range during the transaction, user will be charged an excessive fee.
### Proof of Concept
https://github.com/code-423n4/2023-08-goodentry/blob/71c0c0eca8af957202ccdbf5ce2f2a514ffe2e24/contracts/TokenisableRange.sol#L237-L247
```
if ( fee0+fee1 > 0 && ( n0 > 0 || fee0 == 0) && ( n1 > 0 || fee1 == 0 ) ){
  address pool = V3_FACTORY.getPool(address(TOKEN0.token), address(TOKEN1.token), feeTier * 100);
  (uint160 sqrtPriceX96,,,,,,)  = IUniswapV3Pool(pool).slot0();
  (uint256 token0Amount, uint256 token1Amount) = LiquidityAmounts.getAmountsForLiquidity( sqrtPriceX96, TickMath.getSqrtRatioAtTick(lowerTick), TickMath.getSqrtRatioAtTick(upperTick), liquidity);
  if (token0Amount + fee0 > 0) newFee0 = n0 * fee0 / (token0Amount + fee0);
  if (token1Amount + fee1 > 0) newFee1 = n1 * fee1 / (token1Amount + fee1);
  fee0 += newFee0;
  fee1 += newFee1; 
  n0   -= newFee0;
  n1   -= newFee1;
}
```
Suppose range is [120, 122] and current price is 121. Alice calls deposit with {n0: 100, n1:100} , if Price moves to 119 during execution (due to market fluctuations or malicious frontrunning), getAmountsForLiquidity will return 0 for token1Amount. As a result, newFee1 will be equal to n1, which means all the 100 token1 will be charged as fee.

```
(uint128 newLiquidity, uint256 added0, uint256 added1) = POS_MGR.increaseLiquidity(
  INonfungiblePositionManager.IncreaseLiquidityParams({
    tokenId: tokenId,
    amount0Desired: n0,
    amount1Desired: n1,
    amount0Min: n0 * 95 / 100,
    amount1Min: n1 * 95 / 100,
    deadline: block.timestamp
  })
);
```
Then, increaseLiquidity will succeed since amount1Min is now zero.

## Recommended Mitigation Steps
Don't use this to calculate fee:
```
if ( fee0+fee1 > 0 && ( n0 > 0 || fee0 == 0) && ( n1 > 0 || fee1 == 0 ) ){
  address pool = V3_FACTORY.getPool(address(TOKEN0.token), address(TOKEN1.token), feeTier * 100);
  (uint160 sqrtPriceX96,,,,,,)  = IUniswapV3Pool(pool).slot0();
  (uint256 token0Amount, uint256 token1Amount) = LiquidityAmounts.getAmountsForLiquidity( sqrtPriceX96, TickMath.getSqrtRatioAtTick(lowerTick), TickMath.getSqrtRatioAtTick(upperTick), liquidity);
  if (token0Amount + fee0 > 0) newFee0 = n0 * fee0 / (token0Amount + fee0);
  if (token1Amount + fee1 > 0) newFee1 = n1 * fee1 / (token1Amount + fee1);
  fee0 += newFee0;
  fee1 += newFee1; 
  n0   -= newFee0;
  n1   -= newFee1;
}
```
Always use this:
```
  uint256 TOKEN0_PRICE = ORACLE.getAssetPrice(address(TOKEN0.token));
  uint256 TOKEN1_PRICE = ORACLE.getAssetPrice(address(TOKEN1.token));
  require (TOKEN0_PRICE > 0 && TOKEN1_PRICE > 0, "Invalid Oracle Price");
  // Calculate the equivalent liquidity amount of the non-yet compounded fees
  // Assume linearity for liquidity in same tick range; calculate feeLiquidity equivalent and consider it part of base liquidity 
  feeLiquidity = newLiquidity * ( (fee0 * TOKEN0_PRICE / 10 ** TOKEN0.decimals) + (fee1 * TOKEN1_PRICE / 10 ** TOKEN1.decimals) )   
                                / ( (added0   * TOKEN0_PRICE / 10 ** TOKEN0.decimals) + (added1   * TOKEN1_PRICE / 10 ** TOKEN1.decimals) ); 
```