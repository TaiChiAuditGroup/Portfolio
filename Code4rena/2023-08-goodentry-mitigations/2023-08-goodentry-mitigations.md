| Severity | Title |
| -------- | -------- | 
|H-01 |removeFromAllTicks should be done before getTVL|
|H-02 |Attacker can extract value from pool by sandwiching herself at swapAll during close|
|M-01 |Use of tx.origin breaks interoperability with AA wallets.|
|M-02 |getActiveTickIndex returns wrong index|



## [H-01]  removeFromAllTicks should be done before getTVL

## Vulnerability details
After the mitigation, the TR fee is directly sent to GE vault. Suppose 0.1 eth trading fee has accumulated in TR.

```
uint vaultValueX8 = getTVL();   
uint adjBaseFee = getAdjustedBaseFee(token == address(token0));
// Wrap if necessary and deposit here
if (msg.value > 0){
  require(token == address(WETH), "GEV: Invalid Weth");
  // wraps ETH by sending to the wrapper that sends back WETH
  WETH.deposit{value: msg.value}();
  amount = msg.value;
}
else { 
  ERC20(token).safeTransferFrom(msg.sender, address(this), amount);
}

// Send deposit fee to treasury
uint fee = amount * adjBaseFee / 1e4;
ERC20(token).safeTransfer(treasury, fee);
uint valueX8 = oracle.getAssetPrice(token) * (amount - fee) / 10**ERC20(token).decimals();


require(tvlCap > valueX8 + vaultValueX8, "GEV: Max Cap Reached");


uint tSupply = totalSupply();
// initial liquidity at 1e18 token ~ $1
if (tSupply == 0 || vaultValueX8 == 0)
  liquidity = valueX8 * 1e10;
else {
  liquidity = tSupply * valueX8 / vaultValueX8;
}

rebalance();
```
As above, when depositing, the 0.1 eth fee is not reflected in getTVL. Only after removeFromAllTicks(in rebalance) will the fee be collected and sent to GE vault. Therefore, attacker can take a flashloan, deposit and then withdraw to steal almost all of the 0.1 eth trading fee. (the process is similar to what H-04 has described)

When withdrawing, similarly, user will incur loss since latest trading fee is not accounted.

### Proof of Concept
https://github.com/GoodEntry-io/ge/blob/c7c7de57902e11e66c8186d93c5bb511b53a45b8/contracts/GeVault.sol#L265-L293

## [M-02]  getActiveTickIndex implementation error

## Vulnerability details
### Impact
The implementation of getActiveTickIndex is wrong, and the searched ticks do not meet expectations, causing funds to be incorrectly allocated to edge ticks, and there is basically no staking income.


### Proof of Concept
https://github.com/GoodEntry-io/ge/blob/c7c7de57902e11e66c8186d93c5bb511b53a45b8/contracts/GeVault.sol#L470

```
    // if base token is token0, ticks above only contain base token = token0 and ticks below only hold quote token = token1
    if (newTickIndex > 1) 
      depositAndStash(
        ticks[newTickIndex-2], 
        baseTokenIsToken0 ? 0 : availToken0 / liquidityPerTick,
        baseTokenIsToken0 ? availToken1 / liquidityPerTick : 0
      );


  /// @notice Return first valid tick
  function getActiveTickIndex() public view returns (uint activeTickIndex) {
    // loop on all ticks, if underlying is only base token then we are above, and tickIndex is 2 below
    for (uint tickIndex = 0; tickIndex < ticks.length; tickIndex++){
      (uint amt0, uint amt1) = ticks[tickIndex].getTokenAmountsExcludingFees(1e18);
      // found a tick that's above price (ie its only underlying is the base token)
      if( (baseTokenIsToken0 && amt0 == 0) || (!baseTokenIsToken0 && amt0 == 0) ) return tickIndex;
    }
    // all ticks are below price
    return ticks.length;
  }

```

According to code comments:

- If baseTokenIsToken0 is true, ticks above current price only contain base token, that is token0, so amt1 is 0.
- And if baseTokenIsToken0 is false, ticks below current price only contain quote token, that is token1, so amt0 is 0.
getActiveTickIndex checks amt0 twice in the code is wrong, which causes baseTokenIsToken0 && amt0 == 0 to be true when the tick is below the current price.
That is, the searched tick is the first tick lower than the current price, not the first tick greater than the current price, which is the first tick in the list.
This results in funds being staked to marginal ticks and unable to obtain staking income.
## Recommended Mitigation Steps
```
      // found a tick that's above price (ie its only underlying is the base token)
      if( (baseTokenIsToken0 && amt1 == 0) || (!baseTokenIsToken0 && amt0 == 0) ) return tickIndex;
```


## [H-02]  Attacker can extract value from pool by sandwiching herself at swapAll during close

## Vulnerability details
Attacker can drain the lending pool by leveraging two facts:

1. 2. swapAll allows 1% slippage
There is no Health Factor check after close.
Alice and Bob are good friends, the steps are (in one single tx):

1. Alice deposits 10000 USDT and borrows 7000$ worth of TR.
2. Bob buys ETH at AMM to push up the price to oracle + 1%.
3. Alice close but only repays 1 wei debt. The real intention is to swap from USDT collateral to ETH collateral.
4. Bob sells ETH at AMM to pull down the price to oracle - 1%.
5. Alice close but only repays 1 wei debt to swap to USDT collateral.
6. Repeat
7. Alice has 0 collateral and Bob gains 10000 USDT by sandwiching.
By continues sandwiching Alice, Bob can extract value from the pool. A simple mitigation is to add a HF check after each swap.
### Proof of Concept
https://github.com/GoodEntry-io/ge/blob/c7c7de57902e11e66c8186d93c5bb511b53a45b8/contracts/PositionManager/OptionsPositionManager.sol#L454



## [M-01]  Use of tx.origin breaks interoperability with AA wallets.

## Vulnerability details
In OptionPositionMananger, several functions like close and sellOptions, need to call PMWithdraw, which calls PMTransfer. Then it is checked that tx.origin != user. However, smart contract wallet cannot be tx.origin, which means AA wallets will not be able to interact with the protocol.
### Proof of Concept
https://github.com/GoodEntry-io/GoodEntryMarkets/blob/2e3d23016fadb45e188716d772cec7c2096fae01/contracts/protocol/lendingpool/LendingPool.sol.0x20#L492
```
  function PMTransfer(
    address aAsset,
    address user,
    uint256 amount
  ) external whenNotPaused {
    require(pm[msg.sender], "Not PM");
    if (tx.origin != user) {
      (,,,, uint256 healthFactor) = GenericLogic.calculateUserAccountData(
        user,
        _reserves,
        _usersConfig[user],
        _reservesList,
        _reservesCount,
        _addressesProvider.getPriceOracle()
        );
      require(healthFactor <= softLiquidationThreshold, "Not initiated by user");
    }
    IAToken(aAsset).transferOnLiquidation(user, msg.sender, amount);
  }
```
I suggest we move the check to OptionPositionMananger and check msg.sender == user instead.

## [M-02] 

## Vulnerability details
To find a tick that's above price (ie its only underlying is the base token), getActiveTickIndex should not
```
  if( (baseTokenIsToken0 && amt0 == 0) || (!baseTokenIsToken0 && amt0 == 0) ) return tickIndex;
```
it should
```
  if( (baseTokenIsToken0 && amt1 == 0) || (!baseTokenIsToken0 && amt0 == 0) ) return tickIndex;
```

### Proof of Concept
https://github.com/GoodEntry-io/ge/blob/3b80be0e86e1c01cd85906e9892e06540e12a842/contracts/GeVault.sol#L452
