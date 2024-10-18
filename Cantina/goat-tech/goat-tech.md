| Severity | Title |
| -------- | -------- | 
|H-01 |The real `HALVING_INTERVAL` could be longer than the setup value|
|M-01 |There is no slippage protection in LLido library|
|M-02 |If `_votingToken` is not in Private Mode, it could be transferred to vote multiple times|
|M-03 |The setup of `MAX_SUPPLY` is incorrect|


## [H-01]  The real `HALVING_INTERVAL` could be longer than the setup value

## Vulnerability details
### Description
In the DCT contract, the halving mechanism is designed with a HALVING_INTERVAL constant set to 7 days. This mechanism is pivotal for reducing the token issuance rate over time, ensuring a diminishing supply increase in alignment with the contract's economic model.
```solidity
    uint constant public HALVING_INTERVAL = 7 days;
```
The halving operation is triggered during the publicMint function calls. However, if publicMint is not invoked for an extended period, the actual HALVING_INTERVAL  extends beyond the intended 7 days. This delayed halving can lead to discrepancies between the programmed and actual token distribution schedules.

```solidity
if (block.timestamp - _lastHalved >= HALVING_INTERVAL) {
            _tps = _tps / 2;
            _lastHalved = block.timestamp;
        }
```
The implications of this delay include:

- The effective HALVING_INTERVAL might extend well beyond 7 days, diverging from the intended economic model.
- A larger quantity of tokens may be issued than planned in the interval prior to a halving, due to the token per second rate (_tps) not being reduced at the expected time.
- Prolonged inactivity could lead to a situation where totalSupply() + mintingAmount > MAX_SUPPLY, preventing any further token minting.

## Recommended Mitigation Steps
It is recommended to implement an automated process or utilize a keeper bot to invoke `publicMint` function that executes the halving operation, if necessary, every 7 days.



## [M-01]  There is no slippage protection in LLido library

## Vulnerability details
### Description
The `LLido` library lacks slippage protection, which can result in users losing funds.

Several areas need attention:

1. In uniswap-related functions such as mintNewPosition, increaseLiquidityCurrentRange, decreaseLiquidityCurrentRange, swapExactInputSingleHop, parameters like amountOutMinimum, amount0Min, amount1Min, sqrtPriceLimitX96 are all set to 0, indicating no slippage protection. This makes the functions vulnerable to front-running attacks.
```solidity
        INonfungiblePositionManager.DecreaseLiquidityParams
            memory params = INonfungiblePositionManager.DecreaseLiquidityParams({
                tokenId: tokenId_,
                liquidity: decLiqA_,
                amount0Min: 0,
                amount1Min: 0,
                deadline: block.timestamp
            });
```
2. The `POOL_FEE` is a constant and cannot be changed. This could result in a sub-optimal situation where minting occurs in a pool with unfavorable pricing.
```solidity
    uint24 private constant POOL_FEE = 100;
```
3. The deadline in the parameters is either commented out in swapExactInputSingleHop or directly set as block.timestamp, meaning that the transaction could be held by the miner, leading to a worse price.
```solidity
    function swapExactInputSingleHop(
        address tokenIn,
        address tokenOut,
        uint amountIn
    )
        internal
        returns (uint amountOut) {
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter
            .ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                fee: POOL_FEE,
                recipient: address(this),
                // deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: 0, 
                sqrtPriceLimitX96: 0 
            });

        amountOut = router.exactInputSingle(params);
    }
```

## Recommended Mitigation Steps
1. Implement slippage protection by specifying the maximum acceptable loss during the transaction.
2. `POOL_FEE` could be obtained from the input.
3. The `deadline` could be taken from the input.

## [M-02] If `_votingToken` is not in Private Mode, it could be transferred to vote multiple times 

## Vulnerability details
### Description

In the Voting contract, the _votingToken used is actually a DToken. Typically, a DToken operates in two modes: Private Mode and Non-Private Mode, which can be set using the PERC20::setInPrivateMode function.
```solidity
    function setInPrivateMode(
        bool inPrivateMode_
    )
        external
        onlyOwner
    {
        _setInPrivateMode(inPrivateMode_);
    }
```
When a DToken is in Private Mode, it could not be transferred by its holder.
```solidity
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        require(!_inPrivateMode, "_inPrivateMode");
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(!_inPrivateMode, "_inPrivateMode");
        return super.transferFrom(from, to , amount);
    }
```

However, if the _votingToken is set to Non-Private Mode by the owner via setInPrivateMode, the Voting contract will encounter issues.

In the `Voting::_addVoter function, the balance of the voter is calculated as the voting power. But after voting, there are no restrictions on the voter, allowing them to transfer the token as they wish if the _votingToken is not in Private Mode.
```solidity
        uint power = _votingToken.balanceOf(voter_);
```
This means that a user A could transfer their token to other addresses (such as address B, C, etc.). Consequently, their limited amount of tokens could be reused multiple times to gain infinite voting power.

Note: While the `_votingToken` is initially non-transferable and only the owner can call `setInPrivateMode` to change its state, if the owner is compromised or mistakenly performs the operation, serious consequences could arise.

## Recommended Mitigation Steps
For `VotingToken`, it should override the `setInPrivateMode` function and simply revert in the function, so that the mode of the token could never be changed.

## [M-03] The setup of `MAX_SUPPLY` is incorrect 

## Vulnerability details
### Description

For `DCT` token, the `MAX_SUPPLY` is `3111666666` ether and the initial `_tps` is `7` ether.

```solidity
    uint private _tps = 7 ether;
    uint constant public HALVING_INTERVAL = 7 days;
```

According to function pendingA, the mint amount is calculated via _tps * pastTime.
```solidity
    function pendingA()
        public
        view
        returns(uint)
    {
        if (isMintingFinished || _lastMintAt == 0) {
            return 0;
        }
        uint pastTime = block.timestamp - _lastMintAt;
        return _tps * pastTime;
    }
```

So for the first 7 days, the minted amount will be `7 * 60 * 60 * 60 * 24 * 7 = 254016000 ether`. For the next `7` days, it will be `127008000` due to halving mechanism.

As a result, the limit for all minted amount would be `508032000` ether, which is only `16%` of `MAX_SUPPLY`. In the same word, the `MAX_SUPPLY` would never be reached if the project is working normally.

Thus the check `totalSupply() + mintingA > MAX_SUPPLY` is non-sense.

## Recommended Mitigation Steps
It is recommended to recheck the value of `MAX_SUPPLY` and set it to a reasonable value.


