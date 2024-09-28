| Severity | Title |
| -------- | -------- | 
|M-01 |Bypassing the 2-Day Timelock Due to Unreset `gameLiquidityPoolConnectionRequests`|


## [M-01] Bypassing the 2-Day Timelock Due to Unreset `gameLiquidityPoolConnectionRequests`

## Vulnerability details
### Description
According to the documentation, "There is a 2-day timelock for the contract owner to connect a game to a liquidity pool with shares. In the case where a malicious contract owner adds a malicious game to steal funds from a liquidity pool, liquidity providers have 2 days to withdraw before the attack can happen." However, this invariant could be broken since the 2-day timelock can be skipped, causing confusion and trust concerns among the community and users.

In the `confirmGameLiquidityPoolConnectionRequest`, `gameLiquidityPoolConnectionRequests` is only queried but never cleared after the connection is set. Thus, if the pool is later disconnected, it could be reconnected instantly by calling `confirmGameLiquidityPoolConnectionRequest` at any time, as `gameLiquidityPoolConnectionRequests[requestId]` remains unchanged.

```solidity
        uint256 requestedAt = gameLiquidityPoolConnectionRequests[requestId];

        if (requestedAt == 0) {
            revert GameConfigurationManager__NoGameLiquidityPoolConnectionRequest();
        }

        if (block.timestamp - requestedAt < GAME_LIQUIDITY_POOL_CONNECTION_TIMELOCK) {
            revert GameConfigurationManager__GameLiquidityPoolConnectionRequestConfirmationIsTooEarly();
        }
```

### Proof of Concept

In `GameConfigurationManager.t.sol`:

```solidity
    function test_no_confirm_needed() public {
        _provideLiquidity(user1, 1 ether);

        vm.startPrank(owner);
        gameConfigurationManager.initiateGameLiquidityPoolConnectionRequest(
            address(flipper),
            address(mockWETH),
            address(ethLiquidityPool)
        );
        vm.warp(vm.getBlockTimestamp() + 2 days);
        gameConfigurationManager.confirmGameLiquidityPoolConnectionRequest(
            address(flipper),
            address(mockWETH),
            address(ethLiquidityPool)
        );
        // disconnect
        gameConfigurationManager.disconnectGameFromLiquidityPool(address(flipper), address(mockWETH));
        // simply reconnect without 2-day waiting
        gameConfigurationManager.confirmGameLiquidityPoolConnectionRequest(
            address(flipper),
            address(mockWETH),
            address(ethLiquidityPool)
        );
        vm.stopPrank();
    }
```

## Recommended Mitigation Steps
To mitigate this issue, clear `gameLiquidityPoolConnectionRequests[requestId]` after connection.


