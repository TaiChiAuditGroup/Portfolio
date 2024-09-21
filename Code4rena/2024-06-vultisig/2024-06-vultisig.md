
| Severity | Title |
| -------- | -------- | 
|M-01 |Lack of slippage protection during claiming|
|M-02 |_maxAddressCap can be bypassed by transferring NFT out|
|L-01| 24-hour whitelisted-only period could be violated|
|L-02 |No minimum boundary for DEFAULT_DEADLINE_OFFSET|
|L-03 |Incompatible with Fee-on-transfer token|
|L-04 |whitelistCount may not return the actual whitelisted number|
|L-05 |The vesting allows for instant unlock|
|L-06|All Capital Letters will Cause Confusion|
|L-07|whenNotInitialized Naming is inaccurate|
|L-08 |If one pool fails to raise enough funds, the whole project will fail|
|L-09 |Launch Time should include `launchTime`|
|L-10 |initializedPools can only be added|
|L-11 |getOldestObservationSecondsAgo could be small after initialization|




## [M-01]  Lack of slippage protection during claiming

## Vulnerability details
### Impact
When users claim liquidity, a portion of the share is burned via pool.burn, and the funds are later sent to the user. However, there is no slippage protection during this liquidity burning process, which can potentially lead to users losing funds due to price fluctuations.
### Proof of Concept
https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOPool.sol#L205
https://github.com/Uniswap/v3-periphery/blob/697c2474757ea89fec12a4e6db16a574fe259610/contracts/NonfungiblePositionManager.sol#L257


In Uniswap V3, slippage protection is crucial during the decreaseLiquidity operation. In the NonfungiblePositionManager::decreaseLiquidity function, the returned amount must be greater than or equal to amount0Min and amount1Min to ensure slippage protection:
```
        PoolAddress.PoolKey memory poolKey = _poolIdToPoolKey[position.poolId];
        IUniswapV3Pool pool = IUniswapV3Pool(PoolAddress.computeAddress(factory, poolKey));
        (amount0, amount1) = pool.burn(position.tickLower, position.tickUpper, params.liquidity);
@=>     require(amount0 >= params.amount0Min && amount1 >= params.amount1Min, 'Price slippage check');
```
However, in the ILOPool::claim function, there is no such slippage protection check. This absence of a slippage check during the liquidity burning process can lead to users suffering from potential loss of funds due to unfavorable price changes:
```
            (amount0, amount1) = pool.burn(TICK_LOWER, TICK_UPPER, liquidity2Claim);
```
Without a slippage protection mechanism, users may receive significantly less than expected when claiming their liquidity, resulting in financial losses.
## Recommended Mitigation Steps
To mitigate this issue, it is recommended to add relevant slippage check.

## [M-02]  _maxAddressCap can be bypassed by transferring NFT out

## Vulnerability details
### Impact
In the ILOPool::saleInfo, the maxCapPerUser is used to limit the maximum amount of tokens purchased by a whitelisted user.

However, the purchased amount is only stored in _positions mapping which is associated with tokenId instead of the buyer address.

A whitelisted user could bypass the check by transferring NFT to another address and continue buying with a newly minted NFT. This makes the maxCapPerUser useless, as it only checks the purchase based on tokenId.


### Proof of Concept
https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOPool.sol#L25
https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOPool.sol#L143-L152

In the function ILOManager::initILOPool, the maxCapPerUser is set to restrict the amount of purchase for a whitelisted user.
```
function initILOPool(...) {
    ...
        IILOPool.InitPoolParams memory initParams = IILOPool.InitPoolParams({
            uniV3Pool: params.uniV3Pool,
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            sqrtRatioLowerX96: sqrtRatioLowerX96,
            sqrtRatioUpperX96: sqrtRatioUpperX96,
            hardCap: params.hardCap,
            softCap: params.softCap,
@=>         maxCapPerUser: params.maxCapPerUser,
            start: params.start,
            end: params.end,
            vestingConfigs: params.vestingConfigs
        });
    ...
}
```
This restriction is checked in the ILOPool::buy function so that _position.raiseAmount should never exceed saleInfo.maxCapPerUser.
```
function buy(...) {
    ...
        if (balanceOf(recipient) == 0) {
            _mint(recipient, (tokenId = _nextId++));
            _positionVests[tokenId].schedule = _vestingConfigs[0].schedule;
        } else {
            tokenId = tokenOfOwnerByIndex(recipient, 0);
        }

        Position storage _position = _positions[tokenId];
@=>     require(raiseAmount <= saleInfo.maxCapPerUser - _position.raiseAmount, "UC");

    ...
}
```
However, the purchased amount is only stored in _positions mapping which is associated with tokenId instead of the buyer address.

Thus, a whitelisted user could bypass the check by transferring NFT to another address and continue buying with a newly minted NFT. This makes the maxCapPerUser useless, as it only checks the purchase based on tokenId.

A Test PoC in Foundry is shown below. It could be observed that the INVESTOR could buy as he wants as long as he transfers out NFT to any other address.
```
    function testBypassBuyTooMuch() external {
        _prepareBuy();
        (uint256 tokenId,) = _buyFor(INVESTOR, SALE_START+1, 60000 ether);
        vm.prank(INVESTOR);
        IILOPool(iloPool).transferFrom(INVESTOR, address(2), tokenId);
        _buyFor(INVESTOR, SALE_START+2, 10000 ether);
    }
```
The logs are shown below:
```
Ran 1 test for test/ILOPool.t.sol:ILOPoolTest
[PASS] testBypassBuyTooMuch() (gas: 1113145)
Traces:
  [1113145] ILOPoolTest::testBypassBuyTooMuch()
    ├─ [0] VM::prank(0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc)
    │   └─ ← [Return] 
    ├─ [80189] 0xa2dCd3d28c5caE237De80B47289a0082278CCB85::batchWhitelist([0x976EA74026E726554dB657fA54763abd0C3a0aa9])
    │   ├─ [79408] ILOPool::batchWhitelist([0x976EA74026E726554dB657fA54763abd0C3a0aa9]) [delegatecall]
    │   │   ├─ [8955] ILOManager::project(0x8005a9E9643F2e5E165c67a5162c5169C278B7b4) [staticcall]
    │   │   │   └─ ← [Return] Project({ admin: 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc, saleToken: 0xd8D1e90d913Fff1F2a181E42a8Ef62EABFd29A2A, raiseToken: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, fee: 500, initialPoolPriceX96: 158456325028528675187087900672 [1.584e29], launchTime: 1717606800 [1.717e9], refundDeadline: 1718211600 [1.718e9], investorShares: 0, uniV3PoolAddress: 0x8005a9E9643F2e5E165c67a5162c5169C278B7b4, _cachedPoolKey: PoolKey({ token0: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, token1: 0xd8D1e90d913Fff1F2a181E42a8Ef62EABFd29A2A, fee: 500 }), platformFee: 10, performanceFee: 1000 })
    │   │   ├─ emit SetWhitelist(user: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, isWhitelist: true)
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::prank(0x976EA74026E726554dB657fA54763abd0C3a0aa9)
    │   └─ ← [Return] 
    ├─ [26062] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::approve(0xa2dCd3d28c5caE237De80B47289a0082278CCB85, 1000000000000000000000000000 [1e27])
    │   ├─ [23273] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::approve(0xa2dCd3d28c5caE237De80B47289a0082278CCB85, 1000000000000000000000000000 [1e27]) [delegatecall]
    │   │   ├─ emit Approval(owner: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, spender: 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, value: 1000000000000000000000000000 [1e27])
    │   │   └─ ← [Return] true
    │   └─ ← [Return] true
    ├─ [0] VM::record()
    │   └─ ← [Return] 
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 0
    │   └─ ← [Return] 0
    ├─ [0] VM::accesses(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)
    │   └─ ← [Return] [0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b, 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076], []
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b) [staticcall]
    │   └─ ← [Return] 0x000000000000000000000000807a96288a1a408dbc13de2b1d087d10356395d2
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b) [staticcall]
    │   └─ ← [Return] 0x000000000000000000000000807a96288a1a408dbc13de2b1d087d10356395d2
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 0
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return] 
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 0
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b, 0x000000000000000000000000807a96288a1a408dbc13de2b1d087d10356395d2)
    │   └─ ← [Return] 
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3) [staticcall]
    │   └─ ← [Return] 0x00000000000000000000000043506849d7c04f9138d1a2050bbf3a0c054402dd
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3) [staticcall]
    │   └─ ← [Return] 0x00000000000000000000000043506849d7c04f9138d1a2050bbf3a0c054402dd
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 0
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return] 
    ├─ [2783] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [0] 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3, 0x00000000000000000000000043506849d7c04f9138d1a2050bbf3a0c054402dd)
    │   └─ ← [Return] 
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ emit WARNING_UninitedSlot(who: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, slot: 104000122207162255982895677957337467219776143111287485776280476739120336822390 [1.04e77])
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 0
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return] 
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 57896044618658097711785492504343953926634992332820282019728792003956564819967 [5.789e76]
    │   └─ ← [Return] 57896044618658097711785492504343953926634992332820282019728792003956564819967 [5.789e76]
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076, 0x0000000000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return] 
    ├─ emit SlotFound(who: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, fsig: 0x70a0823100000000000000000000000000000000000000000000000000000000, keysHash: 0x18bbf5fcf8fe870ecff419c4677497c08b2e6a5431bb94541d06c9da3f308e55, slot: 104000122207162255982895677957337467219776143111287485776280476739120336822390 [1.04e77])
    ├─ [0] VM::load(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [0] VM::store(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 0xe5edfbb1a168440ed929bb6e6e846a69c257cb12652e468fc03b05a005956076, 0x0000000000000000000000000000000000000000033b2e3c9fd0803ce8000000)
    │   └─ ← [Return] 
    ├─ [4039] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [staticcall]
    │   ├─ [1253] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::balanceOf(0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   └─ ← [Return] 1000000000000000000000000000 [1e27]
    │   └─ ← [Return] 1000000000000000000000000000 [1e27]
    ├─ [0] VM::warp(1717434001 [1.717e9])
    │   └─ ← [Return] 
    ├─ [0] VM::prank(0x976EA74026E726554dB657fA54763abd0C3a0aa9)
    │   └─ ← [Return] 
    ├─ [376773] 0xa2dCd3d28c5caE237De80B47289a0082278CCB85::buy(60000000000000000000000 [6e22], 0x976EA74026E726554dB657fA54763abd0C3a0aa9)
    │   ├─ [375992] ILOPool::buy(60000000000000000000000 [6e22], 0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, tokenId: 1)
    │   │   ├─ [37549] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::transferFrom(0x976EA74026E726554dB657fA54763abd0C3a0aa9, 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, 60000000000000000000000 [6e22])
    │   │   │   ├─ [34754] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::transferFrom(0x976EA74026E726554dB657fA54763abd0C3a0aa9, 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, 60000000000000000000000 [6e22]) [delegatecall]
    │   │   │   │   ├─ emit Transfer(from: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, to: 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, value: 60000000000000000000000 [6e22])
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Return] true
    │   │   ├─ emit Buy(investor: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, tokenId: 1, raiseAmount: 60000000000000000000000 [6e22], liquidity: 24000000000000000002602 [2.4e22])
    │   │   └─ ← [Return] 1, 24000000000000000002602 [2.4e22]
    │   └─ ← [Return] 1, 24000000000000000002602 [2.4e22]
    ├─ [0] VM::prank(0x976EA74026E726554dB657fA54763abd0C3a0aa9)
    │   └─ ← [Return] 
    ├─ [91207] 0xa2dCd3d28c5caE237De80B47289a0082278CCB85::transferFrom(0x976EA74026E726554dB657fA54763abd0C3a0aa9, 0x0000000000000000000000000000000000000002, 1)
    │   ├─ [90426] ILOPool::transferFrom(0x976EA74026E726554dB657fA54763abd0C3a0aa9, 0x0000000000000000000000000000000000000002, 1) [delegatecall]
    │   │   ├─ emit Approval(owner: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, approved: 0x0000000000000000000000000000000000000000, tokenId: 1)
    │   │   ├─ emit Transfer(from: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, to: 0x0000000000000000000000000000000000000002, tokenId: 1)
    │   │   └─ ← [Stop] 
    │   └─ ← [Return] 
    ├─ [0] VM::warp(1717434002 [1.717e9])
    │   └─ ← [Return] 
    ├─ [0] VM::prank(0x976EA74026E726554dB657fA54763abd0C3a0aa9)
    │   └─ ← [Return] 
    ├─ [314973] 0xa2dCd3d28c5caE237De80B47289a0082278CCB85::buy(10000000000000000000000 [1e22], 0x976EA74026E726554dB657fA54763abd0C3a0aa9)
    │   ├─ [314192] ILOPool::buy(10000000000000000000000 [1e22], 0x976EA74026E726554dB657fA54763abd0C3a0aa9) [delegatecall]
    │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, tokenId: 2)
    │   │   ├─ [18349] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::transferFrom(0x976EA74026E726554dB657fA54763abd0C3a0aa9, 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, 10000000000000000000000 [1e22])
    │   │   │   ├─ [15554] 0x43506849D7C04F9138D1A2050bbF3A0c054402dd::transferFrom(0x976EA74026E726554dB657fA54763abd0C3a0aa9, 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, 10000000000000000000000 [1e22]) [delegatecall]
    │   │   │   │   ├─ emit Transfer(from: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, to: 0xa2dCd3d28c5caE237De80B47289a0082278CCB85, value: 10000000000000000000000 [1e22])
    │   │   │   │   └─ ← [Return] true
    │   │   │   └─ ← [Return] true
    │   │   ├─ emit Buy(investor: 0x976EA74026E726554dB657fA54763abd0C3a0aa9, tokenId: 2, raiseAmount: 10000000000000000000000 [1e22], liquidity: 4000000000000000000433 [4e21])
    │   │   └─ ← [Return] 2, 4000000000000000000433 [4e21]
    │   └─ ← [Return] 2, 4000000000000000000433 [4e21]
    └─ ← [Stop]
```
## Recommended Mitigation Steps
To mitigate:

NFT transfer before the end of the sale should be disabled.




## [L-01] 24-hour whitelisted-only period could be violated**

- The contract tries to enforce `a 24-hour whitelisted (WL) trade-only period will be the next phase (first come, first served among the WL addresses)` according to the [doc](https://docs.vultisig.com/vultisig-token/launch#launch-liquidity). However, the contract does not trace the other pools that could be created by whitelisted buyers. In this way, the check `from == _pool` could be bypassed, and others could freely trade in other pools.

```solidity
    function checkWhitelist(address from, address to, uint256 amount) external onlyVultisig {
        if (from == _pool && to != owner()) {
        ...
        } 
}
```

### **Links to affected code**

- [Whitelist.sol#L205](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/hardhat-vultisig/contracts/Whitelist.sol#L205)


### **Recommended Mitigation Steps**

- To mitigate this issue, it is recommended to add an array to keep track of all pools, or even temporarily disable any token transfer except `from == _pool`.


## [L-02] No minimum boundary for DEFAULT_DEADLINE_OFFSET**

- The `refundDeadline` is always set to be `params.launchTime + DEFAULT_DEADLINE_OFFSET`. However, there is no lower boundary for `DEFAULT_DEADLINE_OFFSET`. If it is set to a small value, the project may not have enough time to launch the project before a malicious user calls `claimRefund` to prevent the project from launching. Similarly, `setRefundDeadlineForProject` should also be called with care as this would trigger the same issues.

```solidity
    function setDefaultDeadlineOffset(uint64 defaultDeadlineOffset) external override onlyOwner() {
        emit DefaultDeadlineOffsetChanged(owner(), DEFAULT_DEADLINE_OFFSET, defaultDeadlineOffset);
        DEFAULT_DEADLINE_OFFSET = defaultDeadlineOffset;
    }
```

### **Links to affected code**

- [ILOManager.sol#L175-L178](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L175-L178)
- [ILOManager.sol#L58](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L58)

### **Recommended Mitigation Steps**

- To mitigate this issue, it is recommended to set a lower boundary in the function `setDefaultDeadlineOffset`.


## [L-03] Incompatible with Fee-on-transfer token**

- The design of `ILOPool` is incompatible with Fee-on-transfer or rebasing tokens. Since the accounting for `raiseAmount`, `amount0`, `amount1`, `amountCollected0`, and `amountCollected1` doesn't consider the case that the amount will be changed due to FOT or REBASE issues.


### **Links to affected code**

- [ILOPool.sol#L242C18-L260](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOPool.sol#L242C18-L260)


### **Recommended Mitigation Steps**

- If Fee-on-transfer or rebasing tokens are to be used, try use `balanceOf(address(this))` to calculate the received amount.


## [L-04] whitelistCount may not return the actual whitelisted number**

- According to the function `checkWhitelist`, if `_allowedWhitelistIndex == 0`, no one is allowed. If `_whitelistIndex[to] > _allowedWhitelistIndex`, the `to` address is not allowed.

```solidity

            if (_allowedWhitelistIndex == 0 || _whitelistIndex[to] > _allowedWhitelistIndex) {
                revert NotWhitelisted();
            }
```

- However, according to this, the function `whitelistCount` does not accurately reflect how many addresses are whitelisted. It should be `0` if `_allowedWhitelistIndex == 0` and be `_allowedWhitelistIndex` otherwise.

```solidity
    /// @notice Returns current whitelisted address count
    function whitelistCount() external view returns (uint256) {
        return _whitelistCount;
    }
```

### **Links to affected code**

- [Whitelist.sol#L113C1-L116C6](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/hardhat-vultisig/contracts/Whitelist.sol#L113C1-L116C6)
- [Whitelist.sol#L216-L218](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/hardhat-vultisig/contracts/Whitelist.sol#L216-L218)


### **Recommended Mitigation Steps**

- `whitelistCount` should return `0` if `_allowedWhitelistIndex == 0` and return `_allowedWhitelistIndex` otherwise.


## [L-05] The vesting allows for instant unlock**

- In the `_validateVestSchedule` function, the function doesn't check if `schedule[i].start` < `schedule[i].end`. If `schedule[i].start == schedule[i].end`, the amount is unlocked instantly.

```solidity
    function _validateVestSchedule(uint64 launchTime, LinearVest[] memory schedule) internal pure {
        require(schedule[0].start >= launchTime, "VT");
        uint16 BPS = 10000;
        uint16 totalShares;
        uint64 lastEnd;
        uint256 scheduleLength = schedule.length;
        for (uint256 i = 0; i < scheduleLength; i++) {
            // vesting schedule must not overlap
            require(schedule[i].start >= lastEnd, "VT");
            lastEnd = schedule[i].end;
            // we need to subtract fist in order to avoid int overflow
            require(BPS - totalShares >= schedule[i].shares, "VS");
            totalShares += schedule[i].shares;
        }
        // total shares should be exactly equal BPS
        require(totalShares == BPS, "VS");
    }
}
```

### **Links to affected code**

- [ILOVest.sol#L35-L52](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/base/ILOVest.sol#L35-L52)


### **Recommended Mitigation Steps**

- Add relevant check `schedule[i].start` < `schedule[i].end` or set a minimum duration of a schedule.

## [L-06] All Capital Letters will Cause Confusion**

- In Solidity, variables with all capital letters in naming are considered to be constant or immutable. However, in the current contract, variables with all capital letters can be changed. This may cause confusion in variable usage and violates the best practices.

```solidity
    uint64 private DEFAULT_DEADLINE_OFFSET = 7 * 24 * 60 * 60; // 7 days
    uint16 public override PLATFORM_FEE;
    uint16 public override PERFORMANCE_FEE;
    address public override FEE_TAKER;
    address public override ILO_POOL_IMPLEMENTATION;
```

### **Links to affected code**

- [ILOManager.sol#L19-L23](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L19-L23)


### **Recommended Mitigation Steps**

- Follow naming conventions instead of using all capital letters directly.

## [L-07] whenNotInitialized Naming is inaccurate**

- In the `Initializable` contract, the `whenNotInitialized` modifier will work why the contract is not initialized and it will set `_initialized` to `true`. According to its function(changing the state) and common practice, it is better to rename it to `initializer` instead of `whenNotInitialized`.

```solidity
    modifier whenNotInitialized() {
        require(!_initialized);
        _;
        _initialized = true;
    }
```

### **Links to affected code**

- [Initializable.sol#L10-L14](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/base/Initializable.sol#L10-L14)


### **Recommended Mitigation Steps**

- Rename the modifier to `initializer` instead of `whenNotInitialized`. 

## [L-08] If one pool fails to raise enough funds, the whole project will fail**

- In the `ILOManager::launch` function, all `IILOPool` will be launched. If we have only 1 pool that fails to raise enough funds, the whole project would be unable to launch due to the check `require(totalRaised >= saleInfo.softCap, "SC")`. This reduces the funds efficiency as the pool could not be removed from `initializedPools`.

```solidity
        for (uint256 i = 0; i < initializedPools.length; i++) {
            IILOPool(initializedPools[i]).launch();
        }
```

### **Links to affected code**

- [ILOManager.sol#L193C1-L195C10](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L193C1-L195C10)
- [ILOPool.sol#L274](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOPool.sol#L274)


### **Recommended Mitigation Steps**

- Add a way to remove a `IILOPool` from `initializedPools` which hasn't raised enough funds.


## [L-09] Launch Time should include `launchTime`**

- In `ILOManager::launch` function, it is required that `require(block.timestamp > _cachedProject[uniV3PoolAddress].launchTime, "LT")`. However, it should include the `_cachedProject[uniV3PoolAddress].launchTime` so that when `_cachedProject[uniV3PoolAddress].launchTime` reaches, one is also able to launch the project at that time. This is also consistent with "LT" error message.

```solidity
        require(block.timestamp > _cachedProject[uniV3PoolAddress].launchTime, "LT");
```

### **Links to affected code**

- [ILOManager.sol#L188](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L188)


### **Recommended Mitigation Steps**

- Change the check to `require(block.timestamp >= _cachedProject[uniV3PoolAddress].launchTime, "LT");`


## [L-10] initializedPools can only be added**

- In the `ILOManager::launch` function, `initializedPools` will be iterated to launch them all. However, this array(`_initializedILOPools[uniV3PoolAddress]`) can only be added(`push`) but never be reduced(`pop`). When there are so many pools in `initializedPools`, this will cause an Out-of-gas error.

```solidity
        for (uint256 i = 0; i < initializedPools.length; i++) {
            IILOPool(initializedPools[i]).launch();
        }
```

### **Links to affected code**

- [ILOManager.sol#L193-L195](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L193-L195)
- [ILOManager.sol#L106](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/src/ILOManager.sol#L106C9-L106C29)

### **Recommended Mitigation Steps**

- Find a way to remove unused pools from `_initializedILOPools[uniV3PoolAddress]`.


## [L-11] getOldestObservationSecondsAgo could be small after initialization**

- `UniswapV3Oracle::peek` queries `TWAP` for Oracle. But the `getOldestObservationSecondsAgo` could return a small value after initialization as `observationCardinality` is still small and has not been extended yet. In this situation, the `TWAP` response could be manipulated during this period.

```solidity
        (uint32 observationTimestamp, , , bool initialized) = IUniswapV3Pool(pool).observations(
            (observationIndex + 1) % observationCardinality
        );
```

```solidity
    /// @notice Returns TWAP price for 1 VULT for the last 30 mins
    function peek(uint256 baseAmount) external view returns (uint256) {
        uint32 longestPeriod = OracleLibrary.getOldestObservationSecondsAgo(pool);
        uint32 period = PERIOD < longestPeriod ? PERIOD : longestPeriod;
        int24 tick = OracleLibrary.consult(pool, period);
        uint256 quotedWETHAmount = OracleLibrary.getQuoteAtTick(tick, BASE_AMOUNT, baseToken, WETH);
        // Apply 5% slippage
        return (quotedWETHAmount * baseAmount * 95) / 1e20; // 100 / 1e18
    }
```

### **Links to affected code**

- [UniswapV3Oracle.sol#L38](https://github.com/code-423n4/2024-06-vultisig/blob/cb72b1e9053c02a58d874ff376359a83dc3f0742/hardhat-vultisig/contracts/oracles/uniswap/UniswapV3Oracle.sol#L38C1-L47)


### **Recommended Mitigation Steps**

- Ensure that there is enough `observationCardinality` before the trading starts.
