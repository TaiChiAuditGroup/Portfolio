| Severity | Title |
| -------- | -------- | 
|H-01 |Exploit reentrancy in transfer function, can get double postion token in mintTokenizedPosition function.|

## [H-01]  Exploit reentrancy in transfer function, can get double postion token in mintTokenizedPosition function.

## Vulnerability details
### Impact
If erc20 token in uniswap v3 pool has transfer funtion which will call other contract,it will be exploit to reentrancy in "mintTokenizedPosition" ，and transfer a "backup" of the erc1155 position baseFee state before it update, and update one in postion key. As a effect of this operation, it will get more collect fee from uniswap V3 to msg.sender.
### Proof of Concept
https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1031
https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1051
https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1209
https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1222
https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1062


we asseume a uniswap v3 pool called P0,and it has one can be exploited token A.

Token A has a tranfer function which can call attack contract function. Like onERC721Receiver() to check receiver,it has an onERC20Spender() to check spender,or this token is used to phishing attack,it has a call to arbitrary contract logic.

When someone mint one tokened position with one leg which's isLong = 0 in P0 pool,it will call mintTokenizedPosition function, and mint ERC1155 token to msg.sender before create:

https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L510
```
function mintTokenizedPosition(
        uint256 tokenId,
        uint128 positionSize,
        int24 slippageTickLimitLow,
        int24 slippageTickLimitHigh
    )
        external
        ReentrancyLock(tokenId.univ3pool())
        returns (int256 totalCollected, int256 totalSwapped, int24 newTick)
    {
        _mint(msg.sender, tokenId, positionSize);

        emit TokenizedPositionMinted(msg.sender, tokenId, positionSize);
      	(totalCollected, totalSwapped, newTick) = _validateAndForwardToAMM(
            tokenId,
            positionSize,
            slippageTickLimitLow,
            slippageTickLimitHigh,
            MINT
        );
    }
```
then call internal _createLegInAMM function,it will record one state:

https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L959

```
uint256 currentLiquidity = s_accountLiquidity[positionKey]; //cache
```
and use _mintLiquidity() to call uniswap v3 pool:

https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1031

```
            _moved = isLong == 0
                ? _mintLiquidity(_liquidityChunk, _univ3pool)
                : _burnLiquidity(_liquidityChunk, _univ3pool); // from msg.sender to Uniswap
```
https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1175

```
    function _mintLiquidity(
        uint256 liquidityChunk,
        IUniswapV3Pool univ3pool
    ) internal returns (int256 movedAmounts) {
        // build callback data
        bytes memory mintdata = abi.encode(
            CallbackLib.CallbackData({ // compute by reading values from univ3pool every time
                    poolFeatures: CallbackLib.PoolFeatures({
                        token0: univ3pool.token0(),
                        token1: univ3pool.token1(),
                        fee: univ3pool.fee()
                    }),
                    payer: msg.sender
                })
        );
        (uint256 amount0, uint256 amount1) = univ3pool.mint(
            address(this),
            liquidityChunk.tickLower(),
            liquidityChunk.tickUpper(),
            liquidityChunk.liquidity(),
            mintdata
        );
       movedAmounts = int256(0).toRightSlot(int128(int256(amount0))).toLeftSlot(
            int128(int256(amount1))
        );
    }
```
in uniswap v3 pool mint, it will call uniswapV3MintCallback function in SFPM:
```
function uniswapV3MintCallback(
        uint256 amount0Owed,
        uint256 amount1Owed,
        bytes calldata data
    ) external {
        CallbackLib.CallbackData memory decoded = abi.decode(data, (CallbackLib.CallbackData));
        CallbackLib.validateCallback(msg.sender, address(FACTORY), decoded.poolFeatures);
        if (amount0Owed > 0)
            SafeTransferLib.safeTransferFrom(
                decoded.poolFeatures.token0,
                decoded.payer,
                msg.sender,
                amount0Owed
            );
        if (amount1Owed > 0)
            SafeTransferLib.safeTransferFrom(
                decoded.poolFeatures.token1,
                decoded.payer,
                msg.sender,
                amount1Owed
            );
    }
```
Then, token A can perform a reentry in the transfer function, invoking the ERC1155 safeTransferFrom function in the SFPM to transfer the already minted tokenId positions.

Noticed SFPM burnTokenizedPosition has ReentrancyLock，but it's ERC1155 safeTransferFrom has no ReentrancyLock:https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/tokens/ERC1155Minimal.sol#L90](https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/tokens/ERC1155Minimal.sol#L90)

```
 function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public {
...
    }
```
Then can transfer all tokenId postion to others, and clear s_accountFeesBase in registerTokentransfer ：

https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L625-L630
```
            //update+store liquidity and fee values between accounts
            s_accountLiquidity[positionKey_to] = fromLiq;
            s_accountLiquidity[positionKey_from] = 0;

            s_accountFeesBase[positionKey_to] = fromBase;
            s_accountFeesBase[positionKey_from] = 0;
            unchecked {
                ++leg;
            }
```
Until uniswap V3 mint is over,we use local memory currentLiquidity and updatedLiquidityto update and calculate:

https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1049-L1066
```
        // if there was liquidity at that tick before the transaction, collect any accumulated fees
        if (currentLiquidity.rightSlot() > 0) {
            _totalCollected = _collectAndWritePositionData(
                _liquidityChunk,
                _univ3pool,
                currentLiquidity,
                positionKey,
                _moved,
                isLong
            );
        }

        // position has been touched, update s_accountFeesBase with the latest values from the pool.positions
        s_accountFeesBase[positionKey] = _getFeesBase(
            _univ3pool,
            updatedLiquidity,
            _liquidityChunk
        );
```
it will use memory updatedLiquidity to calculate new feesBase,and save it in s_accountFeesBase[positionKey], and now we have a s_accountFeesBase "backup" transfer to others,and update one in this postionKey，now we get double postion token.

In _collectAndWritePositionData function, because of s_accountFeesBase[positionKey] == 0 by tranfer token, msg.sender will receive collect token more then it deserved:

https://github.com/code-423n4/2023-11-panoptic/blob/aa86461c9d6e60ef75ed5a1fe36a748b952c8666/contracts/SemiFungiblePositionManager.sol#L1209-L1210

```
    function _collectAndWritePositionData(
        uint256 liquidityChunk,
        IUniswapV3Pool univ3pool,
        uint256 currentLiquidity,
        bytes32 positionKey,
        int256 movedInLeg,
        uint256 isLong
    ) internal returns (int256 collectedOut) {
        uint128 startingLiquidity = currentLiquidity.rightSlot();
        int256 amountToCollect = _getFeesBase(univ3pool, startingLiquidity, liquidityChunk).sub(
            s_accountFeesBase[positionKey]
        );

        if (isLong == 1) {
            amountToCollect = amountToCollect.sub(movedInLeg);
        }
        if (amountToCollect != 0) {
            (uint128 receivedAmount0, uint128 receivedAmount1) = univ3pool.collect(
                msg.sender,
                liquidityChunk.tickLower(),
                liquidityChunk.tickUpper(),
                uint128(amountToCollect.rightSlot()),
                uint128(amountToCollect.leftSlot())
            );
```
## Recommended Mitigation Steps
add ReentrancyLock in registerTokentransfer function.

