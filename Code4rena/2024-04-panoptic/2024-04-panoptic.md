| Severity | Title |
| -------- | -------- | 
|M-01 |No Slippage Protection When Mint Liquidity|
|L-01 |ERC1155::supportsInterface should be virtual |


## [M-01]  No Slippage Protection When Mint Liquidity

## Vulnerability details
### Impact
There is no slippage protection during the minting of full-range-liquidity. In the process, the slot0 is queried and there is no check from the user that the liquidity should be within an acceptable range. Thus user may suffer from loss when providing liquidity in Uniswap V3.
### Proof of Concept
https://github.com/code-423n4/2024-04-panoptic/blob/833312ebd600665b577fbd9c03ffa0daf250ed24/contracts/PanopticFactory.sol#L335

In PanopticFactory::deployNewPool, the full-range liquidity should be provided by msg.sender.

```
        // Mints the full-range initial deposit
        // which is why the deployer becomes also a "donor" of full-range liquidity
        // The SFPM will `safeTransferFrom` tokens from the donor during the mint callback
        (uint256 amount0, uint256 amount1) = _mintFullRange(v3Pool, token0, token1, fee);
```
In the _mintFullRange, the IUniswapV3Pool(v3Pool).mint is being called. But there is no slippage protection during the minting of full-range-liquidity. In the process, the slot0 is queried and there is no check from the user that the liquidity should be within an acceptable range.

```
        (uint160 currentSqrtPriceX96, , , , , , ) = v3Pool.slot0();
        ...
        return
            IUniswapV3Pool(v3Pool).mint(
                address(this),
                tickLower,
                tickUpper,
                fullRangeLiquidity,
                mintCallback
            );
```
Thus, if the pool has gone through prices changes before the mint, the user may suffer from slippage loss.
## Recommended Mitigation Steps
It is recommended to add slippage protection in the function PanopticFactory::deployNewPool.



## [L-01]  ERC1155::supportsInterface should be virtual

## Vulnerability details
### Impact
ERC1155::supportsInterface should be virtual, otherwise it can't be override to add other interface-support.


### Proof of Concept
https://github.com/code-423n4/2024-04-panoptic/blob/833312ebd600665b577fbd9c03ffa0daf250ed24/contracts/tokens/ERC1155Minimal.sol#L200-L204

In the function ERC1155::supportsInterface, there is no virtual for the function, so that it can not be override.
```
    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165 Interface ID for ERC165
            interfaceId == 0xd9b67a26; // ERC165 Interface ID for ERC1155
    }
```
Since ERC1155 currently doesn't support interfaceId == 0x0e89341c(ERC165 Interface ID for ERC1155MetadataURI), the supportsInterface could not be changed to add more interfaces. This may cause future integration problems.

## Recommended Mitigation Steps
Add virtual for function supportsInterface so that more interfaces could be added in the future for better implementation.