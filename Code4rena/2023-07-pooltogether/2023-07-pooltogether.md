| Severity | Title |
| -------- | -------- | 
|M-01 |Potential frontrunning in setDrawManager.|

## [M-01]  Potential frontrunning in setDrawManager.

## Vulnerability details
### Impact
In the code comments, it is mentioned:
```
  /// @notice Allows a caller to set the DrawManager if not already set.
  /// @dev Notice that this can be front-run: make sure to verify the drawManager after construction
  /// @param _drawManager The draw manager
```
setDrawManager allows the caller to set the DrawManager address without performing permission verification, only checking for the zero address.

As long as the current DrawManager address is not the zero address, anyone can call this function to change the DrawManager address.

This may result in unauthorized individuals or contracts being able to call withdrawReserve() to withdraw tokens.


### Proof of Concept
https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/4bc8a12b857856828c018510b5500d722b79ca3a/src/PrizePool.sol#L296-L306


## Recommended Mitigation Steps
Add appropriate permission verification to the setDrawManager function. Check the caller's permissions.