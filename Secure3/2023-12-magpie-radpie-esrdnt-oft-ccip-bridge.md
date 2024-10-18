| Severity | Title |
| -------- | -------- | 
|M-01 |Refund excess funds or set up the withdraw mechanism|

# Refund excess funds or set up the withdraw mechanism

## Location

https://github.com/Secure3Audit/code_Magpie_CCIP/blob/cf6caf72c5b14f7de34f80a0fb2e328cd4f4a8fd/code/contracts/crosschain/RadpieCCIPBridge.sol#L113-L151

## Description

Suppose a user sent more ETH to the RadpieCCIPBridge contract via tokenTransfer(). Currently there is no way to withdraw the excessive ETH so those ETH will be stuck in the contract forever.

## Recommendation

Compute excess ETH sent to the contract:

```solidity
msg.value - actualCost
```

and store this value inside a local accounting system. Implement a separate `withdraw()` function to let users withdraw themselves. This follows the pull over push pattern.
