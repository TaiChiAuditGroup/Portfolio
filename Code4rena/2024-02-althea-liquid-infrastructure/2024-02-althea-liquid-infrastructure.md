| Severity | Title |
| -------- | -------- | 
|M-01 |approveHolder and disapproveHolder should not be called during distribution |
|M-02 |calling setDistributableERC20s during distribution will cause unexpected DoS or incorrect distribution  |
|L-01 |Redundant requirement will never revert|



## [M-01]  approveHolder and disapproveHolder should not be called during distribution 

## Vulnerability details
### Impact
approveHolder and disapproveHolder should not be called during distribution. If a holder is disapproved, some rewards will be left in the contract and will not be used in this round of distribution.
### Proof of Concept
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L106-L109
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L116-L119
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L216

There is no check of LockedForDistribution in the function approveHolder and disapproveHolder. This means that a user can be disapproved during the distribution process.
```
    function disapproveHolder(address holder) public onlyOwner {
        require(isApprovedHolder(holder), "holder not approved");
        HolderAllowlist[holder] = false;
    }
```
Consider the following scenario:

1. User A, B, and C is ready for distribution.
2. User A is distributed.
3. Later user B is disapproved, so he will not get his share of rewards.
4. After C is distributed, some rewards are still left in the contract, leading to incorrect distribution.
## Recommended Mitigation Steps
Add require(!LockedForDistribution," cannot disapprove/approve when already locked"); in the function approveHolder and disapproveHolder.



## [M-01]  calling setDistributableERC20s during distribution will cause unexpected DoS or incorrect distribution

## Vulnerability details
### Impact
In the setDistributableERC20s function, the distributableERC20s is reset by the owner without any check on LockedForDistribution . If the function is called after the distribution has begun, this would cause inconsistency between distributableERC20s and erc20EntitlementPerUnit, leading to Denial of Service or incorrect rewards distribution.
### Proof of Concept
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L441-L445
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L272-L276
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L221-L225


In the setDistributableERC20s function, the distributableERC20s is reset by the owner. Thus tokens and length may all change during the function call.
```
    function setDistributableERC20s(
        address[] memory _distributableERC20s
    ) public onlyOwner {
        distributableERC20s = _distributableERC20s;
    }
```
However, since there is no check on LockedForDistribution, the function setDistributableERC20s could be called during the distribution process.

In _beginDistribution however, erc20EntitlementPerUnit will be created for each token in distributableERC20s.
```
        for (uint i = 0; i < distributableERC20s.length; i++) {
            uint256 balance = IERC20(distributableERC20s[i]).balanceOf(
                address(this)
            );
            uint256 entitlement = balance / supply;
            erc20EntitlementPerUnit.push(entitlement);
        }
```
If setDistributableERC20s after _beginDistribution, this would cause inconsistency in tokens and length. And would cause unintended behavior in distribute since erc20EntitlementPerUnit[j] is inconsistent with distributableERC20s[j].
```
                for (uint j = 0; j < distributableERC20s.length; j++) {
                    IERC20 toDistribute = IERC20(distributableERC20s[j]);
                    uint256 entitlement = erc20EntitlementPerUnit[j] *
                        this.balanceOf(recipient); 
                    if (toDistribute.transfer(recipient, entitlement)) {
                        receipts[j] = entitlement;
                    }
                }
```
In this scenario, the transaction would revert if erc20EntitlementPerUnit.length < distributableERC20s.length or there is not enough balance to transfer for the new token. Otherwise, the distribution would be completely incorrect(For example, 3 USDT is distributed, but should be 3 WETH instead).
## Recommended Mitigation Steps
Add require(!LockedForDistribution," cannot set distributableERC20s when already locked"); in the function setDistributableERC20s.


## [L-01] Redundant requirement will never revert 

## Vulnerability details
### Impact
The redundant requirement will never revert and should be removed.
### Proof of Concept
https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/bd6ee47162368e1999a0a5b8b17b701347cf9a7d/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L431

The requirement require(true, "unable to find released NFT in ManagedNFTs"); is useless in the code since it will never revert.
## Recommended Mitigation Steps