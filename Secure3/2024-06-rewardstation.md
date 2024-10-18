| Severity | Title |
| -------- | -------- | 
|M-01 | Calculation in AllocateRegister.changeAllocate() is wrong due to incorrect casting to uint256 |
|M-02 | allocate and unallocate will always revert due to incorrect use of EnumerableMap |
|L-01 | StakingMETH.deposit() can't be paused |

# Calculation in AllocateRegister.changeAllocate() is wrong due to incorrect casting to uint256

## Location

https://github.com/Secure3Audit/code_RewardStation/blob/1355d75cbc14ac07ce1a8cbbd76d3bb46839fbde/code/src/AllocateRegister.sol#L165

## Description

The following line of code attempts to convert a negative number `msgs[i].amount` to its absolute value by casting it to `uint256` directly. This will give unexpected result since casting to `uint256` is not equivalent to computing absolute value. Instead, it attempts to interpret 2's complement representation of a negative number as positive number, therefore it will return a gibberish large number.

For a toy PoC, copy the following contract into Remix IDE:

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

contract int256ToUint256 {

    function convert() public pure returns(uint256){
        int256 x = -3;
        return uint256(x);
    }
}
```

Developer might expect it to return 3, but it returns a huge number instead:

```
115792089237316195423570985008687907853269984665640564039457584007913129639933
```

## Recommendation

An elegant way to handle such case is implementing a function to compute absolute value:

```solidity
function abs(int256 x) private pure returns (uint256) {
    return x >= 0 ? uint256(x) : uint256(-x);
}
```

And change the code to:

```solidity
_unallocate(msgs[i].tranche, msgs[i].owner, abs(msgs[i].amount));
```

# allocate and unallocate will always revert due to incorrect use of EnumerableMap

## Location

https://github.com/Secure3Audit/code_RewardStation/blob/1355d75cbc14ac07ce1a8cbbd76d3bb46839fbde/code/src/AllocateRegister.sol#L199-L202

https://github.com/Secure3Audit/code_RewardStation/blob/1355d75cbc14ac07ce1a8cbbd76d3bb46839fbde/code/src/AllocateRegister.sol#L224-L227

https://github.com/Secure3Audit/code_RewardStation/blob/1355d75cbc14ac07ce1a8cbbd76d3bb46839fbde/code/src/rewards/StandardTranche.sol#L52-L55

https://github.com/Secure3Audit/code_RewardStation/blob/1355d75cbc14ac07ce1a8cbbd76d3bb46839fbde/code/src/rewards/StandardTranche.sol#L69-L72

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ccc110360f1028143e137258d12a0891f17df3a4/contracts/utils/structs/EnumerableMap.sol#L71-L81

## Description

Currently allocate and unallocate functions in code/src/AllocateRegister.sol and code/src/AllocateRegister.sol will always revert due to incorrect use of EnumerableMap.

Here is the code for `EnumerableMap.set()`:

```solidity
    /**
     * @dev Adds a key-value pair to a map, or updates the value for an existing
     * key. O(1).
     *
     * Returns true if the key was added to the map, that is if it was not
     * already present.
     */
    function set(Bytes32ToBytes32Map storage map, bytes32 key, bytes32 value) internal returns (bool) {
        map._values[key] = value;
        return map._keys.add(key);
    }
```

Here the `add()` comes from `EnumerableSet`:

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/05f218fb6617932e56bf5388c3b389c3028a7b73/contracts/utils/structs/EnumerableSet.sol#L65-L75

    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }
```

We can see that if the map already contains the key, `set()` will always return false because of how `EnumerableSet._add()` is programmed.

Back to the allocate and unallocate functions, take `StandardTranche.allocate()` as example:

```solidity
    /// @notice Add a new allocation to owner
    /// @param user The address of the allocation owner
    /// @param amount The amount allocated
    function allocate(address user, uint256 amount) external nonReentrant onlyRegister {
        (,uint256 _amount) = userAllocations.tryGet(user);
        uint256 allocated_ = _amount + amount;
        if (capacity != -1 && int256(allocated_) > capacity ) {
            revert AllocateOverBound();
        }
        // @audit-issue [High] It returns false when key "user" already exists
        bool ok = userAllocations.set(user, allocated_);
        if (!ok) {
            revert AllocatedFailed();
        }
    }
```

The boolean value ok here will be false since in this scenario we assume the key user exists in EnumerableMap userAllocations, and we are trying to update the value corresponding to that key. The consequence is that such txs will always revert, rendering allocate and unallocate functionalities unless.

Recommendation
When updating a key-value pair, don’t check if `set()` returns true since it will always return false. Take `StandardTranche.allocate()` as example, the logic can be implemented in two branches:

If `_amount` is 0, user record is not in the `EnumerableMap` so the current code is good.
If `_amount` is non-zero, just call `set()` without checking its return value:

```solidity
userAllocations.set(user, allocated_);
```

# StakingMETH.deposit() can't be paused

## Location

https://github.com/Secure3Audit/code_RewardStation/blob/1355d75cbc14ac07ce1a8cbbd76d3bb46839fbde/code/src/StakingMETH.sol#L103-L114

## Description

`StakingMETH.deposit()` lacks the pauser check:

```solidity
    if (pauser.isStakingPaused()) {
        revert Paused();
    }
```

Therefore it can't be paused.

When pauser is in paused state, user can still call `StakingMETH.deposit()` to stake but can't withdraw since `StakingMETH.withdraw()` has the pauser check.

## Recommendation

Add check:

```diff
    function deposit(uint256 assets) public payable override nonReentrant returns (uint256) {
      + if (pauser.isStakingPaused()) {
      +     revert Paused();
      + }
        if (assets < minStake) {
            revert DepositAmountTooSmall(_msgSender(), assets, minStake);
        }
        if (maxStakeSupply != 0 && assets + totalDeposit() > maxStakeSupply) {
            revert DepositOverBond();
        }
        _userStakeCooldown[_msgSender()] = block.timestamp;
        return super.deposit(assets);
    }
```
