| Severity | Title |
| -------- | -------- | 
|H-01 |Incorrect Reward Calculation in `TempleGoldStaking`|
|L-01 |A user could postpone the reward to the next epoch by front-running|


## [H-01] Incorrect Reward Calculation in `TempleGoldStaking`

## Vulnerability details
### Description
In `TempleGoldStaking`, when a user first stakes, their `userRewardPerTokenPaid` is set to `0` since `stakeInfo` is not `initialized` as `updateReward` is being called first. Later, in the `_earned` function, when the user has passed the `vestingPeriod`, `_perTokenReward` would equal `_rewardPerToken()`. And the final reward calculation `_stakeInfo.amount * (_perTokenReward - userRewardPerTokenPaid[_account][_index]) / 1e18` suggests that the current reward is `_stakeInfo.amount * _rewardPerToken() / 1e18`, which means the reward for amount is calculated for the whole staking period, far exceeding the actual staking time.


### Proof of Concept

The `updateReward` modifier is used to update the `rewardPerTokenStored` and `userRewardPerTokenPaid[_account][_index]`.

```solidity
modifier updateReward(address _account, uint256 _index) {
{
	// stack too deep
@=>	rewardData.rewardPerTokenStored = uint216(_rewardPerToken());
	rewardData.lastUpdateTime = uint40(_lastTimeRewardApplicable(rewardData.periodFinish));
	if (_account != address(0)) {
		StakeInfo memory _stakeInfo = _stakeInfos[_account][_index];
@=>	    uint256 vestingRate = _getVestingRate(_stakeInfo);
		claimableRewards[_account][_index] = _earned(_stakeInfo, _account, _index);
@=>		userRewardPerTokenPaid[_account][_index] = vestingRate * uint256(rewardData.rewardPerTokenStored) / 1e18;
		}
	}
	_;

}
```

When a user first stakes, `_applyStake` is called, triggering `updateReward`.

In the calculation:

* The `vestingRate` is calculated as  `_getVestingRate(_stakeInfo)`, but since `_stakeInfo` is not initialized (`_stakeInfo.stakeTime == 0`), `vestingRate` is 0.
* `claimableRewards[_account][_index]` is 0 because `vestingRate` is 0.
* As a result, `userRewardPerTokenPaid[_account][_index] = vestingRate * uint256(rewardData.rewardPerTokenStored) / 1e18` is also `0`.

Later, when the user’s vesting period has passed, the user calls `getReward`, invoking `updateReward` again.

* The `vestingRate` is now `1e18` because the condition `block.timestamp > _stakeInfo.fullyVestedAt` is true.

```solidity
if (block.timestamp > _stakeInfo.fullyVestedAt) {
	vestingRate = 1e18;
}
```

* In the `_earned` function, `_perTokenReward` is equal to `_rewardPerToken()` as `vestingRate == 1e18`.

```solidity
if (vestingRate == 1e18) {
	_perTokenReward = _rewardPerToken();
}
```

* The final earned calculation in `_earned` is `(_stakeInfo.amount * (_perTokenReward - userRewardPerTokenPaid[_account][_index])) / 1e18 + claimableRewards[_account][_index]`, which simplifies to `_stakeInfo.amount * _rewardPerToken() / 1e18`. This results in the reward being calculated based on `rewardData.rewardPerTokenStored` for the entire staking period, exceeding the user’s actual staking time.

```soldity
return
	(_stakeInfo.amount * (_perTokenReward - userRewardPerTokenPaid[_account][_index])) / 1e18 +
	claimableRewards[_account][_index];
```

* This leads to `claimableRewards[_account][_index]` being updated to a higher amount, allowing the user to claim more rewards than they should.


## Recommended Mitigation Steps
Reconsider the design of the reward calculation. `userRewardPerTokenPaid` should always record the `rewardPerTokenStored` without any further modification to ensure accurate reward calculation based on the actual staking time.





## [L-01] A user could postpone the reward to the next epoch by front-running


## Vulnerability details
### Description
In `TempleGoldStaking `, if `distributionStarter == address(0)`, anyone can call the function `distributeRewards` to distribute `TempleGold` rewards to stakers. In some cases, a user could intentionally postpone the reward to the next epoch and make others wait another `rewardDistributionCoolDown` by front-running the `notifyDistribution` from the `TempleGold`.

If `distributionStarter == address(0)`, anyone can call the function `distributeRewards` to distribute `TempleGold` rewards to stakers.

```solidity
function distributeRewards() updateReward(address(0), 0) external {
	if (distributionStarter != address(0) && msg.sender != distributionStarter)
{ revert CommonEventsAndErrors.InvalidAccess(); }
	...
}
```

When the `TempleGold` contract calls `TempleGoldStaking::notifyDistribution` to add `nextRewardAmount` with large amount of token minted, a user could intentionally postpone the reward to the next epoch.

```solidity
	uint256 rewardAmount = nextRewardAmount;
	// revert if next reward is 0 or less than reward duration (final dust amounts)
	if (rewardAmount < rewardDuration ) { revert CommonEventsAndErrors.ExpectedNonZero(); }
	nextRewardAmount = 0;
	_notifyReward(rewardAmount);
```

Others will have to wait additionally `rewardDistributionCoolDown` to be able to `distribute` again. During this interval, the user could stake by himself to enjoy the high reward rate for the following epoch.

```solidity
	if (lastRewardNotificationTimestamp + rewardDistributionCoolDown > block.timestamp)
	{ revert CannotDistribute(); }
```

## Recommended Mitigation Steps
To mitigate this issue:

* remove the setup of `rewardDistributionCoolDown` or make it as `0`.
* Add access control to `distributeRewards`



