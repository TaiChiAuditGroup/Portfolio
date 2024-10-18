| Severity | Title |
| -------- | -------- | 
|H-01 |Adversary can make honest parties unable to retrieve their assertion stakes if the required amount is decreased|
|H-02 |checkClaimIdLink does not check ClaimId|
|L-01 |The time spent paused is incremented in the rollup's timing for assertion validation.|


## [H-01]  Adversary can make honest parties unable to retrieve their assertion stakes if the required amount is decreased
## Vulnerability details
### Impact
When the required stake (to create a new assertions) is updated to a lower amount, adversary can make the honest party unable to retrieve their assertion stakes.


### Proof of Concept
https://github.com/code-423n4/2024-05-arbitrum-foundation/blob/6f861c85b281a29f04daacfe17a2099d7dad5f8f/src/rollup/RollupUserLogic.sol#L180

```
 A -- B -- C -- D(latest confirmed) -- E
```
Suppose the initial stake amount is 1000 ETH, and till now no invalid assertions have been made. (A, B, C, D, E are all valid and made by the same validator). The rollup contract should hold 1000 ETH now.
```
 A -- B -- C -- D(latest confirmed) -- E
                                    \
                                     \ F(invalid)
```
Then, the admin update the required stake to 700 ETH, Alice made an invalid assertion F. Since its parent D was created before the update, Alice will still need to stake 1000 ETH, and the 1000 ETH will be sent to loserStakeEscrow.
```
        if (!getAssertionStorage(newAssertionHash).isFirstChild) {

            // only 1 of the children can be confirmed and get their stake refunded
            // so we send the other children's stake to the loserStakeEscrow
            IERC20(stakeToken).safeTransfer(loserStakeEscrow, assertion.beforeStateData.configData.requiredStake);
        }
```
```
 A -- B -- C -- D(latest confirmed) -- E
                                    \

                                     \ F -- G
```
(a) Alice creates F's children, G. Now, only 700 ETH of stake is needed. However, as the comment suggests, no refund will be made since G's ancestor could need more stake.
```
        // requiredStake is user supplied, will be verified against configHash later
        // the prev's requiredStake is used to make sure all children have the same stake
        // the staker may have more than enough stake, and the entire stake will be locked
        // we cannot do a refund here because the staker may be staker on an unconfirmed ancestor that requires more stake
        // excess stake can be removed by calling reduceDeposit when the staker is inactive
        require(amountStaked(msg.sender) >= assertion.beforeStateData.configData.requiredStake, "INSUFFICIENT_STAKE");
```
(b) To bypass the limit in (a), Alice calls her friend Bob to make the assertion G instead , Bob will only need to stake 700 ETH now. The rollup contract currently holds 1700 ETH. Then, Alice can withdraw her stake since she is no longer active. (her last staked assertion have a child)
```
    function requireInactiveStaker(address stakerAddress) internal view {
        require(isStaked(stakerAddress), "NOT_STAKED");
        // A staker is inactive if
        // a) their last staked assertion is the latest confirmed assertion
        // b) their last staked assertion have a child
        bytes32 lastestAssertion = latestStakedAssertion(stakerAddress);
        bool isLatestConfirmed = lastestAssertion == latestConfirmed();
        bool haveChild = getAssertionStorage(lastestAssertion).firstChildBlock > 0;
        require(isLatestConfirmed || haveChild, "STAKE_ACTIVE");
    }
```
Now the rollup contract holds 700 ETH, which means it is insolvent. The honest validator cannot withdraw her original stake. (700 < 1000)
## Recommended Mitigation Steps
Ensure the following

1. A staker is considered inactive only if her last staked assertion is confirmed.
2. A staker can only stake on her last staked assertion's descendants. (otherwise Alice can switch to the correct branch and withdraw)


## [H-02]  checkClaimIdLink does not check ClaimId
## Vulnerability details
### Impact
checkClaimIdLink does not check ClaimId, and a terminal node can inherit timers which it does not deserve.
### Proof of Concept
https://github.com/code-423n4/2024-05-arbitrum-foundation/blob/6f861c85b281a29f04daacfe17a2099d7dad5f8f/src/challengeV2/libraries/EdgeChallengeManagerLib.sol#L683-L710

According to BoLD paper section 5.4, suppose A, B are terminal nodes which rivals each other (aka shares the same mutualId), and A has children a1, a2, B has children b1, b2, b3. The five children share the same origin id (which is A,B's mutualId).

We should have
β(A,t) := λ(A,t) + max{β(a1,t), β(a2,t), β(a3,t)}
β(B,t) := λ(B,t) + max{β(b1,t), β(b2,t)}

```
    function checkClaimIdLink(EdgeStore storage store, bytes32 edgeId, bytes32 claimingEdgeId, uint8 numBigStepLevel)
        private
        view
    {
        // the origin id of an edge should be the mutual id of the edge in the level below
        if (store.edges[edgeId].mutualId() != store.edges[claimingEdgeId].originId) {
            revert OriginIdMutualIdMismatch(store.edges[edgeId].mutualId(), store.edges[claimingEdgeId].originId);
        }
        // the claiming edge must be exactly one level below
        if (nextEdgeLevel(store.edges[edgeId].level, numBigStepLevel) != store.edges[claimingEdgeId].level) {
            revert EdgeLevelInvalid(
                edgeId,
                claimingEdgeId,
                nextEdgeLevel(store.edges[edgeId].level, numBigStepLevel),
                store.edges[claimingEdgeId].level
            );
        }
    }
```
However, in our implementation, we only check the originId of the children matches the mutualId of the parent.
We can actually set β(A,t) := λ(A,t) + β(b1,t), which means an edge can inherit timer from its rival's children!
Even worse, all of a1, a2, a3, b1, b2's descendants at the same level will share the same originId. We can start from a (proved) proof node at level N, by using it as claimingEdgeId and using its level N-1 length 1 ancestor (or the ancestor's rival) as edgeId, we can set edgeId's timer to type(uint64).max. By repeating so, we can almost instantly confirm any level 0 length 1 edge.
```
            // when bisecting originId is preserved
            ChallengeEdge memory lowerChild = ChallengeEdgeLib.newChildEdge(
                ce.originId, ce.startHistoryRoot, ce.startHeight, bisectionHistoryRoot, middleHeight, ce.level
            );
```
## Recommended Mitigation Steps
require(store.edges[claimingEdgeId].claimId == edgeId);


## [L-01]  The time spent paused is incremented in the rollup's timing for assertion validation.
## Vulnerability details
### Impact
```
    /**
     * @notice Pause interaction with the rollup contract.
     * The time spent paused is not incremented in the rollup's timing for assertion validation.
     * @dev this function may be frontrun by a validator (ie to create a assertion before the system is paused).
     * The pause should be called atomically with required checks to be sure the system is paused in a consistent state.
     * The RollupAdmin may execute a check against the Rollup's latest assertion num or the OldChallengeManager, then execute this function atomically with it.
     */
    function pause() external override {
        _pause();
        emit OwnerFunctionCalled(3);
    }
```
According to the comment, the time spent paused should not be incremented in the rollup's timing for assertion validation. However, the rollup's timing does not take paused time into consideration in reality. As a result, adversary can censor transactions (within the censorship budget) and force incorrect assertion to be confirmed.


### Proof of Concept
https://github.com/code-423n4/2024-05-arbitrum-foundation/blob/6f861c85b281a29f04daacfe17a2099d7dad5f8f/src/rollup/RollupAdminLogic.sol#L145
https://github.com/code-423n4/2024-05-arbitrum-foundation/blob/6f861c85b281a29f04daacfe17a2099d7dad5f8f/src/rollup/RollupUserLogic.sol#L110
According to the contest doc

We assume that an adversary can censor transactions for at most 1 challengePeriodBlocks or confirmPeriodBlock (whichever is smaller)

Suppose challengePeriodBlocks and confirmPeriodBlock are both 7 days. The steps are as following:

1. Adversary make an invalid assertion to the latest confirmed assertion, and censor all other txs that submit assertion for 2 days.(Day 0 - Day 1)
2. Admin pauses the rollup to counteract the situation for 2 days.(Day 2 - Day 3)
3. Admin realizes pausing doesn't help, and unpauses.
4. Adversary continues to censor all txs that submit assertion for 4 days.(Day 4 - Day 7)
5. Adversary confirms this incorrect assertion.
Since no one can make new assertions when the contract is paused, the adversary only needs to spend 6 days of censorship budget (to confirm an incorrect assertion) in this case.

require(block.number >= assertion.createdAtBlock + prevConfig.confirmPeriodBlocks, "BEFORE_DEADLINE");
As this line suggests, no special care for paused time is taken.

## Recommended Mitigation Steps
Make sure the time spent paused is not incremented in the rollup's timing for assertion validation.