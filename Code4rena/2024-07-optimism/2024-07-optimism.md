
| Severity | Title |
| -------- | -------- | 
|H-01 |Invalid DISPUTED_L2_BLOCK_NUMBER is passed to VM |
|M-01 | Attacker can continuously create games for not yet safe l2 blocks to prevent the update of anchor state |
|M-02 | Honest party's move could become invalid when re-org takes place  |
|M-03 |   If the clock has more than CLOCK_EXTENSION but less than CLOCK_EXTENSION * 2 seconds remaining, no time will be allocated |

## [H-01]  Invalid DISPUTED_L2_BLOCK_NUMBER is passed to VM

## Vulnerability details
### Impact
The span of the game tree at split depth is far larger than the length between the starting block and the claimed block, when starting block + trace index + 1 > claimed block, honest party should continue to commit to the root of the claimed block. However, the DISPUTED_L2_BLOCK_NUMBER passed to the VM is always starting block + trace index + 1, which means the op-program (at inter-block perspective) will not stop until it reached the l2 safe head(corresponding to parenthash), and if the claimed block is earlier than the safe head, it can be challenged and will be considered invalid.
### Proof of Concept
https://github.com/code-423n4/2024-07-optimism/blob/70556044e5e080930f686c4e5acde420104bb2c4/packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol#L453
Since op-program is out of scope of this contest, this report will not spend too much time in proving block earlier than safe head can be challenged, instead it will only show the inconsistency within the smart contract part.

For simplicity, we assume the span of the game tree at split depth is 8 and starting block is 0. At block level, we use defend a ->p b to refer to commit a valid VM trace with a as starting output, b as disputed output, p as disputed block number and VALID as the final state, similarly attack a ->p b refers to commit a valid VM trace with ... and INVALID or PANIC as the final state. We use Bi to refer to the valid L2 root at block i.

Suppose Alice made a valid root claim B2 for block 2, Bob made a valid root claim B3 for block 3 and they claim at the same L1 block (so the stored l1Head will be the identical). Ideally, both of them should be able to defend their claim. We already know that Bob can defend B2 ->3 B3 in his own game. What if Bob tries to attack Alice in her game?

(Recall Alice's view of valid state is 12222222 and Bob's is 12333333)
1. Bob attacks by claiming B3. (trace index 3)
2. Alice attacks by claiming B2. (trace index 1)
3. Bob defends by claiming B3. (trace index 2)
4. Alice attacks B2 ->3 B3. (disputed block = starting block + trace index + 1 = 3)
```
    /// @inheritdoc IFaultDisputeGame
    function addLocalData(uint256 _ident, uint256 _execLeafIdx, uint256 _partOffset) external {
        // INVARIANT: Local data can only be added if the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) revert GameNotInProgress();

        (Claim starting, Position startingPos, Claim disputed, Position disputedPos) =
            _findStartingAndDisputedOutputs(_execLeafIdx);
        Hash uuid = _computeLocalContext(starting, startingPos, disputed, disputedPos);

        IPreimageOracle oracle = VM.oracle();
        if (_ident == LocalPreimageKey.L1_HEAD_HASH) {
            // Load the L1 head hash
            oracle.loadLocalData(_ident, uuid.raw(), l1Head().raw(), 32, _partOffset);
        } else if (_ident == LocalPreimageKey.STARTING_OUTPUT_ROOT) {
            // Load the starting proposal's output root.
            oracle.loadLocalData(_ident, uuid.raw(), starting.raw(), 32, _partOffset);
        } else if (_ident == LocalPreimageKey.DISPUTED_OUTPUT_ROOT) {
            // Load the disputed proposal's output root
            oracle.loadLocalData(_ident, uuid.raw(), disputed.raw(), 32, _partOffset);
        } else if (_ident == LocalPreimageKey.DISPUTED_L2_BLOCK_NUMBER) {
            // Load the disputed proposal's L2 block number as a big-endian uint64 in the
            // high order 8 bytes of the word.

            // We add the index at depth + 1 to the starting block number to get the disputed L2
            // block number.
            uint256 l2Number = startingOutputRoot.l2BlockNumber + disputedPos.traceIndex(SPLIT_DEPTH) + 1;

            oracle.loadLocalData(_ident, uuid.raw(), bytes32(l2Number << 0xC0), 8, _partOffset);
        } else if (_ident == LocalPreimageKey.CHAIN_ID) {
            // Load the chain ID as a big-endian uint64 in the high order 8 bytes of the word.
            oracle.loadLocalData(_ident, uuid.raw(), bytes32(L2_CHAIN_ID << 0xC0), 8, _partOffset);
        } else {
            revert InvalidLocalIdent();
        }
    }
```
However, all VM inputs above are identical for B2 ->3 B3 in these two cases. Since VM step is deterministic, B2 ->3 B3 cannot be defended in one game while attacked in another, which shows the contradiction. The problem is that claimed block number is not passed to the VM, so the VM cannot differentiate the context between the two games.


## Recommended Mitigation Steps
```
uint256 l2Number = min(startingOutputRoot.l2BlockNumber + disputedPos.traceIndex(SPLIT_DEPTH) + 1, l2BlockNumber());
```
## Note
```
func (d *Driver) ValidateClaim(l2ClaimBlockNum uint64, claimedOutputRoot eth.Bytes32) error {
	l2Head := d.SafeHead()
	outputRoot, err := d.l2OutputRoot(min(l2ClaimBlockNum, l2Head.Number))
	if err != nil {
		return fmt.Errorf("calculate L2 output root: %w", err)
	}
	d.logger.Info("Validating claim", "head", l2Head, "output", outputRoot, "claim", claimedOutputRoot)
	if claimedOutputRoot != outputRoot {
		return fmt.Errorf("%w: claim: %v actual: %v", ErrClaimNotValid, claimedOutputRoot, outputRoot)
	}
	return nil
}
```
Here l2ClaimBlockNum is just DISPUTED_L2_BLOCK_NUMBER, so DISPUTED_L2_BLOCK_NUMBER clearly should be capped at claimed l2 block number, otherwise the inter-block op-program execution will never stop until it reaches safe head, which means all claims earlier than safe head is invalid in op-program's perspective.


## [M-01]  Attacker can continuously create games for not yet safe l2 blocks to prevent the update of anchor state

## Vulnerability details
Brief
When creating a dispute game, the output root should be one of the safe l2 block's. However, attacker can continuously create games for not yet safe l2 blocks. Honest party can no longer propose the root after it becomes safe, since UUID must be unique. As a result, no root can be sucessfully defended, the anchor state can no longer be updated and the fund on L2 will be frozen.
### Impact
Attacker can avoid losing the bond by making a attack move in the same transaction, needing 0.08 (create) + 0.08 (attack) = 0.16eth once. The fund will be withdrawable after 3.5 (game clock) + 7 (weth delay) = 10.5 days. Assume block time is 2s, the capital needed is 0.16 × 10.5 × 24 × 3600 ÷ 2 = 72576eth ≈ 237 million dollars. Assume interest rate is 3%, to freeze l2 fund for one year, the cost would be 237 million × 3% = 7.11 million dollars, while the loss would be 13.54 billion (Optimism + Base TVL) × 3% = 406.2 million dollars.
### Proof of Concept
https://github.com/code-423n4/2024-07-optimism/blob/70556044e5e080930f686c4e5acde420104bb2c4/packages/contracts-bedrock/src/dispute/DisputeGameFactory.sol#L119-L123

When creating a dispute game, the output root should be one of the safe l2 block's. Otherwise, the claim can be attacked.

However, function create needs uuid to be unique.
```
    // Compute the unique identifier for the dispute game.
    Hash uuid = getGameUUID(_gameType, _rootClaim, _extraData);

    // If a dispute game with the same UUID already exists, revert.
    if (GameId.unwrap(_disputeGames[uuid]) != bytes32(0)) revert GameAlreadyExists(uuid);
```
If an attacker has already made the claim of this block earlier, when the block is still unsafe, the correct claim can no longer be made.


## Recommended Mitigation Steps
Include parentHash in uuid calculation.




## [M-02]  Honest party's move could become invalid when re-org takes place

## Vulnerability details
### Impact
When block re-org takes place, honest party's move could become invalid. A similar issue has been raised earlier, and this report shows two new scnearios, which the fix fails to address.


### Proof of Concept
https://github.com/code-423n4/2024-07-optimism/blob/70556044e5e080930f686c4e5acde420104bb2c4/packages/contracts-bedrock/src/dispute/DisputeGameFactory.sol#L116
https://github.com/Vectorized/solady/blob/a95f6714868cfe5d590145f936d0661bddff40d2/src/utils/LibClone.sol#L458
https://github.com/code-423n4/2024-07-optimism/blob/70556044e5e080930f686c4e5acde420104bb2c4/packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol#L319

A new parameter _claim has been added to ensure the target is the expected one, but this is still not enough.

```
function move(Claim _disputed, uint256 _challengeIndex, Claim _claim, bool _isAttack) public payable virtual {
```
The factory uses create instead of create2 to deploy the proxy, consider the following scenario:

1. Evil Alice creates a invalid root claim A and game P.
2. Seemingly honest Bob attacks A with claim B in game P.
3. Seemingly honest Bob creates a valid root claim C and game Q.
4. Evil Alice attacks C with claim B(valid, same hash as step 2) in game Q.
5. Honest Coco defends B with claim D in game Q.
Alice and Bob are friends actually and they use another smart contract to interact with the factory and game. At the end of step 1 and 3, A,P and C,Q are stored in the contract, and in step 2 and 4, the contract executes P.move(A,...)and Q.move(C,...). Coco simply uses an eoa at step 5.

Then reorg happens, transaction order becomes 34125. The address of game P and Q are swapped (since the deployed address is derived from sender and nonce). Now it will look like

1. Seemingly honest Bob creates a valid root claim C and game Q.
2. Evil Alice attacks C with claim B(valid, same hash with step 4) in game Q.
3. Evil Alice creates a invalid root claim A and game P.
4. Seemingly honest Bob attacks A with claim B in game P.
5. Honest Coco defends B with claim D in game QP.
Alice and Bob are still in their desired game but Coco will be in a wrong game. As a result, her bond will be lost.

```
proxy_ = IDisputeGame(address(impl).clone(abi.encodePacked(msg.sender, _rootClaim, parentHash, _extraData)));
......
instance := create(value, add(m, add(0x0b, lt(n, 0xffd3))), add(n, 0x37))
```
Suppose create2 is used to address the previous scenario, but within the same game, reorg could still impact the honest party. Consider the following scenario.
1. Evil Alice creates an invalid root claim A.
2. Honest Coco attacks A with claim B.
3. Evil Alice attacks A with an invalid claim X.
4. Evil Alice attacks B with the valid claim C.
5. Honest Coco defends C(the claim created in step 4) with claim D.
6. Evil Alice attacks A with an invalid claim E.
7. Evil Alice attacks E with the valid claim C (same hash as step 4).
Now reorg happens again, new transaction order is 1267534. Alice uses the previously mentioned contract call trick(store claim and index this time) so that her txs do not revert. Then at step 5, Coco's tx will succeed since disputed hash is the same. But her defend will now imply C and E are both valid, so she'll lose her bond again.

Chain reorgs are very prevalent in Ethereum mainnet, we can check this index of reorged blocks on etherscan.

## Recommended Mitigation Steps
1. Use cloneDeterministic instead.
claimHash(child) = keccak256(claim(child), position(child), claimHash(parent));
2. Then check claimHash is indeed the expected one.



## [M-03]  If the clock has more than CLOCK_EXTENSION but less than CLOCK_EXTENSION * 2 seconds remaining, no time will be allocated.
## Vulnerability details
### Impact
### Proof of Concept
> If the potential grandchild is an execution trace bisection root claim and their clock has less than CLOCK_EXTENSION seconds remaining, exactly CLOCK_EXTENSION * 2 seconds are allocated for the potential grandchild. This extra time is alloted to allow for completion of the off-chain FPVM run to generate the initial instruction trace.


However, if the clock has more than CLOCK_EXTENSION but less than CLOCK_EXTENSION * 2 seconds remaining, no time will be allocated. So CLOCK_EXTENSION * 2 seconds cannot always be guaranteed for off-chain trace generation.
```
    if (nextDuration.raw() > MAX_CLOCK_DURATION.raw() - CLOCK_EXTENSION.raw()) {
        // If the potential grandchild is an execution trace bisection root, double the clock extension.
        uint64 extensionPeriod =
            nextPositionDepth == SPLIT_DEPTH - 1 ? CLOCK_EXTENSION.raw() * 2 : CLOCK_EXTENSION.raw();
        nextDuration = Duration.wrap(MAX_CLOCK_DURATION.raw() - extensionPeriod);
    }
```