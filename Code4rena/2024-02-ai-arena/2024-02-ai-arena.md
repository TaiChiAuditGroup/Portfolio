| Severity | Title |
| -------- | -------- | 
|H-01 |non-transferable token can be transfer|
|H-02 |FighterFarm::_ableToTransfer check can be bypassed since safeTransferFrom (with 4 args) is not implemented|
|H-03 |In FighterFarm::claimFighters, The order of fighterTypes is not guaranteed.|
|H-04 |ReRoll can use different fighter type to create unmatched FighterBase and PhysicalAttributes|
|H-05 |numElements is never set for generation larger than 0, causing DoS for _createFighterBase|
|M-01 |Potential DoS in claimRewards()|
|M-02 |The setups of privileged roles for multi-contracts are uni-lateral and can not be revoked.|
|M-03 |If an NFT is transferred with funds at-risk, all subsequent updateBattleRecord call in this round will cause unintended behavior |
|L-01 |Lack of access control|
|L-02 |Potential Voltage loss|
|L-03 |URI returns false data.|
|L-04 |Use transferFrom may loss NFT|
|L-05 |Precision loss|
|L-06 |Building on L2 is vulnerable to Re-org attack|

## [H-01]  non-transferable token can be transfer

## Vulnerability details
### Impact
In GameItem.sol safeTransferFrom() use
```
require(allGameItemAttributes[tokenId].transferable)
```
make sure that non-transferable cannot be transfer.
use safeBatchTransferFrom can bypass this check.

### Proof of Concept
https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/GameItems.sol#L291


## [H-02] 

## Vulnerability details
### Impact
In the `FighterFarm` contract, the `_ableToTransfer` function is used to guarantee that
the user's hero amount should not exceed `MAX_FIGHTERS_ALLOWED` and the transferred
hero should not be in `STAKED` status. However, the contract `FighterFarm` inherits
`ERC721`, but doesn't implement all its `safeTransferFrom` methods. As a result, the initial
check could be bypassed using `function safeTransferFrom(address, address, uint256, bytes memory)`,
and the user's hero amount can exceed `MAX_FIGHTERS_ALLOWED` and staked hero can also be transferred.


### Proof of Concept
The ```FighterFarm``` contract inherits ```ERC721``` to manage the creation, ownership, and redemption of AI Arena Fighter NFTs.
```
contract FighterFarm is ERC721, ERC721Enumerable {
     ...
}
```
The [_ableToTransfer](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L539-L546) function is used to guarantee that the user's hero amount should not exceed ```MAX_FIGHTERS_ALLOWED``` and the transferred hero should not be in STAKED status. Hence, the contract could work normally.
```
    function _ableToTransfer(uint256 tokenId, address to) private view returns(bool) {
        return (
          _isApprovedOrOwner(msg.sender, tokenId) &&
          balanceOf(to) < MAX_FIGHTERS_ALLOWED &&
          !fighterStaked[tokenId]
        );
    }
```
The function _ableToTransfer is used in [transferFrom(address, address, uint256)](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L346) and [safeTransferFrom(address, address, uint256)](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L363).
```
    function transferFrom(
        address from, 
        address to, 
        uint256 tokenId
    ) 
        public 
        override(ERC721, IERC721) 
    { // @audit could still get locked?
        require(_ableToTransfer(tokenId, to));
        _transfer(from, to, tokenId);
    }
```
```
    function safeTransferFrom(
        address from, 
        address to, 
        uint256 tokenId
    ) 
        public 
        override(ERC721, IERC721)
    {
        require(_ableToTransfer(tokenId, to));
        _safeTransfer(from, to, tokenId, "");
    }
```
However, the base function [ERC721::safeTransferFrom(address, address, uint256, bytes memory)](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ecd2ca2cd7cac116f7a37d0e474bbb3d7d5e1c4d/contracts/token/ERC721/ERC721.sol#L175-L183) is not implemented by the inherited FighterFarm contract. Thus the check could be bypassed.
```
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner nor approved");
        _safeTransfer(from, to, tokenId, data);
    }
```

As a result, the user's hero amount can exceed MAX_FIGHTERS_ALLOWED and the staked hero can also be transferred.

The PoC is shown below (in ```FighterFarm.t.sol```):
```
    function testTransferringWithDataToBypassCheck() public {
        _mintFromMergingPool(_ownerAddress);
        _fighterFarmContract.addStaker(_ownerAddress);
        _fighterFarmContract.updateFighterStaking(0, true);
        assertEq(_fighterFarmContract.fighterStaked(0), true);
        // check that i'm unable to transfer since i staked
        emit log_string("try using transferFrom with check");
        vm.expectRevert();
        _fighterFarmContract.transferFrom(_ownerAddress, _DELEGATED_ADDRESS, 0);
        assertEq(_fighterFarmContract.ownerOf(0) != _DELEGATED_ADDRESS, true);
        assertEq(_fighterFarmContract.ownerOf(0), _ownerAddress);
        emit log_named_address("the token 0 owner using transferFrom", _fighterFarmContract.ownerOf(0));

        // check that i'm unable to transfer since i staked
        emit log_string("try using safeTransferFrom with check");
        vm.expectRevert();
        _fighterFarmContract.safeTransferFrom(_ownerAddress, _DELEGATED_ADDRESS, 0);
        assertEq(_fighterFarmContract.ownerOf(0) != _DELEGATED_ADDRESS, true);
        assertEq(_fighterFarmContract.ownerOf(0), _ownerAddress);
        emit log_named_address("the token 0 owner using safeTransferFrom(3 args)", _fighterFarmContract.ownerOf(0));

        // check that i could bypass the check to transfer after staking
        emit log_string("try using safeTransferFrom without check");
        _fighterFarmContract.safeTransferFrom(_ownerAddress, _DELEGATED_ADDRESS, 0, "");
        assertEq(_fighterFarmContract.ownerOf(0), _DELEGATED_ADDRESS);
        emit log_named_address("the token 0 owner using safeTransferFrom(4 args)", _fighterFarmContract.ownerOf(0));
    }
```

The log is shown below:
```
[PASS] testTransferringWithDataToBypassCheck() (gas: 524412)
Logs:
  try using transferFrom with check
  the token 0 owner using transferFrom: 0x90193C961A926261B756D1E5bb255e67ff9498A1
  try using safeTransferFrom with check
  the token 0 owner using safeTransferFrom(3 args): 0x90193C961A926261B756D1E5bb255e67ff9498A1
  try using safeTransferFrom without check
  the token 0 owner using safeTransferFrom(4 args): 0x22F4441ad6DbD602dFdE5Cd8A38F6CAdE68860b0
```
## Recommended Mitigation Steps
Implement function ```safeTransferFrom(address, address, uint256, bytes memory)``` by adding ```_ableToTransfer``` in the function.

## [H-03]  In FighterFarm::claimFighters, The order of fighterTypes is not guaranteed.

## Vulnerability details
### Impact
In FighterFarm::claimFighters, the ```fighterTypes ```is not taken from user input, but is pre-assumed that they are in the order like ```0,0,0,1,1,1```. However, this is not guaranteed, if a user doesn't input as pre-assumed, this would cause a mismatch between other params(like modelHashes, modelTypes) and fighterTypes.


### Proof of Concept
In [FighterFarm::claimFighters](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L212-L220), the fighterTypes is not taken from user input. Instead, i < numToMint[0] ? 0 : 1 is used to decide the types.
```
            _createNewFighter(
                msg.sender, 
                uint256(keccak256(abi.encode(msg.sender, fighters.length))),
                modelHashes[i], 
                modelTypes[i],
                i < numToMint[0] ? 0 : 1,
                0,
                [uint256(100), uint256(100)]
            );
```
This shows that the function preassumes that fighterTypes are in the order like 0,0,0,1,1,1(type 0 always occurs before 1), however, this is never guaranteed. If a user doesn't input as pre-assumed, this would cause a mismatch between other params(like modelHashes, modelTypes) and fighterTypes.

In the function [redeemMintPass](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L235), fighterTypes is used as input param, so that there will be no mismatch.



## Recommended Mitigation Steps
Add parms uint8[] calldata fighterTypes just like function redeemMintPass.


## [H-04]  ReRoll can use different fighter type to create unmatched FighterBase and PhysicalAttributes

## Vulnerability details
In function reRoll,it can use any fighter type to rello.If user choose the fighter type which is different original dendroidBool in fighter token, it will use this fight type create fighter base,and use dendroidBool to create physical attributes,create an unmatched attributes.
### Impact
all fighter token can rello，and may effect battle of fighter
### Proof of Concept
In reRoll function：

https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L380
```
    function reRoll(uint8 tokenId, uint8 fighterType) public {
        require(msg.sender == ownerOf(tokenId));
        require(numRerolls[tokenId] < maxRerollsAllowed[fighterType]);
        require(_neuronInstance.balanceOf(msg.sender) >= rerollCost, "Not enough NRN for reroll");

        _neuronInstance.approveSpender(msg.sender, rerollCost);
        bool success = _neuronInstance.transferFrom(msg.sender, treasuryAddress, rerollCost);
        if (success) {
            numRerolls[tokenId] += 1;
            uint256 dna = uint256(keccak256(abi.encode(msg.sender, tokenId, numRerolls[tokenId])));
            (uint256 element, uint256 weight, uint256 newDna) = _createFighterBase(dna, fighterType);
            fighters[tokenId].element = element;
            fighters[tokenId].weight = weight;
            fighters[tokenId].physicalAttributes = _aiArenaHelperInstance.createPhysicalAttributes(
                newDna,
                generation[fighterType],
                fighters[tokenId].iconsType,
                fighters[tokenId].dendroidBool
            );
            _tokenURIs[tokenId] = "";
        }
    }    
```
it use fighter type to create fighter base:

https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L380

```
            (uint256 element, uint256 weight, uint256 newDna) = _createFighterBase(dna, fighterType);
```
and use dendroidBool to create physical attributes:
```
            fighters[tokenId].physicalAttributes = _aiArenaHelperInstance.createPhysicalAttributes(
                newDna,
                generation[fighterType],
                fighters[tokenId].iconsType,
                fighters[tokenId].dendroidBool
            );
```
fighter type is match dendroidBool when create fighter:

https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L509
```
 function _createNewFighter(
        address to, 
        uint256 dna, 
        string memory modelHash,
        string memory modelType, 
        uint8 fighterType,
        uint8 iconsType,
        uint256[2] memory customAttributes
    ) 
        private 
    {  
        require(balanceOf(to) < MAX_FIGHTERS_ALLOWED);
        uint256 element; 
        uint256 weight;
        uint256 newDna;
        if (customAttributes[0] == 100) {
            (element, weight, newDna) = _createFighterBase(dna, fighterType);
        }
        else {
            element = customAttributes[0];
            weight = customAttributes[1];
            newDna = dna;
        }
        uint256 newId = fighters.length;

        bool dendroidBool = fighterType == 1;
        FighterOps.FighterPhysicalAttributes memory attrs = _aiArenaHelperInstance.createPhysicalAttributes(
            newDna,
            generation[fighterType],
            iconsType,
            dendroidBool
        );
        fighters.push(
            FighterOps.Fighter(
                weight,
                element,
                attrs,
                newId,
                modelHash,
                modelType,
                generation[fighterType],
                iconsType,
                dendroidBool
            )
        );
        _safeMint(to, newId);
        FighterOps.fighterCreatedEmitter(newId, weight, element, generation[fighterType]);
    }
```
and ```bool dendroidBool = fighterType == 1;```

so use unmatched fighter type will cause reroll fighter element and weight don't match physical attributes，it will affect the fighters' battle and some ability.
## Recommended Mitigation Steps
make fighter type matchs dendroidBool in ReRoll.

## [H-05]  numElements is never set for generation larger than 0, causing DoS for _createFighterBase

## Vulnerability details
### Impact
In the contract FighterFarm, the mapping numElements is never set for generation > 0, causing permanent DoS in function _createFighterBase after the generation is upgraded.
### Proof of Concept
The mapping numElements appears only 3 times in the contract FighterFarm, in [definition](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L84-L85), [constructor](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L110) and [_createFighterBase](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L462-L474)

```
    /// @notice Mapping of number elements by generation.
    mapping(uint8 => uint8) public numElements; // <= appearance
```

```
    constructor(address ownerAddress, address delegatedAddress, address treasuryAddress_)
        ERC721("AI Arena Fighter", "FTR")
    {
        _ownerAddress = ownerAddress;
        _delegatedAddress = delegatedAddress;
        treasuryAddress = treasuryAddress_;
        numElements[0] = 3; // <= appearance
    } 
```

```
    function _createFighterBase(
        uint256 dna, 
        uint8 fighterType
    ) 
        private 
        view 
        returns (uint256, uint256, uint256) 
    {
        uint256 element = dna % numElements[generation[fighterType]]; // <= appearance
        uint256 weight = dna % 31 + 65;
        uint256 newDna = fighterType == 0 ? dna : uint256(fighterType);
        return (element, weight, newDna);
    }
```

The numElements is never set for generation > 0, which will cause permanent DoS in function _createFighterBase after the generation is upgraded due to division or modulo by zero  error.

The PoC is shown below (in FighterFarm.t.sol):
```
    function testIncrementGenerationAndRevertWhenCreating() public {
        _fighterFarmContract.incrementGeneration(1);
        _fighterFarmContract.incrementGeneration(0);
        assertEq(_fighterFarmContract.generation(1), 1);
        assertEq(_fighterFarmContract.generation(0), 1);

        uint8[2] memory numToMint = [1, 0];
        bytes memory claimSignature = abi.encodePacked(
            hex"407c44926b6805cf9755a88022102a9cb21cde80a210bc3ad1db2880f6ea16fa4e1363e7817d5d87e4e64ba29d59aedfb64524620e2180f41ff82ca9edf942d01c"
        );
        string[] memory claimModelHashes = new string[](1);
        claimModelHashes[0] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";

        string[] memory claimModelTypes = new string[](1);
        claimModelTypes[0] = "original";

        // Expect a revert
        vm.expectRevert();
        _fighterFarmContract.claimFighters(numToMint, claimSignature, claimModelHashes, claimModelTypes);   
    }    
```
The log is shown below:
```
[PASS] testIncrementGenerationAndRevertWhenCreating() (gas: 93364)
Traces:
    ...
    ├─ [46343] FighterFarm::claimFighters([1, 0], 0x407c44926b6805cf9755a88022102a9cb21cde80a210bc3ad1db2880f6ea16fa4e1363e7817d5d87e4e64ba29d59aedfb64524620e2180f41ff82ca9edf942d01c, ["ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m"], ["original"])
    │   ├─ [4574] Verification::verify(0x25820a63f06e1e0f1084b9ab80ecbc8c9659397472c0fea95a08a93019aa3586, 0x407c44926b6805cf9755a88022102a9cb21cde80a210bc3ad1db2880f6ea16fa4e1363e7817d5d87e4e64ba29d59aedfb64524620e2180f41ff82ca9edf942d01c, 0x22F4441ad6DbD602dFdE5Cd8A38F6CAdE68860b0) [delegatecall]
    │   │   ├─ [3000] PRECOMPILES::ecrecover(0xfd8716f5403181916d3702b50af2e697692bec1db02b71fb540c50728810e1ef, 28, 29167584611576571339878995233636422018945121535272023715362727324106082621178, 35314661797998437913913732547377583040930425685770092457433811664373280228048) [staticcall]
    │   │   │   └─ ← 0x00000000000000000000000022f4441ad6dbd602dfde5cd8a38f6cade68860b0
    │   │   └─ ← true
    │   └─ ← panic: division or modulo by zero (0x12)
    └─ ← ()
```
## Recommended Mitigation Steps
When FighterFarm::incrementGeneration is being called, numElements for this generation should be set, like
```
    function incrementGeneration(uint8 fighterType) external returns (uint8) {
        ...
        generation[fighterType] += 1;
        ...
        numElements[generation[fighterType]] = ...; // <= initialize numElements[generation[fighterType]]
        ...
    }
```

## [M-01]  Potential DoS in claimRewards()

## Vulnerability details
### Impact
There are two scenarios here that could lead to a permanent DoS.

1. Player win more than ten rounds.
Consider this scenario:
If a player has never claimed rewards and several rounds have passed, and the player has won more than ten rounds.
claimRewards -> mintFromMergingPool -> _createNewFighter
in _createNewFighter there is a check
```require(balanceOf(to) < MAX_FIGHTERS_ALLOWED);```
MAX_FIGHTERS_ALLOWED is 10, this will always revert and lead to a permanent DoS.

2. unbounded for-loop
claimRewards() allows the user to batch claim rewards for multiple rounds.
There is a similar issue in the [bot race report](https://github.com/code-423n4/2024-02-ai-arena/blob/main/bot-report.md#l-05), but miss this one.
If a player has never claimed rewards and several rounds have passed, the roundID value become very large.
When the player attempts to claim rewards and [currentRound](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/MergingPool.sol#L148) now is 0, and entering a for loop, it may result in a permanent DoS where the player is unable to claim rewards.

### Proof of Concept
https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/MergingPool.sol#L149

## Recommended Mitigation Steps
Better approach is to allow players to choose a specifying range of roundIDs in the claimRewards() to batch claim rewards.


## [M-02]  The setups of privileged roles for multi-contracts are uni-lateral and can not be revoked.

## Vulnerability details
### Impact
Some privileged roles in some contracts(Neuron, GameItems, FighterFarm) are set up by the admin or owner. However, the setup is unilateral and can not be revoked, which means that after an address is granted with the role, there's no way to revoke it. This could lead to security issues when the role is mistakenly set by the admin or is compromised.
### Proof of Concept
#### Neuron contract
The privileged roles in the Neuron contract are MINTER_ROLE, SPENDER_ROLE, and STAKER_ROLE. All these roles are set via the addX function like below:
```
    function addMinter(address newMinterAddress) external {
        require(msg.sender == _ownerAddress);
        _setupRole(MINTER_ROLE, newMinterAddress);
    }
```
It's clear that _setupRole is inherited from AccessControl.
```
    function _setupRole(bytes32 role, address account) internal virtual {
        _grantRole(role, account);
    }
```
However, _revokeRole is never called in Neuron. And manually calling AccessControl::revokeRole will revert since RoleData.adminRole is never set. This could lead to security issues when the role is mistakenly set by the admin or is compromised.

We have the PoC here(in ```Neuron.t.sol```).
```
    function testGetRoleAdmin() public { 
        _neuronContract.addMinter(_DELEGATED_ADDRESS);
        assertEq(_neuronContract.hasRole(keccak256("MINTER_ROLE"), _DELEGATED_ADDRESS), true);
        emit log_named_bytes32("admin role of MINTER_ROLE", _neuronContract.getRoleAdmin(keccak256("MINTER_ROLE")));
        vm.expectRevert();
        _neuronContract.revokeRole(keccak256("MINTER_ROLE"), _DELEGATED_ADDRESS);
    }
```
Log:
```
Logs:
  admin role of MINTER_ROLE: 0x0000000000000000000000000000000000000000000000000000000000000000

revert with revert: AccessControl: account 0x7fa9385be102ac3eac297483dd6233d62b3e1496 is missing role 0x0000000000000000000000000000000000000000000000000000000000000000
```
#### GameItems contract
In the GameItem contract, allowedBurningAddresses is used as the privileged role.

```    mapping(address => bool) public allowedBurningAddresses;```
And the role is set via setAllowedBurningAddresses, but it's always set to true.
```
    function setAllowedBurningAddresses(address newBurningAddress) public {
        require(isAdmin[msg.sender]);
        allowedBurningAddresses[newBurningAddress] = true; // @audit can only set to true
    }
```
In the contract, the allowedBurningAddresses[newBurningAddress] can not be reset to false since this is unilateral. This could lead to security issues when the role is mistakenly set by the admin or is compromised.

FighterFarm contract
In the FighterFarm contract, the Staker role can only be added via addStaker but nowhere to be revoked.
```
    function addStaker(address newStaker) external {
        require(msg.sender == _ownerAddress);
        hasStakerRole[newStaker] = true;
    }
```
This could lead to security issues when the role is mistakenly set by the admin or is compromised.

## Recommended Mitigation Steps
Add functions to be able to revoke the role previously granted, or change the current function, so that an address can either be granted with the role or revoked.

## [M-03]  If an NFT is transferred with funds at-risk, all subsequent updateBattleRecord call in this round will cause unintended behavior
## Vulnerability details
### Impact
If an NFT is transferred during the round with NRN tokens at risk (meaning the previous owner has lost the game), any subsequent updateBattleRecord call for this NFT in this round will cause unintended behavior, including:

1. If the new owner hasn't staked any NRN before, or he is not at a certain loss in StakeAtRisk::amountLost[fighterOwner], any updateBattleRecord call will revert if the NFT wins the battle due to arithmetic underflow or overflow.
2. If the new owner is at a certain loss in StakeAtRisk::amountLost[fighterOwner], he can earn some at-risk-stake of the previous owner without any penalty in this round.
This impact will last for the whole round, approximately 2 weeks.
### Proof of Concept
Imagine the following scenario:

1. The previous owner, let's say A, has staked some NRN to get rewards. Since has lost a battle, he will have some NRN transferred to StakeAtRisk contract, and the stakeAtRisk[round][fighterId] will increase in [updateAtRiskRecords](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/StakeAtRisk.sol#L115-L127)
```

    function updateAtRiskRecords(
        uint256 nrnToPlaceAtRisk, 
        uint256 fighterId, 
        address fighterOwner
    ) 
        external 
    {
        require(msg.sender == _rankedBattleAddress, "Call must be from RankedBattle contract");
        stakeAtRisk[roundId][fighterId] += nrnToPlaceAtRisk;
        totalStakeAtRisk[roundId] += nrnToPlaceAtRisk;
        amountLost[fighterOwner] += nrnToPlaceAtRisk;
        emit IncreasedStakeAtRisk(fighterId, nrnToPlaceAtRisk);
    }   
```

2. User A doesn't want to proceed with the game and decides to quit. So, he [unstakeNRN](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/RankedBattle.sol#L270-L290) and gets his NFT unlocked.
```
    function unstakeNRN(uint256 amount, uint256 tokenId) external {
        ...
        if (success) {
            if (amountStaked[tokenId] == 0) {
                _fighterFarmInstance.updateFighterStaking(tokenId, false); // unlock here
            }
            emit Unstaked(msg.sender, amount);
        }
    }
```
3. Since the NFT is in unlocked states, the [FighterFarm::_ableToTransfer](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/FighterFarm.sol#L539-L545) check is bypassed. user A transfers the NFT to user B who will continue to play in this round.
```
    function _ableToTransfer(uint256 tokenId, address to) private view returns(bool) {
        return (
          _isApprovedOrOwner(msg.sender, tokenId) &&
          balanceOf(to) < MAX_FIGHTERS_ALLOWED &&
          !fighterStaked[tokenId]
        );
    }
```
4. For user B, he can't stake NRN for the NFT in the current round since unstake has been called for this NFT. However, when updateBattleRecord is being called, _addResultPoints will still be called since _stakeAtRiskInstance.getStakeAtRisk(tokenId) is non-zero.
```
    function updateBattleRecord(
        uint256 tokenId, 
        uint256 mergingPortion,
        uint8 battleResult,
        uint256 eloFactor,
        bool initiatorBool
    ) 
        external 
    {   
        ...
        uint256 stakeAtRisk = _stakeAtRiskInstance.getStakeAtRisk(tokenId); // <= non-zero for stakeAtRisk[round][fighterId]
        if (amountStaked[tokenId] + stakeAtRisk > 0) {
            _addResultPoints(battleResult, tokenId, eloFactor, mergingPortion, fighterOwner);
        }
        ...
    }
```
5. In [_addResultPoints](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/RankedBattle.sol#L416), since amountStaked[tokenId] = 0, there will be no penalty for user B when the match is lost since B has nothing to lose.

But if the NFT wins the battle, something unexpected will occur. Since stakeAtRisk is non-zero, curStakeAtRisk will be greater than 0, thus _stakeAtRiskInstance.reclaimNRN(curStakeAtRisk, tokenId, fighterOwner); will be called.
```
    function _addResultPoints(...) {
        ...
        stakeAtRisk = _stakeAtRiskInstance.getStakeAtRisk(tokenId);
        ...
        curStakeAtRisk = (bpsLostPerLoss * (amountStaked[tokenId] + stakeAtRisk)) / 10**4;
        ...
        if (curStakeAtRisk > 0) {
            _stakeAtRiskInstance.reclaimNRN(curStakeAtRisk, tokenId, fighterOwner);
            amountStaked[tokenId] += curStakeAtRisk;
        }
    }
```
6. In [StakeAtRisk::reclaimNRN](https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/StakeAtRisk.sol#L93-L107), amountLost[fighterOwner] will be updated for user B.
 ```       
 bool success = _neuronInstance.transfer(_rankedBattleAddress, nrnToReclaim);
        if (success) {
            stakeAtRisk[roundId][fighterId] -= nrnToReclaim;
            totalStakeAtRisk[roundId] -= nrnToReclaim;
            amountLost[fighterOwner] -= nrnToReclaim;
            emit ReclaimedStake(fighterId, nrnToReclaim);
        }
```
- If amountLost[address( User B)] is zero or is less than nrnToReclaim, meaning he hasn't staked any NRN before, or he has not reached a certain loss, the transaction would revert due to arithmetic underflow or overflow.
- If amountLost[address( User B)] is greater than nrnToReclaim, meaning user B is at a certain loss in previous battles(with other NFTs), he could earn some at-risk-stake of the user A without any penalty in this round.
The PoC for the first case (in ```RankedBattle.t.sol)```:
```
    function testRevertAfterTransferAtRisk() public {
        address oldPlayer = vm.addr(3);
        address newPlayer = vm.addr(4);

        _mintFromMergingPool(oldPlayer);

        _fundUserWith4kNeuronByTreasury(oldPlayer);

        vm.prank(oldPlayer);
        _rankedBattleContract.stakeNRN(4000 * 10 ** 18, 0);

        emit log_named_uint("NRN in _rankedBattleContract" , _neuronContract.balanceOf(address(_rankedBattleContract)) / 1 ether);


        // assertEq(_rankedBattleContract.amountStaked(0), 3_000 * 10 ** 18);
        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(0, 50, 2, 1500, true); // lose 1 game

        emit log_named_uint("oldPlayer staked NRN in _rankedBattleContract" , _rankedBattleContract.amountStaked(0) / 1 ether);
        emit log_named_uint("NRN in _rankedBattleContract" , _neuronContract.balanceOf(address(_rankedBattleContract)) / 1 ether);

        vm.startPrank(oldPlayer);
        _rankedBattleContract.unstakeNRN(_rankedBattleContract.amountStaked(0),0);
        emit log_named_string("after unstaking, token0's lock status", _fighterFarmContract.fighterStaked(0)?"locked":"unlocked");

        _fighterFarmContract.transferFrom(oldPlayer,newPlayer,0);
        vm.stopPrank();

        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(0, 50, 2, 1500, true); // lose 1 game
        emit log_string("new player can lose in game");
        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(0, 50, 1, 1500, true); // tie 1 game
        emit log_string("new player can tie in game");        
        vm.prank(address(_GAME_SERVER_ADDRESS));
        vm.expectRevert(); // <= would revert here!!
        _rankedBattleContract.updateBattleRecord(0, 50, 0, 1500, true); // win 1 game
        emit log_string("new player can not win in game");        
    }
```
The result log for the first case:
```
[PASS] testRevertAfterTransferAtRisk() (gas: 992146)
Logs:
  NRN in _rankedBattleContract: 4000
  oldPlayer staked NRN in _rankedBattleContract: 3996
  NRN in _rankedBattleContract: 3996
  after unstaking, token0's lock status: unlocked
  new player can lose in game
  new player can tie in game
  new player can not win in game
```
The PoC for the second case (in RankedBattle.t.sol):
```
    function testNewOwnerTakeStakeAtRiskFromPrevious() public {
        address oldPlayer = vm.addr(3);
        address newPlayer = vm.addr(4);

        _mintFromMergingPool(oldPlayer);
        _mintFromMergingPool(newPlayer);

        vm.prank(_treasuryAddress);
        _neuronContract.transfer(oldPlayer, 4000000 * 10 ** 18);

        _fundUserWith4kNeuronByTreasury(newPlayer);

        vm.prank(oldPlayer);
        _rankedBattleContract.stakeNRN(4000000 * 10 ** 18, 0);
        vm.prank(newPlayer);
        _rankedBattleContract.stakeNRN(4000 * 10 ** 18, 1);

        emit log_named_uint("NRN in _rankedBattleContract" , _neuronContract.balanceOf(address(_rankedBattleContract)) / 1 ether);


        // assertEq(_rankedBattleContract.amountStaked(0), 3_000 * 10 ** 18);
        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(0, 50, 2, 1500, true); // lose 1 game for oldowner

        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(1, 50, 2, 1500, true); // lose 1 game for newOwner

        emit log_named_uint("oldPlayer staked NRN in _rankedBattleContract" , _rankedBattleContract.amountStaked(0) / 1 ether);
        emit log_named_uint("NRN in _rankedBattleContract" , _neuronContract.balanceOf(address(_rankedBattleContract)) / 1 ether);

        vm.startPrank(oldPlayer);
        _rankedBattleContract.unstakeNRN(_rankedBattleContract.amountStaked(0),0);
        emit log_named_string("after unstaking, token0's lock status", _fighterFarmContract.fighterStaked(0)?"locked":"unlocked");

        _fighterFarmContract.transferFrom(oldPlayer,newPlayer,0);
        vm.stopPrank();

        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(0, 50, 2, 1500, true); // lose 1 game
        emit log_string("new player can lose in game");
        vm.prank(address(_GAME_SERVER_ADDRESS));
        _rankedBattleContract.updateBattleRecord(0, 50, 1, 1500, true); // tie 1 game
        emit log_string("new player can tie in game");        
        vm.prank(address(_GAME_SERVER_ADDRESS));
        // vm.expectRevert();
        _rankedBattleContract.updateBattleRecord(0, 50, 0, 1500, true); // win 1 game
        emit log_string("new player can win in game");
        emit log_named_uint("after win, stake amount of new player in nft 0 is added to", _rankedBattleContract.amountStaked(0) / 1 ether);
    }
```
The result log is shown below:

```
[PASS] testNewOwnerTakeStakeAtRiskFromPrevious() (gas: 1618024)
Logs:
  NRN in _rankedBattleContract: 4004000
  oldPlayer staked NRN in _rankedBattleContract: 3996000
  NRN in _rankedBattleContract: 3999996
  after unstaking, token0's lock status: unlocked
  new player can lose in game
  new player can tie in game
  new player can win in game
  after win, stake amount of new player in nft 0 is added to: 4
```
This impact will last for the whole round, approximately 2 weeks.


## Recommended Mitigation Steps
1. In StateAtRisk, add a cap-check before token transfer in reclaimNRN, so that the transaction will not revert.
```if (amountLost[fighterOwner] < nrnToReclaim) {
    // return or make nrnToReclaim = amountLost[fighterOwner];
}
```
2. For the second case, since curStakeAtRisk = (bpsLostPerLoss * (amountStaked[tokenId] + stakeAtRisk)) / 10**4;, when bpsLostPerLoss = 10, it requires approximately 10^6 initial token staking by user A for user B to get 1 NRN token from user A's stake-at-risk. So it won't be a big deal. A possible way to mitigate this is to record the fighterOwner of an NFT in its first battle of the round so that when fighterOwner has changed, there will be no rewards for the new owners.


## [L-01] Lack of access control

fighterCreatedEmitter() is public, allowing anyone to arbitrarily modify the data storing the new Fighter NFT.

https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/FighterOps.sol#L53
```
   /// @notice Emits a FighterCreated event.
    function fighterCreatedEmitter(
        uint256 id,
        uint256 weight,
        uint256 element,
        uint8 generation
    ) 
        public 
    {
        emit FighterCreated(id, weight, element, generation);
    }
```


## [L-02] Potential Voltage loss
There are some senarios:
1. Users can replenish Voltage every day, but _replenishVoltage is executed within spendVoltage().
 The spendVoltage() function takes the voltageSpent parameter as input. 
Users who only want to replenish Voltage but lack of awareness or accidental input of voltageSpent will lose Voltage.

https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/VoltageManager.sol#L110
```
ownerVoltage[spender] -= voltageSpent;
```
It is recommended to separate replenishVoltage into a standalone function.

2. The useVoltageBattery() only checks if the user's voltage is less than 100. Users with non-zero voltage will lose their remaining Voltage.

https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/VoltageManager.sol#L94
```
require(ownerVoltage[msg.sender] < 100);
```

## [L-03] URI returns false data.

The owner can add admin access for a user through adjustAdminAccess().
Multiple users may have admin access.
setTokenURI() and createGameItem() are called by a user with admin access.
After createGameItem(), other users with admin access can freely modify the tokenURI using setTokenURI.

https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/GameItems.sol#L194
```
function setTokenURI(uint256 tokenId, string memory _tokenURI) public {
        require(isAdmin[msg.sender]);
        _tokenURIs[tokenId] = _tokenURI;
    }
```
The value of the NFTs depends on their metadata which includes critical information such as traits, rarity, images, etc.
Additionally, they can freely set non-existent tokenID and _tokenURI.
Bypass the check for uri() 
```if (bytes(customURI).length > 0)```.
Return non-existing tokenID along with its fake metadata.
This may mislead users. 

## [L-04] Use transferFrom may loss NFT

When using the transferFrom function of an ERC721 contract to send an NFT, if the receiving address is a smart contract and does not support ERC721, the NFT can be permanently lost.

https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/FighterFarm.sol#L338
```
 function transferFrom(
        address from, 
        address to, 
        uint256 tokenId
    ) 
        public 
        override(ERC721, IERC721)
    {
        require(_ableToTransfer(tokenId, to));
        _transfer(from, to, tokenId);
    }
```
Recommendation:
Ensure receiving contract have  onERC721Received method.


## [L-05] Precision  loss
bpsLostPerLoss is [adjusted by the msg.sender](https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/RankedBattle.sol#L226) with isAdmin role, and there are no upper or lower limits.
When calculating curStakeAtRisk, possible precision loss.

https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/RankedBattle.sol#L439
```
curStakeAtRisk = (bpsLostPerLoss * (amountStaked[tokenId] + stakeAtRisk)) / 10**4;
```
Causing users unable to [reclaim](https://github.com/code-423n4/2024-02-ai-arena/blob/main/src/RankedBattle.sol#L461) stake-at-risk puts the NRN back into their staking pool.

## [L-06] Building on L2 is vulnerable to Re-org attack
The project is designed to work on the ARB mainnet. However, for these L2 network, a reorg attack is possible and the duration could last several minutes. Thus the project may suffer from a re-org attack, causing DOS or wrong rewards in fights.


The project is designed to work on the ARB mainnet. However, for these L2 network, a reorg attack is possible and the duration could last several minutes. Thus the project may suffer from a re-org attack, causing DOS or wrong rewards in fights.

https://github.com/code-423n4/2024-02-ai-arena/blob/cd1a0e6d1b40168657d1aaee8223dc050e15f8cc/src/RankedBattle.sol#L16

Consider the following scenario:

1. A user wins the game, and his record is updated.
2. The re-org attack occurs, a user could stake right before the game updates, thus he can get quite a lot of points.

Recommend to increase confirmation times on DAPPs.