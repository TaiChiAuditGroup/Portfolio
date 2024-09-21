| Severity | Title |
| -------- | -------- | 
|H-01 |mintWithBudget will only works for the first maxTokensPerGen|
|H-02 |Accounting Issues Due to Generation Reset in _incrementGeneration |
|M-01 |The 999999 Constraint Can Not be Guaranteed|
|M-02 |Incorrect mintPrice When maxTokensPerGen Is Reached|
|M-03 |There is No Pause/Unpause Function to Change the State|
|M-04 |forgePotential check is incorrect in listForForging|
|M-05 |No Slippage Control in nuke|
|L-01 | Changing Centralized Parameters Half-way Could Cause Issues |
|L-02 | Whitelist Users Could Participate More Than Once |
|L-03 |  the usage of `amountMinted` is redundant     |
|L-04 | The `>=` check for `generationMintCounts` could be simplified   |
|L-05 | Self-transfer of `TraitForgeNft` Could Clear Listing Info         |
|L-06 | Inconsistent Usage of `pause()` and `whenNotPaused` in `TraitForgeNft`    |
|L-07 |  Uninitialized/Unbounded Issue in `fetchListings`|
|L-08 | Seller Could Deliberately Refuse A Purchase/Forge     |
|L-09 |Relationship between `maxAllowedClaimDivisor` and `nukeFactorMaxParam` is not strictly enforced  |
|L-10 | The `merger`Could Send the `mergeNFT` To A New Address to Bypass the Check     |
|L-11 | Secondary Market Buyer May Suffer A Loss If the Forging Happens Before the Transfer   |
|L-12 | Ambiguous Mod Due to  `2 ** 256 < 10 ** 78`        |
|L-13 | `deriveTokenParameters` does not align with the doc         |

## [H-01]  mintWithBudget will only works for the first maxTokensPerGen

## Vulnerability details
### Impact
The mintToken and mintWithBudget functions are expected to support NFT minting for multiple generations, from 1 to 10. However, the _tokenIds < maxTokensPerGen restriction in mintWithBudget limits its functionality to the first maxTokensPerGen NFTs. When there are more than 10,000 NFTs, mintWithBudget will silently return without minting any NFT, contrary to the expected behavior.


### Proof of Concept

https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L215-L216
The whitepaper specifies that the mintToken and mintWithBudget functions should work for generations from 1 to 10. However, the mintWithBudget function has a restriction on _tokenIds:
```
    while (budgetLeft >= mintPrice && _tokenIds < maxTokensPerGen) {
      _mintInternal(msg.sender, mintPrice);
      amountMinted++;
      budgetLeft -= mintPrice;
      mintPrice = calculateMintPrice();
    }
```

The check _tokenIds < maxTokensPerGen limits the mintWithBudget function to the first maxTokensPerGen NFTs. When there are more than 10,000 NFTs, the function will silently return without minting any new NFT, which is not the intended behavior.

In contrast, the mintToken function works correctly and can mint NFTs beyond the first maxTokensPerGen

## Recommended Mitigation Steps

To address this issue, remove or revise the check _tokenIds < maxTokensPerGen in the mintWithBudget function to align with the intended design.




## [H-02]  Accounting Issues Due to Generation Reset in _incrementGeneration 

## Vulnerability details
### Impact
The forge function allows minting new NFTs by combining two existing ones, generating a new entity in the next generation. This process considers the entity generated via forging to be capped under maxTokensPerGen. However, the _incrementGeneration function resets generationMintCounts[currentGeneration] to 0, which can lead to accounting issues when NFTs are minted through forging before the currentGeneration is updated.
### Proof of Concept
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L351-L352
The forge function considers the entity generated via forging to be capped under maxTokensPerGen. Also, the minted newGeneration could be larger than the currentGeneration which is `currentGeneration+1
```
  function forge(
    address newOwner,
    uint256 parent1Id,
    uint256 parent2Id,
    string memory
  ) external whenNotPaused nonReentrant returns (uint256) {
@=> uint256 newGeneration = getTokenGeneration(parent1Id) + 1; 

    /// Check new generation is not over maxGeneration
    require(newGeneration <= maxGeneration, "can't be over max generation");
	...

    // Mint the new entity
@=> uint256 newTokenId = _mintNewEntity(newOwner, newEntropy, newGeneration);

    return newTokenId;
  }

  function _mintNewEntity(
    address newOwner,
    uint256 entropy,
    uint256 gen
  ) private returns (uint256) {
    require(
  @=>  generationMintCounts[gen] < maxTokensPerGen,
      'Exceeds maxTokensPerGen'
    );

    _tokenIds++;
    uint256 newTokenId = _tokenIds;
    _mint(newOwner, newTokenId);

    tokenCreationTimestamps[newTokenId] = block.timestamp;
    tokenEntropy[newTokenId] = entropy;
    tokenGenerations[newTokenId] = gen;
 @=>generationMintCounts[gen]++;
    initialOwners[newTokenId] = newOwner;

    ...
  }
```
If the currentGeneration is later updated to newGeneration in the _incrementGeneration function, the previously added generationMintCounts[gen] is reset to 0:
```
  function _incrementGeneration() private {
    require(
      generationMintCounts[currentGeneration] >= maxTokensPerGen,
      'Generation limit not yet reached'
    );
    currentGeneration++;
@=> generationMintCounts[currentGeneration] = 0;
    priceIncrement = priceIncrement + priceIncrementByGen;
    entropyGenerator.initializeAlphaIndices();
    emit GenerationIncremented(currentGeneration);
  }
```
This leads to accounting issues, as there could be more than maxTokensPerGen under a generation due to previously forged NFTs not being counted in generationMintCounts.

Example Scenario

1. Assume currentGeneration = 1.
2. A user forges a new NFT, incrementing generationMintCounts[2] to 1.
3. Later, when the maxTokensPerGen is reached for generation_1, the generationMintCounts[2]is reset to 0 in _incrementGeneration, ignoring the previously forged NFTs, causing the system to allow more than maxTokensPerGen in a generation.
## Recommended Mitigation Steps
To mitigate this issue, remove the reset logic in _incrementGeneration to accurately track the number of tokens minted per generation.



## [M-01]  The 999999 Constraint Can Not be Guaranteed

## Vulnerability details
### Impact
In the whitepaper, it is stated:

"There is a certain entropy, “999999” which is referred to as “the Golden God”, since it has perfect parameters and will exceed all other entities if played correctly. The Golden God is scanned for and is kept out of the first 2 passes, but is deliberately set in the final pass (at some random point). The Golden God should be the most valuable entity".

The constraint inferred from this is that there should be no 999999 returned as entropy in the first two batches, and this lucky Golden God is set in the final pass at a random point (usually only 1 point).

However, the current check require(pseudoRandomValue != 999999, 'Invalid value, retry.') cannot guarantee this constraint. As a result, 999999 could appear in the first two batches, and there could be multiple 999999 returned as entropy which contradicts the team’s design.


### Proof of Concept

https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntropyGenerator/EntropyGenerator.sol#L171-L175
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntropyGenerator/EntropyGenerator.sol#L72-L78
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntropyGenerator/EntropyGenerator.sol#L52-L58

In the functions writeEntropyBatch1 and writeEntropyBatch2, it is required that the pseudoRandomValue stored in entropySlots should not be 999999:

```
        require(pseudoRandomValue != 999999, 'Invalid value, retry.');
```

The problem is that the entropySlots do not store the entropy directly. Instead, it is further processed in getEntropy:
```
    uint256 slotValue = entropySlots[slotIndex]; // slice the required [art of the entropy value
    uint256 entropy = (slotValue / (10 ** (72 - position))) % 1000000; // adjust the entropy value based on the number of digits
    uint256 paddedEntropy = entropy * (10 ** (6 - numberOfDigits(entropy)));

    return paddedEntropy; // return the caculated entropy value
```
Currently, the scope of slotValue is within uint256, due to the following computation:
```
        uint256 pseudoRandomValue = uint256(
          keccak256(abi.encodePacked(block.number, i))
        ) % uint256(10) ** 78;
        ...
        entropySlots[i] = pseudoRandomValue;
```
Since 10 ** 78 > 2 ** 256, the mod operation here doesn’t take effect. Thus, the scope of entropySlots is uint256 (or 78 digits).

So in getEntropy, we have:

```
    uint256 position = numberIndex * 6; // calculate the position for slicing the entropy value
    require(position <= 72, 'Position calculation error');

    uint256 slotValue = entropySlots[slotIndex]; // slice the required [art of the entropy value
    uint256 entropy = (slotValue / (10 ** (72 - position))) % 1000000; // adjust the entropy value based on the number of digits
    uint256 paddedEntropy = entropy * (10 ** (6 - numberOfDigits(entropy)));
```
There are multiple cases when the entropy could be 999999:

- slotValue=YYYYYYYYY999999XXXXXX and position = 66 (numberIndex = 11)
- slotValue=YYYYYYYYY999999XXXXXXXXXXXX and position = 60 (numberIndex = 10)
- ...
This clearly breaks the intention of the protocol. If there are multiple Golden God entities, the game mechanism is greatly influenced.
## Recommended Mitigation Steps
To mitigate this issue:
• Add a more comprehensive check to ensure the entropy=999999 does not occur in the first two batches.

## [M-02]  Incorrect mintPrice When maxTokensPerGen Is Reached

## Vulnerability details
### Impact

In the [white paper](https://docs.google.com/document/d/1pihtkKyyxobFWdaNU4YfAy56Q7WIMbFJjSHUAfRm6BA/edit), it is expected that **The first starts at 0.005 ETH and each subsequent one rises linearly by 0.0000245 ETH until the final is 0.25 ETH. In total if all are minted then 1,275 ETH is raised in Generation 1. Each generation’s price increment increases by 0.000005.**.

However, the current implementation of the calculateMintPrice function does not correctly account for generation increments happening after price calculation, leading to incorrect pricing. This could result in users either facing DoS (Denial of Service) issues or overpaying for minting.




### Proof of Concept
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L190-L193

In the white paper, it is expected that **The first starts at 0.005 ETH and each subsequent one rises linearly by 0.0000245 ETH until the final is 0.25 ETH. In total if all are minted then 1,275 ETH is raised in Generation 1. Each generation’s price increment increases by 0.000005.**.

The calculateMintPrice function calculates the mint price based on the current generation and the number of mints within that generation:

```
  function calculateMintPrice() public view returns (uint256) {
 @=> uint256 currentGenMintCount = generationMintCounts[currentGeneration];
     uint256 priceIncrease = priceIncrement * currentGenMintCount;
 @=> uint256 price = startPrice + priceIncrease;
     return price;
  }
```
However, the function is called before the generation is incremented in the mintToken function:
```
  function mintToken(
    bytes32[] calldata proof
  )
    public
    payable
    whenNotPaused
    nonReentrant
    onlyWhitelisted(proof, keccak256(abi.encodePacked(msg.sender)))
  {
@=> uint256 mintPrice = calculateMintPrice(); // <= price calculation
    require(msg.value >= mintPrice, 'Insufficient ETH send for minting.'); // @audit Incorrect Pricing.

@=> _mintInternal(msg.sender, mintPrice); // <= generation increment

    uint256 excessPayment = msg.value - mintPrice;
    if (excessPayment > 0) {
      (bool refundSuccess, ) = msg.sender.call{ value: excessPayment }('');
      require(refundSuccess, 'Refund of excess payment failed.');
    }
  }

  function _mintInternal(address to, uint256 mintPrice) internal {
    if (generationMintCounts[currentGeneration] >= maxTokensPerGen) {
 @=>  _incrementGeneration();
    }
    ...
  }

  function _incrementGeneration() private {
    require(
 @=>  generationMintCounts[currentGeneration] >= maxTokensPerGen,
      'Generation limit not yet reached'
    );
 @=>  currentGeneration++;
 @=>  generationMintCounts[currentGeneration] = 0;
    priceIncrement = priceIncrement + priceIncrementByGen;
    entropyGenerator.initializeAlphaIndices();
    emit GenerationIncremented(currentGeneration);
  }
```
In the edge case where generationMintCounts[currentGeneration] equals maxTokensPerGen, the generation should increase by 1, and the price should be reset to the startPrice. However, the calculateMintPrice function calculates the price before this increment, leading to an overestimation of the price.

Example Scenario

1. currentGeneration = 1 and generationMintCounts[currentGeneration] = maxTokensPerGen = 10000.
2. User Bob calls mintToken. The calculated mintPrice is startPrice + generationMintCounts[currentGeneration] * priceIncrement = 0.005 + 10000 * 0.0000245 = 0.25 ETH.
3. However, this NFT should be the first of the second generation, and the correct price should be startPrice = 0.005 ETH.
4. Bob either cannot mint if he sends 0.005 ETH (transaction reverts) or overpays significantly if he sends 0.25 ETH.
Note: Since this is also used in mintWithBudget, this could also lead to the while loop exits earlier than expected.

## Recommended Mitigation Steps

To mitigate this issue:

- Check and Update Generation at the Start of Minting: Move the generation check and update logic to the start of the mintToken function to ensure the correct generation and price are calculated before minting.
- Call _incrementGeneration after each mint: update the _mintInternal function just like _mintNewEntity to include a generationMintCounts[gen] check and update the generation if necessary.



## [M-03]  There is No Pause/Unpause Function to Change the State

## Vulnerability details
### Impact
The Pausable contract from OpenZeppelin is inherited and used across multiple contracts in the project, indicating that certain functionalities should behave differently based on the pause/unpause state. However, the Pausable contract itself does not provide a public interface to trigger the pause or unpause state transitions. If child contracts fail to implement these functions, the whenNotPaused and whenPaused modifiers will not function correctly, effectively breaking the pausing mechanism.
### Proof of Concept
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/DevFund/DevFund.sol#L11-L12
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L20-L21
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L11-L12
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityTrading/EntityTrading.sol#L11-L12
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntropyGenerator/EntropyGenerator.sol#L9-L10

The following contracts(as an example) inherit the Pausable contract and use the whenNotPaused modifier, which relies on the pause state:
```
contract DevFund is IDevFund, Ownable, ReentrancyGuard, Pausable {
    ...
@=> function claim() external whenNotPaused nonReentrant {...}
    ...
}
```
However, as per [OZ implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.9/contracts/security/Pausable.sol), the Pausable contract does not provide public pause or unpause functions by default. It only offers internal _pause() and _unpause() functions which are to be further called:
```
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
```
None of the contracts (DevFund, EntityForging, EntityTrading, NukeFund, and TraitForgeNft) implement these functions publicly, which means the whenNotPaused modifier will never work as intended, effectively breaking the pausing mechanism.
## Recommended Mitigation Steps
To ensure the pausing functionality works correctly, implement public pause and unpause functions in the child contracts (DevFund, EntityForging, EntityTrading, NukeFund, and TraitForgeNft). This will allow for proper state transitions and enforcement of the pause state.

## [M-04]  forgePotential check is incorrect in listForForging

## Vulnerability details
### Impact
The check forgingCounts[tokenId] <= forgePotential in the forgeWithListed function is incorrect. As forgingCounts will increase by 1 without any further check for forgerTokenId, this will cause forgingCounts[tokenId] > forgePotential, which breaks the game invariant.


### Proof of Concept
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L89-L90
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L132-L134

In the forgeWithListed function, the forgingCounts for the forgeTokenId is checked as follows:
```
    require(
      forgePotential > 0 && forgingCounts[tokenId] <= forgePotential,
      'Entity has reached its forging limit'
    );
```
The issue arises due to the use of the <= operator. The check will still pass when forgingCounts[tokenId] == forgePotential. Later in the function forgeWithListed, the forgingCounts[forgeTokenId] is directly increased:
```
    // Check forger's breed count increment but do not check forge potential here
    // as it is already checked in listForForging for the forger
    forgingCounts[forgerTokenId]++;
```
This is incorrect since it can result in forgingCounts[tokenId] > forgePotential, breaking the game invariant.
## Recommended Mitigation Steps
Change the operator from forgingCounts[tokenId] <= forgePotential to forgingCounts[tokenId] < forgePotential.


## [M-05]  No Slippage Control in nuke 

## Vulnerability details
### Impact
The current nuke process in the NukeFund contract does not have slippage protection, which can result in users receiving less ETH if they call the nuke function later than others. Since the fund decreases after each nuke but the percentage (finalNukeFactor) remains unchanged, users calling the function subsequently might receive a significantly lower claim amount than expected, leading to potential losses.


### Proof of Concept
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/NukeFund/NukeFund.sol#L154-L155

In the nuke function, the claim amount received by the msg.sender is determined by the fund and finalNukeFactor:
```
	    uint256 finalNukeFactor = calculateNukeFactor(tokenId); // finalNukeFactor has 5 digits
@=>     uint256 potentialClaimAmount = (fund * finalNukeFactor) / MAX_DENOMINATOR; // Calculate the potential claim amount based on the finalNukeFactor
	    uint256 maxAllowedClaimAmount = fund / maxAllowedClaimDivisor; // Define a maximum allowed claim amount as 50% of the current fund size
	
	    // Directly assign the value to claimAmount based on the condition, removing the redeclaration
	    uint256 claimAmount = finalNukeFactor > nukeFactorMaxParam
	      ? maxAllowedClaimAmount
	      : potentialClaimAmount;
```
The fund is reduced by the claim amount after each nuke:
```
    fund -= claimAmount; // Deduct the claim amount from the fund
```
Thus, if multiple users call nuke consecutively, the first user could receive a larger share of the fund than subsequent users. This situation is exacerbated if the first user claims a large amount, depleting the fund significantly for the following users.

Additionally, the nuke function does not take a minAmount parameter to specify a minimum acceptable claim amount, which could help prevent losses due to slippage.
```
  function nuke(uint256 tokenId) public whenNotPaused nonReentrant {...} // <= No `minAmount`
```
## Recommended Mitigation Steps
Introduce a minAmount parameter in the nuke function to allow users to specify the minimum acceptable claim amount. If the calculated claim amount is less than minAmount, the transaction should revert.


## [L-01] Changing Centralized Parameters Half-way Could Cause Issues

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L22-L25
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L37-L48
### Description
In the project, several parameters such as `maxTokensPerGen`, `startPrice`, `priceIncrement`, and `priceIncrementByGen` are designed to be constants:

```solidity
  // Constants for token generation and pricing
  uint256 public maxTokensPerGen = 10000; // constants should be constants
  uint256 public startPrice = 0.005 ether;
  uint256 public priceIncrement = 0.0000245 ether;
  uint256 public priceIncrementByGen = 0.000005 ether;
```

However, these parameters, along with others like `maxGeneration` and `rootHash`, can be modified by the contract owner:

```solidity
  function setStartPrice(uint256 _startPrice) external onlyOwner {
    startPrice = _startPrice;
  }

  function setPriceIncrement(uint256 _priceIncrement) external onlyOwner {
    priceIncrement = _priceIncrement;
  }

  function setPriceIncrementByGen(
    uint256 _priceIncrementByGen
  ) external onlyOwner {
    priceIncrementByGen = _priceIncrementByGen;
  }

  function setMaxGeneration(uint maxGeneration_) external onlyOwner {
    require(
      maxGeneration_ >= currentGeneration,
      "can't below than current generation"
    );
    maxGeneration = maxGeneration_;
  }

  function setRootHash(bytes32 rootHash_) external onlyOwner {
    // @note: Centralized Risk. Should not change.
    rootHash = rootHash_;
  }

  function setWhitelistEndTime(uint256 endTime_) external onlyOwner {
    whitelistEndTime = endTime_;
  }
```

Allowing these parameters to be changed midway through the contract’s owner's operation can lead to several unexpected consequences:

• **Price Changes**: If `startPrice`, `priceIncrement`, or `priceIncrementByGen` are suddenly altered, users could unintentionally spend more funds than anticipated.
• **Generation Limits**: Modifying `maxGeneration` can unexpectedly change the global total supply of tokens.
• **Whitelist Integrity**: Changing the `rootHash` halfway can allow more whitelisted accounts to join and mint, leading to unexpected outcomes.
• **Whitelist Period Extension: Changing the `whitelistEndTime` halfway can extend the whitelisted period.

To note, this is also the same in other contracts like `EntityForging`.
• **Fee and Tax**: If `taxCut`, `minimumListFee`are suddenly altered, users could unintentionally pay more taxes/fees than anticipated.

To note, this is also the same in other contracts like `NukeFund`.
• **Quick Exit**: If `ageMultiplier`, `minimumDaysHeld`are suddenly altered, users could `nuke` their NFT in a shorter period and get more shares.

### Recommendation
To mitigate, re-assess whether these parameters need to be modifiable. If they are intended to be constants, enforce immutability to avoid potential issues caused by centralized operations.

## [L-02] Whitelist Users Could Participate More Than Once

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L51-L59

### Description
The `onlyWhitelisted` modifier ensures that only whitelisted users can perform certain operations within the whitelist period:

```solidity
  modifier onlyWhitelisted(bytes32[] calldata proof, bytes32 leaf) {
    if (block.timestamp <= whitelistEndTime) { // @note could disable the whitelist only at anytime by the owner
      require(
@=>      MerkleProof.verify(proof, rootHash, leaf), // @note: whitelist can continously participate
        'Not whitelisted user'
      );
    }
    _;
  }
```

However, the modifier does not record the `leaf` input to prevent future replays. Consequently, whitelisted users can participate in minting more than once by providing the same proof multiple times.

### Recommendation
To mitigate this issue, revise the design to check if each whitelisted user can  participate more than once once during the whitelist period. 

If it is to be restricted, this can be achieved by recording the participation of each user and preventing multiple entries.

## [L-03] The usage of `amountMinted` is redundant

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L212-L213
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L217-L218
### Description
In the `mintWithBudget` function, the local variable `amountMinted` is used to increment with each mint but serves no further purpose within the function. This makes the use of `amountMinted` redundant.
```solidity
  function mintWithBudget(
    bytes32[] calldata proof
  )
    public
    payable
    whenNotPaused
    nonReentrant
    onlyWhitelisted(proof, keccak256(abi.encodePacked(msg.sender)))
  {
	    uint256 mintPrice = calculateMintPrice();
@=> 	uint256 amountMinted = 0;
	    uint256 budgetLeft = msg.value;
	
	    while (budgetLeft >= mintPrice && _tokenIds < maxTokensPerGen) { // @audit _tokenIds can only work with 1 generation
	      _mintInternal(msg.sender, mintPrice);
@=> 	  amountMinted++;
	      budgetLeft -= mintPrice;
	      mintPrice = calculateMintPrice();
	    }
	    if (budgetLeft > 0) {
	      (bool refundSuccess, ) = msg.sender.call{ value: budgetLeft }('');
	      require(refundSuccess, 'Refund failed.');
	    }
  }
```
The variable `amountMinted` is incremented within the while loop but is not used after the loop. Hence, it serves no purpose in the function and can be removed.
### Recommendation
Remove the `amountMinted` variable and its associated increment statement to simplify the code.

## [L-04] The `>=` check for `generationMintCounts` could be simplified

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L332
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L281
### Description
In the `TraitForgeNft` contract, the check `generationMintCounts[currentGeneration] >= maxTokensPerGen` can be simplified to `generationMintCounts[currentGeneration] == maxTokensPerGen`. 

Since `generationMintCounts[currentGeneration]` will not exceed `maxTokensPerGen` under normal circumstances (if `maxTokensPerGen` is not altered during the contract’s lifecycle), the check can be simplified to:

```solidity
    if (generationMintCounts[currentGeneration] >= maxTokensPerGen) {
      _incrementGeneration();
    }
```

### Recommendation
Simplify the check to `==` if it is guaranteed that `maxTokensPerGen` will not be changed during the contract’s lifecycle.

## [L-05] Self-transfer of `TraitForgeNft` Could Clear Listing Info

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L378-L394
### Description
In the `TraitForgeNft` contract, the `_beforeTokenTransfer` function is overridden to include additional constraints, such as canceling the listing information of a token upon transfer. However, the current implementation does not account for self-transfers (where the from and to addresses are the same). This could lead to accidental clearing of listing information.

```solidity
    /// @dev don't update the transferred timestamp if from and to address are same
    if (from != to) {
      lastTokenTransferredTimestamp[firstTokenId] = block.timestamp;
    }

    // @note: self-transfer could clear listing info.
    if (listedId > 0) {
      IEntityForging.Listing memory listing = entityForgingContract.getListings(
        listedId
      );
      if (
        listing.tokenId == firstTokenId &&
        listing.account == from &&
        listing.isListed
      ) {
        entityForgingContract.cancelListingForForging(firstTokenId);
      }
    }
```

The condition `from != to` is considered for updating the transfer timestamp `lastTokenTransferredTimestamp`, but not for canceling the listing. This oversight allows a self-transfer (where from == to) to inadvertently clear the listing information.

### Recommendation

To prevent accidental clearing of listing information during self-transfers, modify the `_beforeTokenTransfer` function to only cancel the listing if `from!=to`.

## [L-06] Inconsistent Usage of `pause()` and `whenNotPaused` in `TraitForgeNft`

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L207-L208
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/TraitForgeNft/TraitForgeNft.sol#L396-L397
### Description
The `TraitForgeNft` contract inherits from `Pausable` and supports pausing functionalities. However, the contract uses the pausing mechanism inconsistently across different functions.

In the `TraitForgeNft` contract, the `mintToken` function uses the `whenNotPaused` modifier to ensure it can only be executed when the contract is not paused.
On the other hand, the `_beforeTokenTransfer` function directly checks the `paused()` state without using the `whenNotPaused` modifier.

```solidity
  function mintToken(
    bytes32[] calldata proof
  )
    public
    payable
@=> whenNotPaused
    nonReentrant
    onlyWhitelisted(proof, keccak256(abi.encodePacked(msg.sender)))
  {...}

  function _beforeTokenTransfer(
    address from,
    address to,
    uint256 firstTokenId,
    uint256 batchSize
  ) internal virtual override {
	    super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
		...
@=>     require(!paused(), 'ERC721Pausable: token transfer while paused'); // @note: why not use whenNotPaused
  }
```

The inconsistent usage is not a good practice and could cause confusion.
### Recommendation

To ensure consistency and improve readability, use the `whenNotPaused` modifier in the `_beforeTokenTransfer` function instead of directly checking the `paused()` state. This will align the pausing logic with other functions in the contract.

## [L-07] Uninitialized/Unbounded Issue in `fetchListings`

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L49-L54
### Description
The function fetchListings initializes an array of `listingCount + 1` but only fills elements from index `1` to `listingCount`, leaving the first element uninitialized. This off-by-one issue can cause confusion and may lead to unexpected behavior when the function is used.

```solidity
  function fetchListings() external view returns (Listing[] memory _listings) {
    _listings = new Listing[](listingCount + 1);
    for (uint256 i = 1; i <= listingCount; ++i) {
      _listings[i] = listings[i]; //@audit incorrect setup
    }
  }
```


Additionally, if listings are deleted via the `cancelListingForForging` function, the corresponding elements in the listings array become uninitialized or hold no value, further complicating the data returned by `fetchListings`.

**Also, since the listing is unbounded(grows over time) and is looped, when there are so many listings, this could cause performance issues (DOS) or OOG(out-of-gas) issues when all previous listings are retrieved. **
### Recommendation

- Revise the design to ensure that the returned array only contains initialized elements. One approach is to skip index `0` or filter out uninitialized elements before returning the array.
- Revise the design to keep track of the active listing to avoid oog/dos issues, or use pagination to improve performance.

## [L-08] Seller Could Deliberately Refuse A Purchase/Forge

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityTrading/EntityTrading.sol#L77
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L159-L160
### Description
The `seller/forgeOwner` could deliberately refuse a purchase/forge in the callback/receive function by simply reverting. This can result in a denial of service (DoS) attack, where the `seller/forgeOwner` prevents successful transactions, causing frustration and poor user experience.

```solidity
...
    (bool success_forge, ) = forgerOwner.call{ value: forgerShare }('');
...
    (bool success, ) = payable(listing.seller).call{ value: sellerProceeds }(
      ''
    );
```

If the `seller` or `forgeOwner` reverts the transaction, it will cause a failure in the purchase/forge process, resulting in a denial of service for other users. Since the listing can only be canceled by the `seller/forgeOwner`, this can lead to a bad user experience.

### Recommendation

To mitigate this issue, implement a method to allow the contract owner to cancel the listing. This will provide a mechanism to handle cases where the `seller/forgeOwner` deliberately refuses transactions.

## [L-09] Relationship between `maxAllowedClaimDivisor` and `nukeFactorMaxParam` is not strictly enforced

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/NukeFund/NukeFund.sol#L168-L173
### Description
The nuke function in the `NukeFund` contract does not enforce the relationship between `maxAllowedClaimDivisor` and `nukeFactorMaxParam`. This relationship is crucial for the proper calculation of the `claimAmount`. If these variables are not set correctly, it can lead to incorrect or unexpected behavior in the `nuke` process, potentially resulting in incorrect distribution of funds.

In the nuke function, the `claimAmount` is calculated based on whether `finalNukeFactor` exceeds `nukeFactorMaxParam`:

```solidity
    uint256 potentialClaimAmount = (fund * finalNukeFactor) / MAX_DENOMINATOR; // Calculate the potential claim amount based on the finalNukeFactor
    uint256 maxAllowedClaimAmount = fund / maxAllowedClaimDivisor; // Define a maximum allowed claim amount as 50% of the current fund size

    // Directly assign the value to claimAmount based on the condition, removing the redeclaration
    uint256 claimAmount = finalNukeFactor > nukeFactorMaxParam
      ? maxAllowedClaimAmount
      : potentialClaimAmount;

    fund -= claimAmount; // Deduct the claim amount from the fund
```

The implicit relationship is:
```solidity
fund / maxAllowedClaimDivisor = fund * nukeFactorMaxParam / MAX_DENOMINATOR
=>
maxAllowedClaimDivisor * nukeFactorMaxParam = MAX_DENOMINATOR
```

However, both `maxAllowedClaimDivisor` and `nukeFactorMaxParam` are set independently without enforcing this constraint:

```solidity
  function setMaxAllowedClaimDivisor(uint256 value) external onlyOwner {
    maxAllowedClaimDivisor = value;
  }

  function setNukeFactorMaxParam(uint256 value) external onlyOwner {
    nukeFactorMaxParam = value;
  }
```

### Recommendation

Ensure that the relationship between `maxAllowedClaimDivisor` and `nukeFactorMaxParam` is maintained when setting these values. This can be done by modifying the setter functions to enforce the constraint.

## [L-11] Secondary Market Buyer May Suffer A Loss If the Forging Happens Before the Transfer

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntityForging/EntityForging.sol#L112-L119
### Description

The parameter `forgePotential` is crucial as it determines the number of times an NFT can forge within a year.

```solidity
    require(
      forgePotential > 0 && forgingCounts[tokenId] <= forgePotential,
      'Entity has reached its forging limit'
    );
```

In the secondary market, NFTs with a higher `forgePotential` or lower `forgeCounts` are valued more. However, there is a potential issue that can cause losses for buyers in the secondary market. Consider the following scenario:

1. User `Alice` lists an NFT for forging, which can still forge one more time.
2. User `Alice` lists the NFT in the secondary market.
3. User `Bob` buys the NFT, willing to pay a higher price since the NFT can still forge.
4. Just before his purchase, the NFT is forged. Consequently, `Bob` loses money as the NFT’s value decreases due to it reaching its forging limit.

### Recommendation
- **Cooldown Period for Transfer**: Implement a cooldown period after a successful forge, during which the NFT cannot be transferred. This ensures that the buyer can verify the forging status and potential before completing the purchase.

## [L-12] Ambiguous Mod Due to  `2 ** 256 < 10 ** 78`

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntropyGenerator/EntropyGenerator.sol#L73-L75
### Description

The `mod` operation in the code below is unnecessary and adds unnecessary complexity. This is because the modulus value `10 ** 78` is larger than the maximum value of a uint256 (`2 ** 256`). As a result, the modulus operation has no effect, leading to ambiguity and potential misunderstanding of the code’s intent.

```solidity
        uint256 pseudoRandomValue = uint256(
          keccak256(abi.encodePacked(block.number, i))
        ) % uint256(10) ** 78;
```

### Recommendation
- Remove the unnecessary modulus operation to simplify the code and avoid confusion.

## [L-13] `deriveTokenParameters` does not align with the doc

### Link
https://github.com/code-423n4/2024-07-traitforge/blob/279b2887e3d38bc219a05d332cbcb0655b2dc644/contracts/EntropyGenerator/EntropyGenerator.sol#L152-L153
### Description

The function `deriveTokenParameters` contains calculations that do not align with the project’s documentation. This discrepancy can lead to misunderstandings and potential bugs in the system, as the calculated parameters will not match the expected values described in the documentation.**


The documentation specifies the following calculations:
1. **Entropy / 40 = initialNukeFactor**
2. **Entropy[4] = colour1 && forgePotential**

However, the deriveTokenParameters function calculates:
1. nukeFactor = entropy / 4000000
2. forgePotential = getFirstDigit(entropy)

```solidity
  // function to derive various parameters baed on entrtopy values, demonstrating potential cases
  function deriveTokenParameters(
    uint256 slotIndex,
    uint256 numberIndex
  )
    public
    view
    returns (
      uint256 nukeFactor,
      uint256 forgePotential,
      uint256 performanceFactor,
      bool isForger
    )
  {
    uint256 entropy = getEntropy(slotIndex, numberIndex);

    // example calcualtions using entropyto derive game-related parameters
@=> nukeFactor = entropy / 4000000; // inconsistent with design
@=> forgePotential = getFirstDigit(entropy);
    performanceFactor = entropy % 10;

    // exmaple logic to determine a boolean property based on entropy
    uint256 role = entropy % 3;
    isForger = role == 0;

    return (nukeFactor, forgePotential, performanceFactor, isForger); // return derived parammeters
  }
```

### Recommendation
Since the `deriveTokenParameters` function is not being used anymore, it is recommended to remove it from the codebase to avoid confusion and ensure the code remains clean and maintainable.