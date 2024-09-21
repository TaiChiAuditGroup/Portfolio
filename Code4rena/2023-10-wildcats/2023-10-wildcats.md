| Severity | Title |
| -------- | -------- | 
|H-01 |Lack of appropriate function in WildcatMarketController to close the market|
|H-02 |Wrong parameters used in calls to createEscrow function|
|L-01 |Market could be closed multiple times|
|L-02 |If admin removes the market from WildcatArchController - nukeFromOrbit and executeWithdrawal functions would be DOS for sanctioned lenders|
|L-03 |Protocol admin could accidentally front-run borrower with the fee increasing|
|NC-01 |Redundant modifier onlyControlledMarket in WildcatMarketController|
|NC-02 |Redundant line in WildcatSanctionsSentinel#createEscrow|



## [H-01]  Lack of appropriate function in WildcatMarketController to close the market

## Vulnerability details
The WildcatMarket contract has a closeMarket function that should allow the borrower to close the existing market if needed and the required conditions are met:
```
File: WildcatMarket.sol
133:   /**
134:    * @dev Sets the market APR to 0% and marks market as closed.
135:    *
136:    *      Can not be called if there are any unpaid withdrawal batches.
137:    *
138:    *      Transfers remaining debts from borrower if market is not fully
139:    *      collateralized; otherwise, transfers any assets in excess of
140:    *      debts to the borrower.
141:    */
142:   function closeMarket() external onlyController nonReentrant { 
...
```

The ```closeMarket``` function could be called only through the market controller due to it's access control modifier.

The motivation for existing such functionality is clearly described in protocol documentation:
```
In the event that a borrower has finished utilising the funds for the purpose that the market was set up to facilitate (or if lenders are choosing not to withdraw their assets and the borrower is paying too much interest on assets that have been re-deposited to the market), the borrower can close a market at will.
```
However, if we check the code of WildcatMarketController we can't find an appropriate function that would allow the borrower to call closeMarket at the market address. This would lead to the situation described earlier in docs - borrowers would need to pay interest for funds their not used after finished utilizing the funds.

### Impact
Borrowers cannot close the market if needed and would need to pay interest for funds their not used after finished utilizing the funds.

### Proof of Concept

1. Borrower creates a new market.
2. Lenders deposit their funds into the market.
3. Borrower uses provided funds and later returns them back to the market.
4. Lenders do not withdraw their funds, interests continue to accrue for their deposits.
5. Borrower can't close the market and is forced to pay interest for funds that are not utilized anymore.
This bug is missed in tests since they implemented in the way the caller is pranked as a controller address, while it should be an actual call through not existed WildcatMarketController#closeMarket function - L202:

```
File: WildcatMarket.t.sol
198:   // ===================================================================== //
199:   //                             closeMarket()                              //
200:   // ===================================================================== //
201: 
202:   function test_closeMarket_TransferRemainingDebt() external asAccount(address(controller)) {
203:     // Borrow 80% of deposits then request withdrawal of 100% of deposits
204:     _depositBorrowWithdraw(alice, 1e18, 8e17, 1e18);
205:     startPrank(borrower);
206:     asset.approve(address(market), 8e17);
207:     stopPrank();
208:     vm.expectEmit(address(asset));
209:     emit Transfer(borrower, address(market), 8e17);
210:     market.closeMarket();
211:   }

```


## Recommended Mitigation Steps
Consider implementing a function in WildcatMarketController that would allow the borrower to call the closeMarket function on the market contract.


## [H-02]  Wrong parameters used in calls to createEscrow function

## Vulnerability details
When a lender address becomes sanctioned due to sanction oracle, the market could create a separate Escrow contract that would hold the lender balance, or 2 Escrow contracts if sanctioned lender call WildcatMarketWithdrawals#executeWithdrawal.
Escrow is created using the WildcatSanctionsSentinel#createEscrow() function, which expects the next order of parameters:
```
File: WildcatSanctionsSentinel.sol
87:   /**
88:    * @dev Creates a new WildcatSanctionsEscrow contract for `borrower`,
89:    *      `account`, and `asset` or returns the existing escrow contract
90:    *      if one already exists.
91:    *
92:    *      The escrow contract is added to the set of sanction override
93:    *      addresses for `borrower` so that it can not be blocked.
94:    */
95:   function createEscrow(
96:     address borrower,
97:     address account, 
98:     address asset
99:   ) public override returns (address escrowContract) {
```
However, if we check how this function is called at WildcatMarketBase#_blockAccount, we can see that the wrong order of parameters was used - accountAddress and borrower switched their places:
```
File: WildcatMarketBase.sol
163:   function _blockAccount(MarketState memory state, address accountAddress) internal {
164:     Account memory account = _accounts[accountAddress];
165:     if (account.approval != AuthRole.Blocked) {
166:       uint104 scaledBalance = account.scaledBalance;
167:       account.approval = AuthRole.Blocked;
168:       emit AuthorizationStatusUpdated(accountAddress, AuthRole.Blocked);
169: 
170:       if (scaledBalance > 0) {
171:         account.scaledBalance = 0;
172:         address escrow = IWildcatSanctionsSentinel(sentinel).createEscrow(
173:           accountAddress, 
174:           borrower,
175:           address(this)
176:         );
```
This issue has a second appearance at WildcatMarketWithdrawals.sol#166, in this case, 2 Escrow contracts with wrong parameters would be created - one for market balance in _blockAccount call and the second for asset balance:
```
File: WildcatMarketWithdrawals.sol
164:     if (IWildcatSanctionsSentinel(sentinel).isSanctioned(borrower, accountAddress)) { 
165:       _blockAccount(state, accountAddress);
166:       address escrow = IWildcatSanctionsSentinel(sentinel).createEscrow(
167:         accountAddress,
168:         borrower,
169:         address(asset)
170:       );
```

### Impact
An escrow contract (or 2 contracts) would be created with the borrower's address as an expected receiver of sanctioned funds, while it should be the lender's address.


### Proof of Concept
The next test is an update of the existing test test_executeWithdrawal_Sanctioned in test/market/WildcatMarketWithdrawals.t.sol and could show a scenario when an Escrow contract created with wrong parameters, allowing the borrower to instantly withdraw assets that should be available only for the sanctioned lender:

```
  function test_executeWithdrawal_Sanctioned() external {
    _deposit(alice, 1e18);
    _requestWithdrawal(alice, 1e18);
    fastForward(parameters.withdrawalBatchDuration);
    sanctionsSentinel.sanction(alice);
    address escrow = sanctionsSentinel.getEscrowAddress(alice, borrower, address(asset));
    vm.expectEmit(address(asset));
    emit Transfer(address(market), escrow, 1e18);
    vm.expectEmit(address(market));
    emit SanctionedAccountWithdrawalSentToEscrow(alice, escrow, uint32(block.timestamp), 1e18);
    market.executeWithdrawal(alice, uint32(block.timestamp));

    // This check fails since Alice is not an actual "account" in escrow
    assertEq(alice, WildcatSanctionsEscrow(escrow).account(), "Account address at escrow is not Alice");

    // This check shows that the borrower could instantly withdraw funds that should be stored for Alice
    uint256 _balance = asset.balanceOf(borrower);
    WildcatSanctionsEscrow(escrow).releaseEscrow();
    uint256 balance_ = asset.balanceOf(borrower);
    assertEq(_balance, balance_, "Borrower balance increased");
  }
  ```
## Recommended Mitigation Steps
Consider updating the order of parameters at affected lines in WildcatMarketBase.sol#L172 and WildcatMarketWithdrawals.sol#L166

## [L-01] - Market could be closed multiple times

`WildcatMarket#closeMarket` function does not check if market is already closed:
```solidity
File: WildcatMarket.sol
142:   function closeMarket() external onlyController nonReentrant { 
143:     MarketState memory state = _getUpdatedState();
144:     state.annualInterestBips = 0;
145:     state.isClosed = true; 
146:     state.reserveRatioBips = 0;
147:     if (_withdrawalData.unpaidBatches.length() > 0) {
148:       revert CloseMarketWithUnpaidWithdrawals();
149:     }
150:     uint256 currentlyHeld = totalAssets();
151:     uint256 totalDebts = state.totalDebts();
152:     if (currentlyHeld < totalDebts) {
153:       // Transfer remaining debts from borrower
154:       asset.safeTransferFrom(borrower, address(this), totalDebts - currentlyHeld);
155:     } else if (currentlyHeld > totalDebts) { 
156:       // Transfer excess assets to borrower
157:       asset.safeTransfer(borrower, currentlyHeld - totalDebts);
158:     }
159:     _writeState(state);
160:     emit MarketClosed(block.timestamp);
161:   }
```
This could lead to a situation when the same market is closed more than 1 time, and an appropriate event is emitted, which would mislead external listeners.
Recommendation: Consider adding a check that the market is not closed yet in the `closeMarket` function.

## [L-02] - If admin removes the market from `WildcatArchController` - `nukeFromOrbit` and `executeWithdrawal` functions would be DOS for sanctioned lenders
`createEscrow` function that creates Escrow contracts for sanctioned lenders includes check that `msg.sender` is actually registered market:
```solidity
File: WildcatSanctionsSentinel.sol
095:   function createEscrow(
096:     address borrower,
097:     address account, 
098:     address asset
099:   ) public override returns (address escrowContract) {
100:     if (!IWildcatArchController(archController).isRegisteredMarket(msg.sender)) { 
101:       revert NotRegisteredMarket();
102:     }
...
```
At the same time `WildcatArchController` allows protocol admin to un-register any market using `removeMarket` function. This could lead to a situation when the market would be removed from `WildcatArchController` and sanctioned lenders would be unable to receive their funds due to DOS in `nukeFromOrbit` and `executeWithdrawal` functions that call the `createEscrow` function inside.
Recommendation: Consider adding a separate list of `removedMarkets` in `WildcatArchController` and check inside the `createEscrow` function if `msg.sender` is active or removed market.

## [L-03] - Protocol admin could accidentally front-run borrower with the fee increasing 
`WildcatMarketController#deployMarket` allows the borrower to deploy a new market and pay a fee to the protocol if it exists. This fee could be changed at any moment by admin.

Admin can accidentally front-run borrowers `deployMarket` call and set fee to bigger value, which borrower wasn't expected.

Recommendation: Consider adding a timelock to change fee parameters. This way, frontrunning will be impossible, and borrowers will know which fee they agree to.

## [NC-01] - Redundant modifier `onlyControlledMarket` in `WildcatMarketController`

Modifier `onlyControlledMarket` checks that the called market is actually a market that is deployed and controlled by the current controller:
```solidity 
File: WildcatMarketController.sol
87:   modifier onlyControlledMarket(address market) { 
88:     if (!_controlledMarkets.contains(market)) {
89:       revert NotControlledMarket();
90:     }
91:     _;
92:   }
``` 
But this check is redundant since the market itself checks that the caller is a correct controller:
```solidity
File: WildcatMarketConfig.sol
171:   function setReserveRatioBips(uint16 _reserveRatioBips) public onlyController nonReentrant {
...
```
Recommendation: Consider removing not needed modifier.

## [NC-02] - Redundant line in `WildcatSanctionsSentinel#createEscrow`

Line 114 in `createEscrow` change `sanctionOverrides` storage value for the newly created escrow address:
```solidity
File: WildcatSanctionsSentinel.sol
095:   function createEscrow(
...
110:     new WildcatSanctionsEscrow{ salt: keccak256(abi.encode(borrower, account, asset)) }(); 
111: 
112:     emit NewSanctionsEscrow(borrower, account, asset);
113: 
114:     sanctionOverrides[borrower][escrowContract] = true; 
119:   }
```

However, this value is not actually used anywhere in the codebase, since `isSanctioned` function actually checks `account` (lender address) to be sanctioned.

Recommendation: Consider removing not needed line 114.
