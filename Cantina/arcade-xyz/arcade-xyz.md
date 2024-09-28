| Severity | Title |
| -------- | -------- | 
| M-01 |The lender may incur losses on a loan if the borrower repays it quickly, considering the `lenderPrincipleFee`|
| M-02 |`lenderPrincipalFee` can be bypassed using `rolloverLoan`|
| L-01 |Non-whitelisted collateral can still be used to create loan via `RefinanceController::refinanceLoan`|
| L-02 | Unexpected revert on `initializeLoan` with borrower-signed signature if `msg.sender` is approved by both parties|

## [M-01] The lender may incur losses on a loan if the borrower repays it quickly, considering the `lenderPrincipleFee`

## Vulnerability details
### Description
There is no minimum time limit for a borrower to repay the debt. If he calls repayFull not soon after the loan is signed, this may incur a loss of fund of the lender.

The lender has to pay the following fees :
```solidity
Principal * (LENDER_ORIGINATION_FEE + LENDER_PRINCIPAL_FEE) / Constants.BASIS_POINTS_DENOMINATOR;
```
And the lender will receive the following :
```solidity
interest *  (Constants.BASIS_POINTS_DENOMINATOR - lenderInterestFee) / Constants.BASIS_POINTS_DENOMINATOR;
```
However, the interest here isn't fixed.

It is calculated using the following formula in InterestCalculator::getProratedInterestAmount:

```solidity
Principal * timeSinceLastPayment * interestRate
            / (Constants.BASIS_POINTS_DENOMINATOR * Constants.SECONDS_IN_YEAR);
```

If the borrower calls repayFull not soon after the loan is signed, `timeSinceLastPayment` would be quite small, and the interest he receives may not be able to cover the fees he has paid for the loan. Thus, this may incur a loss of fund of the lender. The uncertainty of income and principal losses hinders the motivation and information for lenders to participate in lending.

## Recommended Mitigation Steps
To proper deal with this issue, a minimum interest to pay during the whole loan from the borrower should be considered.

## [M-02] `lenderPrincipalFee` can be bypassed using `rolloverLoan`

## Vulnerability details
### Description
Lender is expected to pay principalFee and interestFee when the borrower repays him. The relevant calculation can be seen in `RepaymentController::_prepareRepay`.
```solidity
        uint256 principalFee = (paymentToPrincipal * data.feeSnapshot.lenderPrincipalFee) / Constants.BASIS_POINTS_DENOMINATOR;
        ...
        amountToLender = amountFromBorrower - interestFee - principalFee;
```        
However, in OriginationController::rolloverLoan, when _calculateRolloverAmounts is used to calculate RolloverAmounts, only interestFee is taken into account.
```solidity
        uint256 interestFee = (interest * oldLoanData.feeSnapshot.lenderInterestFee)
            / Constants.BASIS_POINTS_DENOMINATOR;
```
and  amounts.amountToOldLender is only deducted with interestFee.
```solidity
        amounts.amountToOldLender = repayAmount - interestFee;
```
Thus, lenders, don't have to pay for `principalFee` to retrieve their principal due to the miss of calculation of `principalFee`. This would result in fees that should have been collected not being received, leading to a decrease in protocol fees.

## Recommended Mitigation Steps
Add the `principalFee` calculation in `_calculateRolloverAmounts` so that fees are collected anyway.



## [L-01] Non-whitelisted collateral can still be used to create loan via `RefinanceController::refinanceLoan`

## Vulnerability details
### Description
In the contract `OriginationConfiguration`, the `_allowedCollateral` is used to indicate if the collateral is allowed. The function `validateLoanTerms` would revert with an `OCC_InvalidCollateral` if the collateral is not whitelisted.
```solidity
        if (!isAllowedCollateral(terms.collateralAddress)) revert OCC_InvalidCollateral(terms.collateralAddress);
```
So, the function `validateLoanTerms` is used when `OriginationController::initializeLoan` and `OriginationController::rolloverLoan` are being called. Also in `OriginationControllerMigrate::_validateV3Migration`, it is also guaranteed that Any collateral or currencies that are whitelisted on v3 also need to be whitelisted on v4.

However, there is no relevant check in `RefinanceController`. So when a loan is refinanced, the only restriction in `_validateRefinance` is that the collateral should be the same.
```solidity
        if (
            newTerms.collateralAddress != oldLoanData.terms.collateralAddress ||
            newTerms.collateralId != oldLoanData.terms.collateralId
        ) revert REFI_CollateralMismatch(
            oldLoanData.terms.collateralAddress,
            oldLoanData.terms.collateralId,
            newTerms.collateralAddress,
            newTerms.collateralId
        );
```
But if the collateral is later removed from the whitelist via `OriginationConfiguration::setAllowedCollateralAddresses`, the check in `_validateRefinance` is still valid, thus, the previous loan is closed and a new loan is created via `RefinanceController::refinanceLoan`. This violates the design that a loan with unsupported collateral should never be created.

### Proof of Concept

The PoC of this finding (added to `Refinancing.ts`, under `describe("refinance active loan", () => {):`

```solidity
        it("same principal, same due date, unsupported collateral can be refinanced", async () => {
            const { originationController,originationConfiguration, refinanceController, loanCore, mockERC20, mockERC721, vaultFactory, lender, borrower, newLender, blockchainTime, } = ctx;

            const bundleId = await initializeBundle(vaultFactory, borrower);
            const bundleAddress = await vaultFactory.instanceAt(bundleId);
            const tokenId = await mint721(mockERC721, borrower);
            await mockERC721.connect(borrower).transferFrom(borrower.address, bundleAddress, tokenId);

            const loanTerms = createLoanTerms(mockERC20.address, vaultFactory.address, { collateralId: bundleId });
            await mint(mockERC20, lender, loanTerms.principal);
            await approve(mockERC20, lender, originationController.address, loanTerms.principal);

            const sig = await createLoanTermsSignature(
                originationController.address,
                "OriginationController",
                loanTerms,
                lender,
                EIP712_VERSION,
                defaultSigProperties,
                "l",
            );

            // start initial loan
            await vaultFactory.connect(borrower).approve(originationController.address, bundleId);
            await originationController
                .connect(borrower)
                .initializeLoan(loanTerms, borrowerStruct, lender.address, sig, defaultSigProperties, []);

            // fast forward 2 days
            await blockchainTime.increaseTime(60 * 60 * 24 * 2);

            // @audit-issue poc
            // The collateral is disabled here.
            await originationConfiguration.setAllowedCollateralAddresses(
                [mockERC721.address, vaultFactory.address],
                [false, false]
            );
            console.log("collateral Not allowed")

            // refinance loan terms, same due date, better interest and principal
            const loanData: LoanData = await loanCore.getLoan(1);
            const loanEndDate = BigNumber.from(loanData.startDate).add(loanData.terms.durationSecs);
            const sameDueDate = loanEndDate.sub(await blockchainTime.secondsFromNow(3));
            const refiLoanTerms = createLoanTerms(mockERC20.address, vaultFactory.address, {
                collateralId: bundleId,
                principal: loanTerms.principal, // same principal
                interestRate: BigNumber.from(500),
                durationSecs: sameDueDate
            });

            // approve old loan interest and new principal to be collected by LoanCore
            const interestDue = await originationController.getProratedInterestAmount(
                loanData.balance,
                loanData.terms.interestRate,
                loanData.terms.durationSecs,
                loanData.startDate,
                loanData.lastAccrualTimestamp,
                await blockchainTime.secondsFromNow(3),
            );

            const newLenderOwes: BigNumber = refiLoanTerms.principal.add(interestDue);

            await mint(mockERC20, newLender, newLenderOwes);
            await approve(mockERC20, newLender, refinanceController.address, newLenderOwes);

            const oldLenderBalanceBefore = await mockERC20.balanceOf(lender.address);
            const newLenderBalanceBefore = await mockERC20.balanceOf(newLender.address);
            const borrowerBalanceBefore = await mockERC20.balanceOf(borrower.address);

            // refinance loan
            expect(await refinanceController.connect(newLender).refinanceLoan(1, refiLoanTerms))
                .to.emit(loanCore, "LoanRolledOver");

            const oldLenderBalanceAfter = await mockERC20.balanceOf(lender.address);
            const newLenderBalanceAfter = await mockERC20.balanceOf(newLender.address);
            const borrowerBalanceAfter = await mockERC20.balanceOf(borrower.address);

            // accounting checks
            expect(oldLenderBalanceAfter).to.equal(oldLenderBalanceBefore.add(loanTerms.principal.add(interestDue)));
            expect(newLenderBalanceAfter).to.equal(newLenderBalanceBefore.sub(newLenderOwes));
            expect(borrowerBalanceAfter).to.equal(borrowerBalanceBefore);

            // loan state checks
            const loanData1After: LoanData = await loanCore.getLoan(1);
            expect(loanData1After.state).to.equal(2); // repaid
            expect(loanData1After.balance).to.equal(0);
            expect(loanData1After.interestAmountPaid).to.equal(interestDue);

            const loanDataAfter: LoanData = await loanCore.getLoan(2);
            expect(loanDataAfter.state).to.equal(1); // active
            expect(loanDataAfter.balance).to.equal(refiLoanTerms.principal);
            expect(loanDataAfter.interestAmountPaid).to.equal(0);
        });
```

## Recommended Mitigation Steps
It would be proper to add the following check to the `_validateRefinance` function:

```solidity
        if (
            newTerms.collateralAddress != oldLoanData.terms.collateralAddress ||
            newTerms.collateralId != oldLoanData.terms.collateralId
        ) revert REFI_CollateralMismatch(
            oldLoanData.terms.collateralAddress,
            oldLoanData.terms.collateralId,
            newTerms.collateralAddress,
            newTerms.collateralId
        );
```


## [L-02] Unexpected revert on `initializeLoan` with borrower-signed signature if `msg.sender` is approved by both parties

## Vulnerability details
### Description
In `OriginationController::initializeLoan`, it is expected that the external signer must come from the opposite side of the loan as the caller.

Thus, if `msg.sender` is approved by (or is) borrower, the signature is expected to come from the lender, and the signature will be validated with the lender address.
```solidity
        Side neededSide = isSelfOrApproved(borrowerData.borrower, msg.sender) ? Side.LEND : Side.BORROW;
```
In the situation that `msg.sender` is approved by both lender and borrower (possible, especially when the loan is facilitated through third-party matchmaking.), things might go wrong.

The contract tries to deal with this in the function `_validateCounterparties` by specifying that even if the caller is approved, the caller is not the signing counterparty.

```solidity
        // Make sure the signer recovered from the loan terms is not the caller,
        // and even if the caller is approved, the caller is not the signing counterparty 
        if (caller == signer || caller == signingCounterparty) revert OC_ApprovedOwnLoan(caller);
```

However, in the situation that the caller is approved by both parties via the approve function if the signature is actually signed by borrower, the neededSide would still be `Side.LEND`.

Thus the signature will fail to pass the check as `lender != borrower`, causing an unexpected revert due to `OC_InvalidSignature`.

### Proof of Concept

The PoC is here (added to `OriginationController.ts` under `describe("initializeLoan", () => {`)

```solidity
        it("Initializes a loan signed by the borrower but revert due to double approval", async () => {
            const { originationController, mockERC20, vaultFactory, user: lender, other: borrower, signers } = ctx;

            const bundleId = await initializeBundle(vaultFactory, borrower);
            const loanTerms = createLoanTerms(mockERC20.address, vaultFactory.address, { collateralId: bundleId });
            await mint(mockERC20, lender, loanTerms.principal);

            const sig = await createLoanTermsSignature(
                originationController.address,
                "OriginationController",
                loanTerms,
                borrower,
                EIP712_VERSION,
                defaultSigProperties,
                "b",
            );

            await approve(mockERC20, lender, originationController.address, loanTerms.principal);
            await vaultFactory.connect(borrower).approve(originationController.address, bundleId);

            //@audit-issue poc
            await originationController.connect(lender).approve(signers[3].address,true);
            console.log("approved by lender");
            await originationController.connect(borrower).approve(signers[3].address,true);
            console.log("approved by borrower");
            await expect(
                originationController
                    .connect(signers[3],)
                    .initializeLoan(loanTerms, borrowerStruct, lender.address, sig, defaultSigProperties, []),
            )
                .to.be.revertedWith('OC_InvalidSignature("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x57F3A07e187674B8f09Ed86C9d8cE4eC0a0cbeEc")');

        });

```

## Recommended Mitigation Steps
A few possible ways to mitigate:
1. Add a parameter specifying the side directly.
2.Simply revert with a specific customized error when msg.sender is approved by two parties.