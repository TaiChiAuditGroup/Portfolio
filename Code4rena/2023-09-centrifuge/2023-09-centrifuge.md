| Severity | Title |
| -------- | -------- | 
|M-01 |Not implement ERC4626 properly|

## [M-01]  Not implement ERC4626 properly

## Vulnerability details
### Impact
According to EIP-4626, previewMint and previewWithdraw should round up.

In previewMint and previewWithdraw, the currencyAmount is calculated by calling _calculateCurrencyAmount.

The _calculateCurrencyAmount performs calculations using round down, which can result in a lower returnTrancheTokenAmount than expected.




### Proof of Concept
https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/InvestmentManager.sol#L383

https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/InvestmentManager.sol#L396



## Recommended Mitigation Steps
Introduce a deadline parameter to the mentioned Calculations should take into account the requirements of EIP 4626 and use the correct rounding method.
