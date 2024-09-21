| Severity | Title |
| -------- | -------- | 
|M-01 |The quotes from Curve may be subject to manipulation|
|M-02 |Missing deadline checks allow pending transactions to be maliciously executed|

## [M-01]  The quotes from Curve may be subject to manipulation

## Vulnerability details
### Impact
The get_virtual_price() function in Curve has a reentrancy risk, which can affect the price if the protocol fetches quotes from pools integrated with ETH on Curve.

Please refer below link for read-only reentrancy detail.
https://chainsecurity.com/heartbreaks-curve-lp-oracles/

 The attacker could use this to artificially inflate the price of the LP token/its balance, and use the inflated balance to take out loans which become undercollateralized at the end of the transaction, or to buy assets at exchange rates not actually available on the open market.
### Proof of Concept
https://github.com/Tapioca-DAO/tapioca-periph-audit/blob/main/contracts/oracle/implementations/ARBTriCryptoOracle.sol#L118


## Recommended Mitigation Steps
Calling the pools withdraw_admin_fees function to trigger the reentrancy lock.

## [M-02]  Missing deadline checks allow pending transactions to be maliciously executed

## Vulnerability details
### Impact
In Singularity.sol, sellCollateral() is used to sell collateral to repay debt, and buyCollateral() is used to borrow more and buy collateral with it. However, both of these functions lack consideration for the deadline, which means transactions may wait in the memory pool for a long time.
### Proof of Concept
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/markets/singularity/Singularity.sol#L322
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/markets/singularity/Singularity.sol#L351


## Recommended Mitigation Steps
Introduce a deadline parameter to all functions which potentially perform a swap on the user’s behalf.