| Severity | Title |
| -------- | -------- | 
|H-01 |Attacker can call addCollateral with share=0 to steal other's collateral|
|H-02 |When a cross chain request fails, bridged asset will be permanently locked because an extra revert is made after transfer. |
|H-03 |_unwrap always will revert in leverageDownInternal|
|H-04 |User's asset can be stolen when retrieveFromStrategy|
|H-05 |Incorrect amount of USDO is burned when repaying debt on BigBang, leading to excessive Penrose fee|
|M-01 |The quotes from Curve may be subject to manipulation|
|M-02 |Missing deadline checks allow pending transactions to be maliciously executed|
|M-03 |multiHopSell and multiHopBuy can be frontrunned with high slippage tolerance|
|M-04 |User could be forced to withdraw more amount than desired when calling retrieveFromStrategy|
|M-05 |Function strategyWithdraw should _burn instead of _debitFrom|
|M-06 |totalBorrow.base should not be used when comparing total borrow with borrow cap|

## [H-01]  Attacker can call addCollateral with share=0 to steal other's collateral 

## Vulnerability details
### Impact
The modifier allowedBorrow only checks that share is less than allowance, but both amount and share can be specified when calling addCollateral. As a result, attacker can call function addCollateral with a zero share and a nonzero amount to bypass the check.
### Proof of Concept
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/2286f80f928f41c8bc189d0657d74ba83286c668/contracts/markets/singularity/SGLLendingCommon.sol#L23-L25

```
function addCollateral(
    address from,
    address to,
    bool skim,
    uint256 amount,
    uint256 share
) public notPaused allowedBorrow(from, share) {
    _addCollateral(from, to, skim, amount, share);
}

function _allowedBorrow(address from, uint share) internal {
    if (from != msg.sender) {
        if (allowanceBorrow[from][msg.sender] < share) {
            revert NotApproved(from, msg.sender);
        }
        allowanceBorrow[from][msg.sender] -= share;
    }
}

function _addCollateral(
    address from,
    address to,
    bool skim,
    uint256 amount,
    uint256 share
) internal {
    if (share == 0) {
        share = yieldBox.toShare(collateralId, amount, false);
    }
    userCollateralShare[to] += share;
    uint256 oldTotalCollateralShare = totalCollateralShare;
    totalCollateralShare = oldTotalCollateralShare + share;
    _addTokens(
        from,
        to,
        collateralId,
        share,
        oldTotalCollateralShare,
        skim
    );
    emit LogAddCollateral(skim ? address(yieldBox) : from, to, share);
}
```
When a innocent user tries to add collateral, they need to first approve or permit Singularity to spend YieldBox asset. If attacker detects such transactions, he can immediately call addCollateral with {from: user, to: attacker, skim: false, amount: _amount, share: 0} to steal the user's collateral by adding collateral for himself.

The attack also applies to any other users who have approved Singularity to spend YieldBox collateral.
## Recommended Mitigation Steps
```
function addCollateral(
    address from,
    address to,
    bool skim,
    uint256 amount,
    uint256 share
) public notPaused {
    if (share == 0) {
        share = yieldBox.toShare(collateralId, amount, false);
    }
    _allowedBorrow(from, share)
    _addCollateral(from, to, skim, 0, share);
}
```


## [H-02]  When a cross chain request fails, bridged asset will be permanently locked because an extra revert is made after transfer. 

## Vulnerability details
### Impact
When a cross chain tx fails, bridged asset should be directly transfered to receiver. However, an extra revert is made after the transfer. As a result, the user will not be able to get the asset back by any means.
```
    (bool success, bytes memory reason) = module.delegatecall(
        abi.encodeWithSelector(
            this.leverageDownInternal.selector,
            amount,
            swapData,
            externalData,
            lzData,
            leverageFor
        )
    );

    if (!success) {
        if (balanceAfter - balanceBefore >= amount) {
            IERC20(address(this)).safeTransfer(leverageFor, amount);
        }
        revert(_getRevertMsg(reason)); //forward revert because it's handled by the main executor
    }
```
### Proof of Concept
https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L195-L200
A cross chain request can fail due to various reasons, such as high slippage, wrong parameters. When the request involves debiting and crediting USDO(TOFT), if the module execution fails, we need to directly transfer the balance to user. However, in current implementation, an extra revert is made after the transfer, so even if user retries, the tx will still always revert, which means the asset is permanently locked.
## Recommended Mitigation Steps
```
if (!success) {
    if (balanceAfter - balanceBefore >= amount) {
        IERC20(address(this)).safeTransfer(leverageFor, amount);
    } else {
        revert(_getRevertMsg(reason)); //forward revert because it's handled by the main executor
    }
}
```

## [H-03]  _unwrap always will revert in leverageDownInternal

## Vulnerability details
### Impact
When calling _unwrap in function leverageDownInternal, msg.sender is actually LayerZero Endpoint as context remains the same during delegate call. As a result, the _unwrap will fail.
### Proof of Concept
https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L212
```
else if (packetType == PT_LEVERAGE_MARKET_DOWN) {
    _executeOnDestination(
        Module.Leverage,
        abi.encodeWithSelector(
            BaseTOFTLeverageModule.leverageDown.selector,
            leverageModule,
            _srcChainId,
            _srcAddress,
            _nonce,
            _payload
        ),
        _srcChainId,
        _srcAddress,
        _nonce,
        _payload
    );
}

function _executeModule(
    Module _module,
    bytes memory _data,
    bool _forwardRevert
) private returns (bool success, bytes memory returnData) {
    success = true;
    address module = _extractModule(_module);

    (success, returnData) = module.delegatecall(_data);
    if (!success && !_forwardRevert) {
        revert(_getRevertMsg(returnData));
    }
}

function leverageDown(
    address module,
    uint16 _srcChainId,
    bytes memory _srcAddress,
    uint64 _nonce,
    bytes memory _payload
) public {
    (
        ,
        ,
        uint256 amount,
        IUSDOBase.ILeverageSwapData memory swapData,
        IUSDOBase.ILeverageExternalContractsData memory externalData,
        IUSDOBase.ILeverageLZData memory lzData,
        address leverageFor
    ) = abi.decode(
        _payload,
        (
            uint16,
            bytes32,
            uint256,
            IUSDOBase.ILeverageSwapData,
            IUSDOBase.ILeverageExternalContractsData,
            IUSDOBase.ILeverageLZData,
            address
        )
    );

    uint256 balanceBefore = balanceOf(address(this));
    bool credited = creditedPackets[_srcChainId][_srcAddress][_nonce];
    if (!credited) {
        _creditTo(_srcChainId, address(this), amount);
        creditedPackets[_srcChainId][_srcAddress][_nonce] = true;
    }
    uint256 balanceAfter = balanceOf(address(this));

    (bool success, bytes memory reason) = module.delegatecall(
        abi.encodeWithSelector(
            this.leverageDownInternal.selector,
            amount,
            swapData,
            externalData,
            lzData,
            leverageFor
        )
    );

    if (!success) {
        if (balanceAfter - balanceBefore >= amount) {
            IERC20(address(this)).safeTransfer(leverageFor, amount);
        }
        revert(_getRevertMsg(reason)); //forward revert because it's handled by the main executor
    }

    emit ReceiveFromChain(_srcChainId, leverageFor, amount);
}

function leverageDownInternal(
    uint256 amount,
    IUSDOBase.ILeverageSwapData memory swapData,
    IUSDOBase.ILeverageExternalContractsData memory externalData,
    IUSDOBase.ILeverageLZData memory lzData,
    address leverageFor
) public payable {
    _unwrap(address(this), amount);
    // ......
}
```
As above, leverageDownInternal is delegate called by leverageDown and leverageDown is delegate called by _executeModule, so msg.sender in _unwrap will be LayerZero Endpoint, who calls lzReceive. As a result, the _unwrap will revert since the Endpoint has no token to burn.
```
function _unwrap(address _toAddress, uint256 _amount) private {
    _burn(msg.sender, _amount);

    if (erc20 == address(0)) {
        _safeTransferETH(_toAddress, _amount);
    } else {
        IERC20(erc20).safeTransfer(_toAddress, _amount);
    }
}
```
## Recommended Mitigation Steps
Call unwrap externally
```
address(this).unwrap(address(this), amount);
```

## [H-04]  User's asset can be stolen when retrieveFromStrategy
## Vulnerability details
### Impact
Cross chain request to retrieveFromStrategy can be frontrunned. Attacker can take advantage of the fact that input data amount and share can both be specified, and use two seperate transactions to steal user's asset.


### Proof of Concept
https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTStrategyModule.sol#L89-L120
```
function retrieveFromStrategy(
    address _from,
    uint256 amount,
    uint256 share,
    uint256 assetId,
    uint16 lzDstChainId,
    address zroPaymentAddress,
    bytes memory airdropAdapterParam
) external payable {
    require(amount > 0, "TOFT_0");

    bytes32 toAddress = LzLib.addressToBytes32(msg.sender);

    bytes memory lzPayload = abi.encode(
        PT_YB_RETRIEVE_STRAT,
        LzLib.addressToBytes32(_from),
        toAddress,
        amount,
        share,
        assetId,
        zroPaymentAddress
    );
    _lzSend(
        lzDstChainId,
        lzPayload,
        payable(msg.sender),
        zroPaymentAddress,
        airdropAdapterParam,
        msg.value
    );
    emit SendToChain(lzDstChainId, msg.sender, toAddress, amount);
}

function strategyWithdraw(
    uint16 _srcChainId,
    bytes memory _payload
) public {
    (
        ,
        bytes32 from,
        ,
        uint256 _amount,
        uint256 _share,
        uint256 _assetId,
        address _zroPaymentAddress
    ) = abi.decode(
            _payload,
            (uint16, bytes32, bytes32, uint256, uint256, uint256, address)
        );

    address _from = LzLib.bytes32ToAddress(from);
    _retrieveFromYieldBox(_assetId, _amount, _share, _from, address(this));

    _debitFrom(
        address(this),
        lzEndpoint.getChainId(),
        LzLib.addressToBytes32(address(this)),
        _amount
    );

    bytes memory lzSendBackPayload = _encodeSendPayload(
        from,
        _ld2sd(_amount)
    );
    _lzSend(
        _srcChainId,
        lzSendBackPayload,
        payable(this),
        _zroPaymentAddress,
        "",
        address(this).balance
    );
}
```
When a user initiates a cross chain request to retrieveFromStrategy, they need to sign a EIP712 permit to approve YieldBox for TOFT contract. Attacker can take the signature and frontrun the tx with two seperate transactions.
1. Call retrieveFromStrategy with {from: user, amount: 1 wei, share: user's balance, approvals:user's signature}. All of the user's share will be withdrawn but _debitFrom only burns 1 wei of TOFT. The extra TOFT will stay in the contract.
2. Call retrieveFromStrategy with {from: attacker, amount: TOFT's balance, share: 1 wei}. Only 1 wei of share needs to be withdrawn from attacker's yieldbox balance and attacker can receive all the detained (in step 1) TOFT.
```
    function _withdrawFungible(
        Asset storage asset,
        uint256 assetId,
        address from,
        address to,
        uint256 amount,
        uint256 share
    ) internal returns (uint256 amountOut, uint256 shareOut) {
        // Effects
        uint256 totalAmount = _tokenBalanceOf(asset);
        if (share == 0) {
            // value of the share paid could be lower than the amount paid due to rounding, in that case, add a share (Always round up)
            share = amount._toShares(totalSupply[assetId], totalAmount, true);
        } else {
            // amount may be lower than the value of share due to rounding, that's ok
            amount = share._toAmount(totalSupply[assetId], totalAmount, false);
        }
```
## Recommended Mitigation Steps
Only allow specifying amount.
```
function retrieveFromStrategy(
    address _from,
    uint256 amount,
--  uint256 share,
    uint256 assetId,
    uint16 lzDstChainId,
    address zroPaymentAddress,
    bytes memory airdropAdapterParam
)
```
## [H-05]  Incorrect amount of USDO is burned when repaying debt on BigBang, leading to excessive Penrose fee
## Vulnerability details
### Impact
When borrowing on BigBang, the interest that borrower pays goes to Penrose. This is achieved by keeping (amount - part) of USDO in BigBang. However, the interest should not be (amount - part), because the amount that user originally borrows is not part.
### Proof of Concept
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/2286f80f928f41c8bc189d0657d74ba83286c668/contracts/markets/bigBang/BigBang.sol#L730-L731
```
function _repay(
    address from,
    address to,
    uint256 part
) internal returns (uint256 amount) {
    (totalBorrow, amount) = totalBorrow.sub(part, true);

    userBorrowPart[to] -= part;

    uint256 toWithdraw = (amount - part); //acrrued
    uint256 toBurn = amount - toWithdraw;
    yieldBox.withdraw(assetId, from, address(this), amount, 0);
    //burn USDO
    if (toBurn > 0) {
        IUSDOBase(address(asset)).burn(address(this), toBurn);
    }

    emit LogRepay(from, to, amount, part);
}

function refreshPenroseFees(
    address
) external onlyOwner notPaused returns (uint256 feeShares) {
    uint256 balance = asset.balanceOf(address(this));
    totalFees += balance;
    feeShares = yieldBox.toShare(assetId, totalFees, false);
```
Suppose currently totalBorrow.base is 1000 and totalBorrow.elastic is 1200. Alice borrow 12 USD0, then userBorrowPart[Alice] is 10. Then Alice immediately repays the 12 USDO, and 2 USDO accrues as Penrose fee. This is incorrect since no interest has actually been generated. As a result, Penrose gets more fee than it deserves.
## Recommended Mitigation Steps
Track Penrose fee when accruing interest.


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

## [M-03] multiHopSell and multiHopBuy can be frontrunned with high slippage tolerance

## Vulnerability details
### Impact
multiHopSell and multiHopBuy can be frontrunned with high slippage tolerance. User may experince loss from a sandwich attack.
### Proof of Concept
https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L111-L146
When a user initiates a cross chain request to multiHopSell, they need to sign a EIP712 permit to approve borrow share for TOFT contract. Attacker can take the signature and frontrun the tx with same data except a lower swapData.amountOutMin.

Action flow is multiHopSell(local) -> leverageDown(local) -> lend(remote)
```
function leverageDownInternal(
    uint256 amount,
    IUSDOBase.ILeverageSwapData memory swapData,
    IUSDOBase.ILeverageExternalContractsData memory externalData,
    IUSDOBase.ILeverageLZData memory lzData,
    address leverageFor
) public payable {
    _unwrap(address(this), amount);

    //swap to USDO
    IERC20(erc20).approve(externalData.swapper, amount);
    ISwapper.SwapData memory _swapperData = ISwapper(externalData.swapper)
        .buildSwapData(erc20, swapData.tokenOut, amount, 0, false, false);
    (uint256 amountOut, ) = ISwapper(externalData.swapper).swap(
        _swapperData,
        swapData.amountOutMin,
        address(this),
        swapData.data
    );
```
As a result, user may experince loss from a sandwich attack. The attack applies to multiHopBuy in a similar way.
## Recommended Mitigation Steps
Set a maximum slippage.


## [M-04]  User could be forced to withdraw more amount than desired when calling retrieveFromStrategy

## Vulnerability details
### Impact
User could be forced to withdraw more amount than desired when calling retrieveFromStrategy, because they can not specify the amount of yieldbox balance to permit.
### Proof of Concept
https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTStrategyModule.sol#L89-L120
```
function retrieveFromStrategy(
    address _from,
    uint256 amount,
    uint256 share,
    uint256 assetId,
    uint16 lzDstChainId,
    address zroPaymentAddress,
    bytes memory airdropAdapterParam
) external payable {
    require(amount > 0, "TOFT_0");

    bytes32 toAddress = LzLib.addressToBytes32(msg.sender);

    bytes memory lzPayload = abi.encode(
        PT_YB_RETRIEVE_STRAT,
        LzLib.addressToBytes32(_from),
        toAddress,
        amount,
        share,
        assetId,
        zroPaymentAddress
    );
    _lzSend(
        lzDstChainId,
        lzPayload,
        payable(msg.sender),
        zroPaymentAddress,
        airdropAdapterParam,
        msg.value
    );
    emit SendToChain(lzDstChainId, msg.sender, toAddress, amount);
}
```
When a user initiates a cross chain request to retrieveFromStrategy, they need to sign a EIP712 permit to approve YieldBox for TOFT contract. Attacker can take the signature and frontrun the tx with {from: user, amount: larger than user wishes, approvals:user's signature} to force the user to withdraw more amount than desired.
If user forgets to revoke their approvals, the attack could also happen. Attacker can withdraw the user's yieldbox balance without being noticed.

Note: I believe it is a mistake that ICommonData.IApproval[] calldata approvals is missing at retrieveFromStrategy input param. Even though this is intended, the issue still exists as user still needs to approve YieldBox for TOFT contract in other way.
## Recommended Mitigation Steps
Add more refined allowance control for YieldBox. (just like erc20)

## [M-05]  Function strategyWithdraw should _burn instead of _debitFrom

## Vulnerability details
### Impact
In function strategyWithdraw, _debitFrom will fail because msg.sender(Endpoint) has no allowance. We should directly _burn TOFT here.


### Proof of Concept
https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTStrategyModule.sol#L208-L213
```
function strategyWithdraw(
    uint16 _srcChainId,
    bytes memory _payload
) public {
    (
        ,
        bytes32 from,
        ,
        uint256 _amount,
        uint256 _share,
        uint256 _assetId,
        address _zroPaymentAddress
    ) = abi.decode(
            _payload,
            (uint16, bytes32, bytes32, uint256, uint256, uint256, address)
        );

    address _from = LzLib.bytes32ToAddress(from);
    _retrieveFromYieldBox(_assetId, _amount, _share, _from, address(this));

    _debitFrom(
        address(this),
        lzEndpoint.getChainId(),
        LzLib.addressToBytes32(address(this)),
        _amount
    );

function _debitFrom(address _from, uint16, bytes32, uint _amount) internal virtual override returns (uint) {
    address spender = _msgSender();
    if (_from != spender) _spendAllowance(_from, spender, _amount);
    _burn(_from, _amount);
    return _amount;
}
```
strategyWithdraw is delegate called by function _nonblockingLzReceive, so msg.sender is LayerZero Endpoint. However, the Endpoint has not been approved, so _debitFrom(address(this),...) will revert.
## Recommended Mitigation Steps
Replace
```
_debitFrom(
    address(this),
    lzEndpoint.getChainId(),
    LzLib.addressToBytes32(address(this)),
    _amount
);
```

## [M-06]  totalBorrow.base should not be used when comparing total borrow with borrow cap

## Vulnerability details
### Impact
When comparing total borrow with borrow cap, totalBorrow.base is mistakenly used instead of totalBorrow.elastic, this will make actual borrow cap higher than expected.
### Proof of Concept
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/2286f80f928f41c8bc189d0657d74ba83286c668/contracts/markets/singularity/SGLLendingCommon.sol#L66-L69
```
function _borrow(
    address from,
    address to,
    uint256 amount
) internal returns (uint256 part, uint256 share) {
    uint256 feeAmount = (amount * borrowOpeningFee) / FEE_PRECISION; // A flat % fee is charged for any borrow

    (totalBorrow, part) = totalBorrow.add(amount + feeAmount, true);
    require(
        totalBorrowCap == 0 || totalBorrow.base <= totalBorrowCap,
        "SGL: borrow cap reached"
    );
```
The borrow cap is meant to set a limit for the total debt. When interest accures, totalBorrow.elastic increases while totalBorrow.base remains the same. If we need to limit the actual debt amount, we should use totalBorrow.elastic.
## Recommended Mitigation Steps
```
require(
    totalBorrowCap == 0 || totalBorrow.elastic <= totalBorrowCap,
    "SGL: borrow cap reached"
);
```
