| Severity | Title |
| -------- | -------- | 
|H-01 |User will lose their shares permanently if they delegate to zero address|
|M-01 |Potential frontrunning in setDrawManager.|
|M-02 |The number of tiers will always expand if canary tier is claimed, even if the _claimExpansionThreshold is not met.|
|M-03 |Incorrect implementation of ERC-2612 |

## [H-01] User will lose their shares permanently if they delegate to zero address 

## Vulnerability details
### Impact
User will lose their shares permanently if they delegate to zero address due to logic inconsistency.
### Proof of Concept
https://github.com/GenerationSoftware/pt-v5-twab-controller/blob/0145eeac23301ee5338c659422dd6d69234f5d50/src/TwabController.sol#L612-L627

1. When a user is delegating to zero address, _delegateAmount of the user will be decreased to zero.
```
function _transferDelegateBalance(
    address _vault,
    address _fromDelegate,
    address _toDelegate,
    uint96 _amount
) internal {
    // If we are transferring tokens from a delegated account to an undelegated account
    if (_fromDelegate != address(0) && _fromDelegate != SPONSORSHIP_ADDRESS) {
        _decreaseBalances(_vault, _fromDelegate, 0, _amount);

        // If we are delegating to the zero address, decrease total supply
        // If we are delegating to the sponsorship address, decrease total supply
        if (_toDelegate == address(0) || _toDelegate == SPONSORSHIP_ADDRESS) {
            _decreaseTotalSupplyBalances(_vault, 0, _amount);
        }
    }

    // If we are transferring tokens from an undelegated account to a delegated account
    if (_toDelegate != address(0) && _toDelegate != SPONSORSHIP_ADDRESS) {
        _increaseBalances(_vault, _toDelegate, 0, _amount);

        // If we are removing delegation from the zero address, increase total supply
        // If we are removing delegation from the sponsorship address, increase total supply
        if (_fromDelegate == address(0) || _fromDelegate == SPONSORSHIP_ADDRESS) {
            _increaseTotalSupplyBalances(_vault, 0, _amount);
        }
    }
}
```
2. When the user is trying to delegate to another address, _fromDelegate will still be the user. _delegateAmount of the user will be decreased by amount again, despite it is already zero. So any attempts to redelegate to another address will fail.
```
function _delegateOf(address _vault, address _user) internal view returns (address) {
    address _userDelegate;

    if (_user != address(0)) {
        _userDelegate = delegates[_vault][_user];

        // If the user has not delegated, then the user is the delegate
        if (_userDelegate == address(0)) {
            _userDelegate = _user;
        }
    }

    return _userDelegate;
}
```
3. If the user is trying to transfer the balance, _delegateAmount still needs to be decreased by amount. So any attempts to transfer balance will fail.
```
function _transferBalance(address _vault, address _from, address _to, uint96 _amount) internal {
    if (_from == _to) {
        return;
    }

    // If we are transferring tokens from a delegated account to an undelegated account
    address _fromDelegate = _delegateOf(_vault, _from);
    address _toDelegate = _delegateOf(_vault, _to);
    if (_from != address(0)) {
        bool _isFromDelegate = _fromDelegate == _from;

        _decreaseBalances(_vault, _from, _amount, _isFromDelegate ? _amount : 0);
        ......
```
## Recommended Mitigation Steps
Add a check to prevent users from delegating to zero address.
```
function _delegate(address _vault, address _from, address _to) internal {
    address _currentDelegate = _delegateOf(_vault, _from);
    if (_to == _currentDelegate) {
        revert SameDelegateAlreadySet(_to);
    }

    if (_to == address(0)) {
        _to = SPONSORSHIP_ADDRESS;
    }

    delegates[_vault][_from] = _to;

    _transferDelegateBalance(
        _vault,
        _currentDelegate,
        _to,
        uint96(userObservations[_vault][_from].details.balance)
    );

    emit Delegated(_vault, _from, _to);
}
```

## [M-01]  Potential frontrunning in setDrawManager.

## Vulnerability details
### Impact
In the code comments, it is mentioned:
```
  /// @notice Allows a caller to set the DrawManager if not already set.
  /// @dev Notice that this can be front-run: make sure to verify the drawManager after construction
  /// @param _drawManager The draw manager
```
setDrawManager allows the caller to set the DrawManager address without performing permission verification, only checking for the zero address.

As long as the current DrawManager address is not the zero address, anyone can call this function to change the DrawManager address.

This may result in unauthorized individuals or contracts being able to call withdrawReserve() to withdraw tokens.


### Proof of Concept
https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/4bc8a12b857856828c018510b5500d722b79ca3a/src/PrizePool.sol#L296-L306


## Recommended Mitigation Steps
Add appropriate permission verification to the setDrawManager function. Check the caller's permissions.



## [M-02]  The number of tiers will always expand if canary tier is claimed, even if the _claimExpansionThreshold is not met. 

## Vulnerability details
### Impact
The number of tiers will always expand if someone has claimed canary tier, even if the _claimExpansionThreshold is not met.
### Proof of Concept
https://github.com/GenerationSoftware/pt-v5-prize-pool/blob/4bc8a12b857856828c018510b5500d722b79ca3a/src/PrizePool.sol#L784

```
function _computeNextNumberOfTiers(uint8 _numTiers) internal view returns (uint8) {
    UD2x18 _claimExpansionThreshold = claimExpansionThreshold;

    uint8 _nextNumberOfTiers = largestTierClaimed + 2; // canary tier, then length
    _nextNumberOfTiers = _nextNumberOfTiers > MINIMUM_NUMBER_OF_TIERS
        ? _nextNumberOfTiers
        : MINIMUM_NUMBER_OF_TIERS;

    if (_nextNumberOfTiers >= MAXIMUM_NUMBER_OF_TIERS) {
        return MAXIMUM_NUMBER_OF_TIERS;
    }

    // check to see if we need to expand the number of tiers
    if (
        _nextNumberOfTiers >= _numTiers &&
        canaryClaimCount >=
        fromUD60x18(
            intoUD60x18(_claimExpansionThreshold).mul(_canaryPrizeCountFractional(_numTiers).floor())
        ) &&
        claimCount >=
        fromUD60x18(
            intoUD60x18(_claimExpansionThreshold).mul(toUD60x18(_estimatedPrizeCount(_numTiers)))
        )
    ) {
        // increase the number of tiers to include a new tier
        _nextNumberOfTiers = _numTiers + 1;
    }

    return _nextNumberOfTiers;
}
```

If someone has claimed canary tier, largestTierClaimed will be _numTiers - 1, and _nextNumberOfTiers will be _numTiers + 1. So even if the claim count is below expansion threshold, the return value will still be _numTiers + 1.
## Recommended Mitigation Steps
```
uint8 _nextNumberOfTiers = largestTierClaimed + 1;
```

## [M-03] Incorrect implementation of ERC-2612

## Vulnerability details
### Impact
The implementation of ERC20Permit functions deviates from the original intention of ERC-2612.
### Proof of Concept
https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L427-L437

"However, a limiting factor in this design stems from the fact that the EIP-20 approve function itself is defined in terms of msg.sender. This means that the user's initial action involving EIP-20 tokens must be performed by an externally owned account (EOA) (but see Note below). If the user needs to interact with a smart contract, then they need to make 2 transactions (approve and the smart contract call which will internally call transferFrom). Even in the simple use case of paying another person, they need to hold ETH to pay for transaction gas costs.
This ERC extends the EIP-20 standard with a new function permit, which allows users to modify the allowance mapping using a signed message, instead of through msg.sender."

Source: ERC-2612: Permit Extension for EIP-20 Signed Approvals
```
function depositWithPermit(
    uint256 _assets,
    address _receiver,
    uint256 _deadline,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
) external returns (uint256) {
    _permit(IERC20Permit(asset()), msg.sender, address(this), _assets, _deadline, _v, _r, _s);
    return deposit(_assets, _receiver);
}
```
However, the second parameter of _permit is still msg.sender, which means that it is impossible to achieve the goal of "allows users to modify the allowance mapping using a signed message, instead of through msg.sender."
https://eips.ethereum.org/EIPS/eip-2612

## Recommended Mitigation Steps
```
function depositWithPermit(
    address _owner,
    uint256 _assets,
    address _receiver,
    uint256 _deadline,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
) external returns (uint256) {
    _permit(IERC20Permit(asset()), _owner, address(this), _assets, _deadline, _v, _r, _s);
    return deposit(_assets, _receiver);
}
```