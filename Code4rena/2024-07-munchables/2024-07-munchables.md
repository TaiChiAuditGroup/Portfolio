
| Severity | Title |
| -------- | -------- | 
|H-01 |Incorrect PlotId Check in _farmPlots|



## [H-01]  Incorrect PlotId Check in _farmPlots
## Vulnerability details
### Impact
In the _farmPlots function, the check for the dirty state is incorrect due to an off-by-one error. This error allows a plot that exceeds the number of qualified plots to bypass the check and not be marked as dirty.
### Proof of Concept
https://github.com/code-423n4/2024-07-munchables/blob/94cf468aaabf526b7a8319f7eba34014ccebe7b9/src/managers/LandManager.sol#L258-L261

In the _farmPlots function, the check for the dirty state is performed as follows:
```
            if (_getNumPlots(landlord) < _toiler.plotId) {
                timestamp = plotMetadata[landlord].lastUpdated;
                toilerState[tokenId].dirty = true;
            }
```
The _getNumPlots(landlord) function returns the number of plots allowed for the landlord. However, if _toiler.plotId == _getNumPlots(landlord), it actually exceeds the limit of plots but is still regarded as valid due to the use of the < operator. Since plotId can be 0, the correct comparison should use the <= operator.

This can be verified in another check.
```
if (plotId >= totalPlotsAvail) revert PlotTooHighError();
```
As a result, this error allows a plot that exceeds the number of qualified plots to bypass the check and not be marked as dirty.
## Recommended Mitigation Steps
Change _getNumPlots(landlord) < _toiler.plotId to _getNumPlots(landlord) <= _toiler.plotId