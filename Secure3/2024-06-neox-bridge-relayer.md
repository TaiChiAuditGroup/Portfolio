| Severity | Title |
| -------- | -------- | 
|L-01 |Potential DoS in signature processors due to lack of timeout|

# [L-01] Potential DoS in signature processors due to lack of timeout

## Location

https://github.com/Secure3Audit/code_NeoX_Bridge_Relayer/blob/479c9618949f4666c102094cffad46df0336fa32/code/signatureprocessor/deposit.go#L72

https://github.com/Secure3Audit/code_NeoX_Bridge_Relayer/blob/479c9618949f4666c102094cffad46df0336fa32/code/signatureprocessor/deposit.go#L147

https://github.com/Secure3Audit/code_NeoX_Bridge_Relayer/blob/479c9618949f4666c102094cffad46df0336fa32/code/signatureprocessor/withdrawal.go#L72

https://github.com/Secure3Audit/code_NeoX_Bridge_Relayer/blob/479c9618949f4666c102094cffad46df0336fa32/code/signatureprocessor/withdrawal.go#L146

## Description

In signature processors for both deposit and withdrawal, the code creates a channel called  `awaitAckChannel` and calls `p.broker.PublishTokenDeposits` in a goroutine. After the call, the code waits acknowledgement from broker:

```go
<-awaitAckChannel
```

The problem here is that there is no timeout for this wait. If the broker does not ACK this call, signature processor is going to wait for this response forever and put the system into a DoS state.

## Recommendation

Add timeout to this code. Timeout can be implemented with  `time.After() `. After a specific amount of time, the signature processor should throw error or exit from the call stack gracefully.
