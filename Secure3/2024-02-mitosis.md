| Severity | Title |
| -------- | -------- | 
|M-01 |Unsupported Opcode in Multi-Chain Deployment|

# Unsupported Opcode in Multi-Chain Deployment

## Location

https://github.com/Secure3Audit/code_Mitosis/blob/8b51d801b80c783430220cd67bd9357303002b63/code/src/vault/BasicVault.sol#L2

https://github.com/Secure3Audit/code_Mitosis/blob/8b51d801b80c783430220cd67bd9357303002b63/code/src/vault/BasicVaultFactory.sol#L2

https://github.com/Secure3Audit/code_Mitosis/blob/8b51d801b80c783430220cd67bd9357303002b63/code/src/vault/Cap.sol#L2

https://github.com/Secure3Audit/code_Mitosis/blob/8b51d801b80c783430220cd67bd9357303002b63/code/src/helpers/ccdm/CCDMClient.sol#L2

https://github.com/Secure3Audit/code_Mitosis/blob/8b51d801b80c783430220cd67bd9357303002b63/code/src/helpers/ccdm/CCDMHost.sol#L2

## Description

The primary concern identified in the smart contracts relates to the Solidity compiler version used, specifically pragma solidity 0.8.23;. This version, along with every version after 0.8.19, introduces the use of the `PUSH0` opcode. This opcode is not universally supported across all Ethereum Virtual Machine (EVM)-based Layer 2 (L2) solutions. For instance, ZKSync, one of the targeted platforms for this protocol’s deployment, does not currently support the `PUSH0` opcode.

The consequence of this incompatibility is that contracts compiled with Solidity versions higher than 0.8.19 may not function correctly or fail to deploy on certain L2 solutions.

The impact of using a Solidity compiler version that includes the `PUSH0` opcode is significant for a protocol intended to operate across multiple EVM-based chains. Chains that do not support this opcode will not be able to execute the contracts as intended, resulting in a range of issues from minor malfunctions to complete deployment failures. This limitation directly affects the protocol’s goal of wide compatibility and interoperability, potentially excluding it from deployment on key L2 solutions like ZKsync.

## Recommendation

To mitigate this issue and ensure broader compatibility with various EVM-based L2 solutions, it is recommended to downgrade the Solidity compiler version used in the smart contracts to 0.8.19. This version does not utilize the `PUSH0` opcode and therefore maintains compatibility with a wider range of L2 solutions, including ZKsync.

```diff
- pragma solidity 0.8.23;
+ pragma solidity 0.8.19;
```

This change will allow the protocol to maintain a consistent and deterministic bytecode across all targeted chains, ensuring functionality and deployment success on platforms that currently do not support the `PUSH0` opcode.
