# Configuration and Useful Notes

## Network
1 DataBroker (DB)
1 DataConsumer (DC)
N DataOwners (DO)
N iDataAgents (iDA)

## Ethereum rinkeby testnet nodes:
DB/iDA address:  0x0a4a2f95e8625eb07a67f8dfa0cd566c515a01c3
   private key:  6307a6a04aa0e59aa308d64073ddbe28c81914a1e96353d7c89aa6c88cb611a4
DC address:      0x65843BE2Dd4ad3bC966584E2Fcbb38838d49054B
   private key:  fcfc028c752996a2d29a5e2f1c1acaee2fe05892d38f7338059ce844b80819de
DO1 address:     0xac5d434a4a9cf170baaa5d1be12b48c7fe358fa0
   private key:  3bdc966729b1c929efa2053c40c77f31cf2e9048950c8f86af937780e5686dbd

## Created contracts
DistributeFund: 0x6F8E9B88FA2D61a88034321E46fA98205ddaDb76
DataBroker_v1:  0x058943a672aF6a2D06b4374eD39544DEF4bC039C
DataBroker_v2:  0x669eEf9F9DF482C8f9b6E2087E890c945d7A7d8D
DataBroker_v3:  0x7CAC532e3E93666247a56D987e25AEa5050B8cee
DataOwner_v1:   0x992d8b41E547D40920172E5369fe0fA0d769BC5c
DataOwner_v2:   0x208D3CEdFE8918298A726264B578A9BA2AE8c85B

## Keccak-256 hashes (no parenthesis)
cc527740 <= "register(int256,int256,uint256,address,int256)"
80ac1323 <= "register(int256,uint256,address,int256)"
7022b58e <= "confirm()"
ad352967 <= "request(int256,int256,int256)"
4092a8d9 <= "computationComplete(bytes32)"
8438e7ea <= "completeTransaction(string)"
ea8a1af0 <= "cancel()"
b6549f75 <= "revoke()"