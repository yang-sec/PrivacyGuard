# PrivacyGuard

## Entities to be run in the cloud:
- iDA (iDataAgent)
- DB (Data Broker)
- CEE (Contract Execution Environment)

## Entities to be run remotely
- DC (Data Consumer)
- DO (Data Owner)

## System requirements
- OS: Ubuntu 16.04 LTS
- Intel SGX driver, PSW, SDK
- Put the libsecp256k1.a inside $(SGX_SDK)/lib64

## Deployed contracts (on Ethereum Rinkeby)
DataBroker:  0x7CAC532e3E93666247a56D987e25AEa5050B8cee
DataOwner:   0x208D3CEdFE8918298A726264B578A9BA2AE8c85B

## System workflow for single data usage case with 1 DO, 1 iDA, 1 CEE
1. DO publishes its data usage policy through Ethereum smart contracts.
2. DO remotely attests iDA's enclave.
3. DC observes DO's contract from blockchain and parses the policy.
4. DC invokes the smart contract by sending a transaction with the required deposit amount to call the contract's request() function.
5. DC sends a REQUEST message to DO's iDataAgent.
6. iDataAgent checks DC's deposit amount in the contract and then deploys CEE.
7. iDataAgent and DC remotely attest CEE's enclave.
8. With the secure channel establish by step 6, iDataAgent provisions DO's data decryption key to CEE and DC provisions its signing key to CEE.
9. CEE performs data operation.
10. CEE commits the data usage by sending a transaction to call the contract's record() function, securely provisions the result to DC, and then destructs the enclave. Note that the transaction is signed inside the enclave, and then published in the form of raw transaction hex.

## Misc
CEE_Rust needs to be run in sgx-rust docker
