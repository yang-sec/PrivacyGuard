*Dear users, we kindly note that this repo provides a proof-of-concept implementation of PrivacyGuard, not a product release. An older generation (2.0.1) of Intel SGX is used. We recommend readers to use our code as a workflow reference, rather than a product baseline. Thanks!*

## Entities to be run in the cloud:
- iDA (iDataAgent)
- DB (Data Broker)
- CEE (Contract Execution Environment)

## Entities to be run remotely
- DC (Data Consumer)
- DO (Data Owner)

## System requirements
- OS: Ubuntu 16.04 LTS
- Intel SGX driver, PSW, SDK (see https://github.com/intel/linux-sgx)

## Deployed contracts (on Ethereum Rinkeby)
- DataBroker Contract address:  0x7CAC532e3E93666247a56D987e25AEa5050B8cee
- DataOwner Contract address:   0x208D3CEdFE8918298A726264B578A9BA2AE8c85B
(Search contract addresses at https://rinkeby.etherscan.io/)

## How to run
- To build all programs: bash ./allmake
- To clean all programs: bash ./allclean
- Executables will appear in individual directories.

## System workflow for single data usage case with 1 DO, 1 iDA, 1 CEE
1. DO publishes its data usage policy through Ethereum smart contracts.
2. DO remotely attests iDA's enclave.
3. DC observes DO's contract from blockchain and parses the policy.
4. DC invokes the smart contract by sending a transaction with the required deposit amount to call the contract's request() function.
5. DC sends a REQUEST message to DO's iDataAgent.
6. iDataAgent checks DC's deposit amount in the contract and then deploys CEE.
7. iDataAgent and DC remotely attest CEE's enclave.
8. With the secure channel establish by step 6, iDataAgent provisions DO's data decryption key K_data to CEE.
9. CEE performs data operation.
10. CEE securely provisions C_result, Hash(C_result), Hash(K_result) to DC; K_result to iDA. Then destructs the enclave.
11. DC calls the contract's computationComplete() function with Hash(K_result).
12. DO calls the contract's completeTransaction() function with K_result.

## Test the Enclave Program ML Model Training Only (i.e., off-chain execution)
- Go to Enclave_testML and there should be a similar executable, which only instantiates the in-enclave ML training functions.
- Try option 3,4,5,6 to reproduce the enclave benchmark results in our paper.

## Publication
The paper titled "PrivacyGuard: Enforcing Private Data Usage Control with Blockchain and Attested Off-chain Contract Execution" has appeared in ESORICS 2020, Sep 14-18, 2020.
