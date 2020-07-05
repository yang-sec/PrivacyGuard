# To compile and deploy a contract in the hard way 

## Use solidity to write the contract source code
Contract filename: X.sol
Contract name: X

## Generate Javascript file from the Solidity source code file:
echo "var ContractOutput=`solc --optimize --combined-json abi,bin,interface X.sol`" > X.js

## Compile and deploy the contract in a geth console (in the same folder as with the .js file):
loadScript('X.js');
var ContractAbi = ContractOutput.contracts['X.sol:X'].abi;
var Contract = eth.contract(JSON.parse(ContractAbi));
var BinCode = "0x" + ContractOutput.contracts['X.sol:X'].bin;
personal.unlockAccount("0x...");
var deployTransationObject = { from: "0x...", data: BinCode, gas: 2000000 };
var Instance = Contract.new(deployTransationObject);

## Interact with the deployed contract
var Address = eth.getTransactionReceipt(Instance.transactionHash).contractAddress;
var ThisContract = Contract.at(Address);



# To access a contract with source code and contract address

## Generate Javascript file in the contract folder:
echo "var ContractOutput=`solc --optimize --combined-json abi,bin,interface X.sol`" > X.js

## Compile and access the contract in a geth console
loadScript('X.js');
var ContractAbi = ContractOutput.contracts['X.sol:X'].abi;
var Contract = eth.contract(JSON.parse(ContractAbi));
var ThisContract = Contract.at("0x...");