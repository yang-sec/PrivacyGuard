// The orginal full tx generation process of geth
var Web3 = require('web3');
var util = require('ethereumjs-util');
var tx = require('ethereumjs-tx');
// var solc = require("solc");
// var fs = require('fs');

var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));

var argv = process.argv;

var address = argv[2];





// var DataOwnerOutput = require('./DataOwner_v2');
// var DataOwnerOutput = require('./DataOwner_v2.js');

// console.log(DataOwnerOutput);

// console.log(DataOwnerOutput);

// var ContractAbi = DataOwnerOutput.contracts['DataOwner_v2.sol:DataOwner_v2'].abi;

var ContractAbi = "[{\"constant\":true,\"inputs\":[],\"name\":\"status\",\"outputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"Data_List_Length\",\"outputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"K_result_hash\",\"type\":\"bytes32\"}],\"name\":\"computationComplete\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"name\":\"dataRecordList\",\"outputs\":[{\"name\":\"DC\",\"type\":\"address\"},{\"name\":\"op\",\"type\":\"int256\"},{\"name\":\"DC_CompleteTime\",\"type\":\"uint256\"},{\"name\":\"TransactionTime\",\"type\":\"uint256\"},{\"name\":\"K_result\",\"type\":\"string\"},{\"name\":\"K_result_hash\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"K_result\",\"type\":\"string\"}],\"name\":\"completeTransaction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"name\":\"dataSourceList\",\"outputs\":[{\"name\":\"data\",\"type\":\"int256\"},{\"name\":\"op\",\"type\":\"int256\"},{\"name\":\"price\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"data_range_start\",\"type\":\"int256\"},{\"name\":\"data_range_end\",\"type\":\"int256\"},{\"name\":\"op\",\"type\":\"int256\"}],\"name\":\"request\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"revoke\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"taskCount\",\"outputs\":[{\"name\":\"\",\"type\":\"int256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"data\",\"type\":\"int256\"},{\"name\":\"op\",\"type\":\"int256\"},{\"name\":\"price\",\"type\":\"uint256\"},{\"name\":\"DC\",\"type\":\"address\"},{\"name\":\"DC_action\",\"type\":\"int256\"}],\"name\":\"register\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"waitTimeOut\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"cancel\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"DO\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]";

var Contract = new web3.eth.Contract(JSON.parse(ContractAbi), address, {
	from: '0x0a4a2f95e8625eb07a67f8dfa0cd566c515a01c3', // default from address
    gasPrice: '20000000000' // default gas price in wei, 20 gwei in this case
});

console.log('Contract status: ');
Contract.methods.status().call().then(console.log);

// console.log('Contract dataRecordList: ');
// Contract.methods.dataRecordList(4).call().then(console.log);
