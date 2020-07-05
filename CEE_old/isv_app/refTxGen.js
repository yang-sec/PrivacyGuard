// The orginal full tx generation process of geth
var Web3 = require('web3');
var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
// var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
var tx = require('ethereumjs-tx');

// var privateKey = '0xc0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de';
// var publicKey = util.bufferToHex(util.privateToPublic(privateKey));
// console.log(publicKey);
// var address = '0x' + util.bufferToHex(util.sha3(publicKey)).slice(26); //0x53ae893e4b22d707943299a8d0c844df0e3d5557


var rawTx = {
    nonce: web3.utils.numberToHex('0'),
    gasPrice: web3.utils.numberToHex('20000000000'),
    gasLimit: web3.utils.numberToHex('100000'),
    to: '0x687422eEA2cB73B5d3e242bA5456b782919AFc85',
    value: web3.utils.numberToHex('0'),
    data: '0xc0de'
};
var p = new Buffer('c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de', 'hex');


var transaction = new tx(rawTx);

// console.log('0x' + transaction.serialize().toString('hex'));

console.log('\nTransaction cefore signing:\n', transaction);

transaction.sign(p); // This step needs to be done in the enclave

console.log('\nTransaction after signing:\n', transaction);

// console.log('from: '+ transaction.from.toString('hex'));

var RawTxHex = '0x' + transaction.serialize().toString('hex'); // This is what we need to feed the api

// // Send the raw transaction hex
// web3.eth.sendSignedTransaction(RawTxHex, function (err, hash) {
// 	if (err) {
// 		console.log(err);
// 	}
// 	else {
// 		console.log(hash);
// 	}
// });

console.log('\n- Raw Transaction Hex:\n' + RawTxHex);
var txHash = util.bufferToHex(util.sha3(RawTxHex));
console.log('\n- Transaction hash:\n' + txHash);