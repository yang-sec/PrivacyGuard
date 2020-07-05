// The orginal full tx generation process of geth
var Web3 = require('web3');
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
var tx = require('ethereumjs-tx');

var rawTx = {
    nonce: web3.utils.numberToHex('1'),
    gasPrice: web3.utils.numberToHex('20000000000'),
    gasLimit: web3.utils.numberToHex('100000'),
    to: '0xe81f56753c8a0096458bab4bb358574268454b05',
    value: web3.utils.numberToHex('1000000000000000000'), // 1 ether
    data: '0xc0de'
};
var p = new Buffer('fcfc028c752996a2d29a5e2f1c1acaee2fe05892d38f7338059ce844b80819de', 'hex');


var transaction = new tx(rawTx);

// console.log('0x' + transaction.serialize().toString('hex'));

console.log('\nTransaction cefore signing:\n', transaction);

transaction.sign(p); // This step needs to be done in the enclave

console.log('\nTransaction after signing:\n', transaction);

// console.log('from: '+ transaction.from.toString('hex'));

var RawTxHex = '0x' + transaction.serialize().toString('hex'); // This is what we need to feed the api

// Send the raw transaction hex
web3.eth.sendSignedTransaction(RawTxHex, function (err, hash) {
	if (err) {
		console.log(err);
	}
	else {
		console.log(hash);
	}
});

console.log('\n- Raw Transaction Hex:\n' + RawTxHex);
var txHash = util.bufferToHex(util.sha3(RawTxHex));
console.log('\n- Transaction hash:\n');