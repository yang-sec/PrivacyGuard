// The orginal full tx generation process of geth
var Web3 = require('web3');
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
var tx = require('ethereumjs-tx');


var p = new Buffer('6307a6a04aa0e59aa308d64073ddbe28c81914a1e96353d7c89aa6c88cb611a4', 'hex'); // DB/iDA' Ethereum private key
var address = '0x0a4a2f95e8625eb07a67f8dfa0cd566c515a01c3'; // DB/iDA's Ethereum address

var argv = process.argv;

web3.eth.getTransactionCount(address).then(function (res, err){
	if (err) {
		console.log('error: ' + err);

	}
	else {
		// console.log('success: ' + res);
		var txCount = res;
		// console.log(txCount);

		var rawTx = {
		    nonce: web3.utils.numberToHex(txCount),
		    gasPrice: web3.utils.numberToHex(argv[2]),
		    gasLimit: web3.utils.numberToHex(argv[3]),
		    to: argv[4], // DO's address
		    value: web3.utils.numberToHex(argv[5]), // 0.01 ether
		    data: argv[6]
		};

		var transaction = new tx(rawTx);
		transaction.sign(p); // This step needs to be done in the enclave
		var RawTxHex = '0x' + transaction.serialize().toString('hex'); // This is what we need to feed the api
		console.log('\nRawTxHex:\n' + RawTxHex);

		// Send the raw transaction hex
		// web3.eth.sendSignedTransaction(RawTxHex, function (err, hash) {
		// 	if (err) {
		// 		console.log(err);
		// 	}
		// 	else {
		// 		console.log('\nTransaction hash: ' + hash);
		// 	}
		// });

		web3.eth.sendSignedTransaction(RawTxHex).on('receipt', console.log);
	}
});