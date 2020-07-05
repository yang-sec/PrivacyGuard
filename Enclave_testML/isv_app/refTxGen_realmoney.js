// The orginal full tx generation process of geth
var Web3 = require('web3');
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
var tx = require('ethereumjs-tx');

var p = new Buffer('fcfc028c752996a2d29a5e2f1c1acaee2fe05892d38f7338059ce844b80819de', 'hex');
var address = '0x65843be2dd4ad3bc966584e2fcbb38838d49054b';


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
		    gasPrice: web3.utils.numberToHex('1000000000'),
		    gasLimit: web3.utils.numberToHex('200000'),
		    to: '0x1dA00C84C35b56f93B55a5A80724EC0fae8e71E4', // DO's address
		    value: web3.utils.numberToHex('0'), // 0.01 ether
		    data: '0x266cf109'
		};

		var transaction = new tx(rawTx);

		// console.log('0x' + transaction.serialize().toString('hex'));

		// console.log('\nTransaction cefore signing:\n', transaction);
		transaction.sign(p); // This step needs to be done in the enclave
		console.log('\nTransaction after signing:\n', transaction);
		// console.log('from: '+ transaction.from.toString('hex'));

		var RawTxHex = '0x' + transaction.serialize().toString('hex'); // This is what we need to feed the api

		console.log('RawTxHex:\n' + RawTxHex);

		
		// // Send the raw transaction hex
		// web3.eth.sendSignedTransaction(RawTxHex, function (err, hash) {
		// 	if (err) {
		// 		console.log(err);
		// 	}
		// 	else {
		// 		console.log('Transaction hash: ' + hash);
		// 	}
		// });
	}
});





// var transaction = new tx(rawTx);

// // console.log('0x' + transaction.serialize().toString('hex'));

// console.log('\nTransaction cefore signing:\n', transaction);

// transaction.sign(p); // This step needs to be done in the enclave

// console.log('\nTransaction after signing:\n', transaction);

// // console.log('from: '+ transaction.from.toString('hex'));

// var RawTxHex = '0x' + transaction.serialize().toString('hex'); // This is what we need to feed the api

// // Send the raw transaction hex
// web3.eth.sendSignedTransaction(RawTxHex, function (err, hash) {
// 	if (err) {
// 		console.log(err);
// 	}
// 	else {
// 		console.log(hash);
// 	}
// });

// console.log('\n- Raw Transaction Hex:\n' + RawTxHex);
// var txHash = util.bufferToHex(util.sha3(RawTxHex));
// console.log('\n- Transaction hash:\n');

// 0xf86819843b9aca0083030d40941da00c84c35b56f93b55a5a80724ec0fae8e71e48084266cf109 1c a0d81325c6b19cd908ce8d99b11d1184d503705efb0696b13bdf2a66b4f2dc07a2a0547a0f30b2c2f6bc9610c99f350b5cdb8893847a9bfca91ba7b2ad4e81718aa7
// 0xf86819843b9aca0083030d40941da00c84c35b56f93b55a5a80724ec0fae8e71e48084266cf109 1b a0d81325c6b19cd908ce8d99b11d1184d503705efb0696b13bdf2a66b4f2dc07a2a0547a0f30b2c2f6bc9610c99f350b5cdb8893847a9bfca91ba7b2ad4e81718aa7
