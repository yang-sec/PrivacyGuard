// The orginal full tx generation process of geth
var Web3 = require('web3');
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
var tx = require('ethereumjs-tx');


var p = new Buffer('fcfc028c752996a2d29a5e2f1c1acaee2fe05892d38f7338059ce844b80819de', 'hex'); // DataConsumer's Ethereum private key
var address = '0x65843be2dd4ad3bc966584e2fcbb38838d49054b'; // DataConsumer's Ethereum address

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

/*
web3.eth.sendTransaction({from: '0x123...', data: '0x432...'})
.once('transactionHash', function(hash){ ... })
.once('receipt', function(receipt){ ... })
.on('confirmation', function(confNumber, receipt){ ... })
.on('error', function(error){ ... })
.then(function(receipt){
    // will be fired once the receipt is mined
});
*/