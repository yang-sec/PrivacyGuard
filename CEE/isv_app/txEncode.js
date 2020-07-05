var Web3 = require('web3');
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
var RLP = require('rlp');
var fs = require("fs");

// console.log(process.argv);
var address = '0x65843be2dd4ad3bc966584e2fcbb38838d49054b';

var argv = process.argv;


web3.eth.getTransactionCount(address).then(function (res, err){
	if (err) {
		console.log('error: ' + err);
	}
	else {
		var txCount = res;
		var nonce = '';
		var value = '';
		if(txCount != 0){
			nonce = web3.utils.numberToHex(txCount);
		}
		if(argv[5] != '0'){
			value = web3.utils.numberToHex(argv[5]);
		}

		var txNake = [
				nonce, 
				web3.utils.numberToHex(argv[2]), 
				web3.utils.numberToHex(argv[3]), 
				argv[4], 
				value, 
				argv[6]
				];

		var txSixFieldRLP = util.bufferToHex(RLP.encode(txNake));
		var txRLP_hash = util.sha3(txSixFieldRLP);


		// console.log('\nSixFieldRLP hex:\n' + txSixFieldRLP);
		// console.log('\nTransaction RLP+Hash:\n' + util.bufferToHex(txRLP_hash));

		fs.writeFile('isv_app/txRLP_hash.txt', txRLP_hash,  function(err) {
		   if (err) {
		      return console.error(err);
		   }
		});
	}
});




// var nonce = null;
// if(argv[2] != '0'){
// 	nonce = web3.utils.numberToHex(argv[2]);
// }

// var txNake = [
// 		nonce, 
// 		web3.utils.numberToHex(argv[3]), 
// 		web3.utils.numberToHex(argv[4]), 
// 		argv[5], 
// 		web3.utils.numberToHex(argv[6]), 
// 		argv[7]
// 		];

// var txSixFieldRLP = util.bufferToHex(RLP.encode(txNake));
// var txRLP_hash = util.sha3(txSixFieldRLP);


// // console.log('\nSixFieldRLP hex:\n' + txSixFieldRLP);
// console.log('\nTransaction RLP+Hash:\n' + util.bufferToHex(txRLP_hash));

// fs.writeFile('isv_app/txRLP_hash.txt', txRLP_hash,  function(err) {
//    if (err) {
//       return console.error(err);
//    }
// });
