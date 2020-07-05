var Web3 = require('web3');
// var web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/'));
var web3 = new Web3(new Web3.providers.HttpProvider('https://rinkeby.infura.io/'));
var util = require('ethereumjs-util');
// var tx = require('ethereumjs-tx');
var RLP = require('rlp');
var fs = require("fs");

// console.log(process.argv);
var address = '0x65843be2dd4ad3bc966584e2fcbb38838d49054b';
var argv = process.argv;

var data;

data = fs.readFileSync('isv_app/txSignature_v.txt');
var txSignature_v = util.bufferToHex(data).toString();

data = fs.readFileSync('isv_app/txSignature_r.txt');
var txSignature_r = util.bufferToHex(data).toString();

data = fs.readFileSync('isv_app/txSignature_s.txt');
var txSignature_s = util.bufferToHex(data).toString();


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

    var txFull = [
        nonce, 
        web3.utils.numberToHex(argv[2]), 
        web3.utils.numberToHex(argv[3]), 
        argv[4], 
        value, 
        argv[6],
        txSignature_v,
        txSignature_r,
        txSignature_s
        ];

    // console.log(txFull);

    var txRawHex = util.bufferToHex(RLP.encode(txFull));

    console.log('\ntxRawHex: \n' + txRawHex);

    // Send the raw transaction hex
    console.log('\nTxHash: ');

    web3.eth.sendSignedTransaction(txRawHex, function (err, hash) {
      if (err) {
        console.log(err);
      }
      else {
        console.log(hash);
      }
    });


    // Write the raw transaction hex into a file which may be used later
    fs.writeFile('isv_app/txRawHex.txt', txRawHex,  function(err) {
       if (err) {
          return console.error(err);
       }
    });
  }
});