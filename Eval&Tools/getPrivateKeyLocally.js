var argv = process.argv;

var keythereum = require("keythereum");
var datadir = "/home/yang/.ethereum/rinkeby";
var address= argv[2];
const password = argv[3];
var keyObject = keythereum.importFromFile(address, datadir);
var privateKey = keythereum.recover(password, keyObject);
console.log(privateKey.toString('hex'));