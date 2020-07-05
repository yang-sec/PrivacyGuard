var keythereum = require("keythereum");








var accounts = [
"0x154f3d575f404544f65aace4f3cb462f652a4185",
"0x9e2320af88a83077c4445e552ace02fd20b83fbf",
"0xe4347b89a0b63e59ecde1957cd4473ceb8ce0a92",
"0xdbaed106423a7c2e848c6581b66713ad4c8bc7ff",
"0x629ed2bb627ea6e5469b16b1c3dc5ea1c689d347",
"0xb86af8cc002386522748620c45b685ef34cac4cf",
"0x8e043544ea9ac143e441132e1ff9fba47ce12489",
"0x157d6879f13be984594947f4afd7f2f0c9732876",
"0x29ee5a723e9d4b4be56689ac931e7d92bd7f1c86",
"0x0d186638156630e0d0869959ecc568704dbaa0c2",
"0x35f7df7258b55ccb86a223b230c2c8e44b56c24e",
"0x89b1b0ae1e0eb7c9119439c2bdd504957008968a",
"0x133542b7a868d1f25a5cb80eff816c8583a56e98",
"0x8057442400c8634b95ba68b76922b2a486fbe4cf",
"0xfe7079bbebb5fc8ad4a62fddeb3556cb691b2d3e",
"0xe362321eeddfc2513a54f8427c5ba40d088e8294",
"0x9463d8301d38341d5f6f7f5304dd8e3e29867141",
"0x373e7dbf92e86bc510f587ba560707a83d4f795e",
"0x5c1c58978037c723583482cd38c5d40ecd2d7398",
"0xb144f3d8e20bc55e468e5f43b5ccc032ca84ba74",
"0x42906762aaaa468ce56219b3205848154b4cc0e7",
"0x46ca0f770485fe09a704f0b4f400e74da55e262e",
"0x9db25ef4239411a0ee6dfc75e11303a1c75fb6e3",
"0x0c64c370d595ada819656de2674e4877b484b1d7",
"0x22f2b4a4dfc20e4a2bf25239b0125ce31dab50e5",
"0xecc4e97c4111259996931d689ad016d4e550ace3",
"0xfcad6bb861d1af44d05b60c61b6336bce16ffdf7",
"0xfde6be6b88f1de8b53506869fc9132ceade74c44",
"0xee200296748ab60e2d3b67243ff763fbdd89269a",
"0x9e7fff61ce55a9e97c2bb1670ab902925f523b7e",
"0x057f0bce633834c3dc5401164a274ae762231cbd",
"0x7ed00465e851440597acd7bac5da8c96cbe91b19"
];

var datadir = "/home/yang/.ethereum/rinkeby";
// var address= argv[2];
const password = "123666";

// display accounts and private keys
for (var i = 0; i < accounts.length; i++) {
	var address = accounts[i];
	var keyObject = keythereum.importFromFile(address, datadir);
	var privateKey = keythereum.recover(password, keyObject);
	console.log("{\""+address+"\", \""+privateKey.toString('hex')+"\"},");
}

// // display accounts only
// for (var i = 0; i < accounts.length; i++) {
// 	var address = accounts[i];
// 	console.log(address+',');
// }
