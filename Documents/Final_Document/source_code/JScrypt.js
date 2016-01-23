
'use strict'

//required packages
var crypto = require('crypto');
var eks = require('./eksBlowfish.js');
var buff = require('buffer'); //https://nodejs.org/api/buffer.html
var bufferPack = require('bufferpack'); //https://github.com/ryanrolds/bufferpack

var BCRYPT_VERSION = "2a";
var DEFAULT_ROUNDS = 10;
var MIN_ROUNDS = 6;
var MAX_ROUNDS  = 31;
var SALT_LENGTH_BYTE = 16; //16bytes
var SALT_LENGTH_CHAR = 22;
var KEY_HASH_SIZE = 31;
var MIN_KEY_SIZE = 1; // 1 byte/character(ASCII)
var MAX_KEY_SIZE = 56; //56 bytes/characters


//this is the string that the developer will save in their db.
//it has the format "$ <bcryptVersion> $ <NumOfRounds> $ <encodedSalt><hashKey>"
var hashString = "";


//functions required in the router for the front end, and for testing
module.exports.generateRandomSalt = generateRandomSalt;
module.exports.hashKey = hashKey;
module.exports.compareKey = compareKey;
module.exports.getComponents = getComponents;



// create 16-byte salt, and generate the hashString accordingly

/**
 * Generates a random padded string of length 24, which is used for hashing the key. This string includes padding which later will be removed before hashing the key.
 * @param {Integer} rounds Number of time the key is hashed.
 * @returns {String} Random padded string of length 24.
 */
function generateRandomSalt(rounds) {

	//buffer of 16bytes
	var salt = crypto.randomBytes(SALT_LENGTH_BYTE);


	if (salt.length != SALT_LENGTH_BYTE) {
		console.log("bad salt generated");
		return null;
	}


	//the salt is auto padded, so remove the appropriate paadding so we get a length of 22 characters
	var unpadded_salt = salt.toString('base64').substring(0,22);


	//this ensures we get the format 06, 07, 08, 09, for small rounds
	if (rounds < 10) rounds = "0"+rounds; 

	//update the hash string
	//now all we are missing is the hashKey to complete hashString :)
	hashString = "$" + BCRYPT_VERSION + "$" + rounds + "$" + unpadded_salt;

	// return unpadded_salt;
	return unpadded_salt;
}	



// key will be given by the user, rounds will be set by developer, and salt will be auto generated

/**
 * Generates the hash string that will be stored in the applications database. This is one of the only two functions that a user of the project will be required to call in their application. 
 * @param {Integer} rounds Number of time the key is hashed.
 * @param {String} key String input of length 1 to 56
 * @returns {String} Encrypted string with various components and random ASCII characters.
 */
function hashKey(key, rounds) {


	var keyLen;
	if(key != null) {
		keyLen = key.length;
	} else {
		keyLen = 0;
	}



	//throw error on invalid key size
	if (keyLen < MIN_KEY_SIZE || keyLen > MAX_KEY_SIZE || typeof key != "string") {
		console.log("invalid key!");
		return null;
	}


	if (!rounds || rounds < MIN_ROUNDS || rounds > MAX_ROUNDS) {
		rounds = DEFAULT_ROUNDS;
	}


	//generateaRandomSalt returns of a buffer of 16 bytes
	//but if we take .toString('base64') it returns a string of 24 characters into base64
	var salt = generateRandomSalt(rounds).toString('base64');

	//now we need to call eksblowfish(key,salt, keyLen)
	//and append the result (as base64) to hashString

	var magicKey_buffer = buff.Buffer("OrpheanBeholderScryDoubt");
    var ctext = bufferPack.unpack('>IIII', magicKey_buffer);

    var x = new eks.eksObj();


	x.eksblowfish.keyExpansion(salt, key)

	for (var i = 0; i < Math.pow(2,rounds); i++) {
		x.eksblowfish.keyExpansion("", key)
		x.eksblowfish.keyExpansion("", salt);
	}

	for (var i = 0; i < 64; i++) {
		for (var j = 0; j < 4; j+=2) {
			var xl_xr = x.eksblowfish.feistel_cipher(ctext[j], ctext[j+1], 0);
			ctext[j] = xl_xr[0];
			ctext[j+1] = xl_xr[1];
		}
	}

	var hash_key= bufferPack.pack('>IIII', ctext).toString('base64');

	hashString += hash_key

	return hashString
}


/*
compareKey(cleanKey, hashKey) 
  cleanKey comes from the user input
  hashKey comes from the database
*/


/**
 * Hashes the cleanKey provided as input and compares the hashed string to the haskKey provided as input. If both values match, returns true, otherwise the function returns false.
 * @param {String} cleanKey Plain text password that the user wants to compare to hashed password.
 * @param {String} hashKey Corresponding hashed password.
 * @returns {Boolean} True if passwords match, false otherwise.
 */
function compareKey(cleanKey, hashKey) {

	//split up the hashkey
	var components = getComponents(hashKey);

	if (components.length == 0) {
		return false;
	}

	var rounds = components[1];
	var salt = components[2];
	var key = components[3];



	var magicKey_buffer = buff.Buffer("OrpheanBeholderScryDoubt");
    var ctext = bufferPack.unpack('>IIII', magicKey_buffer);

	var y = new eks.eksObj();
	y.eksblowfish.keyExpansion(salt, cleanKey)

	for (var i = 0; i < Math.pow(2,rounds); i++) {
		y.eksblowfish.keyExpansion("", cleanKey)
		y.eksblowfish.keyExpansion("", salt);
	}

	for (var i = 0; i < 64; i++) {
		for (var j = 0; j < 4; j+=2) {
			var xl_xr = y.eksblowfish.feistel_cipher(ctext[j], ctext[j+1], 0);
			ctext[j] = xl_xr[0];
			ctext[j+1] = xl_xr[1];
		}
	}


	var hash_key= bufferPack.pack('>IIII', ctext).toString('base64');


	//success, they keys match
	if (key == hash_key) {
		return true;
	}

	//failure :(
	return false;

};


/*
getComponents(hashkey)
split up the components of the hashkey into an array */

/**
 * Parses the input hashKey and returns its various components in an array.
 * @param {String} hashKey String input of length 1 to 56.
 * @returns {Array} Array of components that have been parsed from the haskKey.
 */
function getComponents(haskKey) {
	
	var hashKeyLen;
	if(haskKey.length != 53){
		return [];
	} else {
		hashKeyLen = haskKey.length;
	}
	
	var components = []; // 0: version, 1: rounds, 2: salt, 3: key

	var tempComponents = haskKey.split("$");

	components.push(tempComponents[1]) // version
	components.push(parseInt(tempComponents[2])); //rounds
	components.push(tempComponents[3].substring(0,SALT_LENGTH_CHAR)); //salt
	components.push(tempComponents[3].substring(SALT_LENGTH_CHAR, hashKeyLen)); //key

	//check validity
	if (components[0] != BCRYPT_VERSION) {
		return [];
	}

	if (components[1] < MIN_ROUNDS || components[1] > MAX_ROUNDS) {
		return [];
	}

	if (components[2].length != SALT_LENGTH_CHAR) {
		return [];
	}

	if (components[3].length > KEY_HASH_SIZE) {
		return [];
	}


	return components;
}



//create a hash string and store it into x 
// var x = hashKey('superSecretKey',10);
// console.log(x);
// console.log( compareKey('superSecretKey', x) );