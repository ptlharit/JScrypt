var express = require('express');
var router = express.Router();
var js = require('../src/JScrypt');



var encryptionIsDone = false;
var encryptedKey = "";

router.post('/hashKey', function(req, res) {

	var key = req.body.key;
	var rounds = req.body.rounds
	console.log(key +"  " +rounds);

	var hashedKey =  js.hashKey(key, rounds);



	res.send({status:'success', hash: hashedKey});

});


router.post('/compareKey', function(req,res) {

	console.log("received clean and encrypted keys");

	var cKey = req.body.clean;
	var eKey = req.body.encrypted;

	var passOrFail = js.compareKey(cKey, eKey);


	res.send({status:'success', pass:passOrFail });


});



// router.post('/genSalt', function(req,res) {

// 	console.log("rounds received as " + req.body.numOfRounds );

// 	var r = req.body.numOfRounds;

// 	var salt =  js.generateRandomSalt(r);

// 	res.send({status:'success', salt: salt});
// })


// router.get('/getRounds', function(req,res) {
	
// })
module.exports = router;
