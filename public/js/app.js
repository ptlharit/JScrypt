angular.module('js_crypt', [])





	.controller('makeHashKeyCtrl', function($http) {

		var self = this;

		this.keyInfo  = {
			key: "",
			rounds: ""
		}

		// this.mykey = "";
		this.encryptedKey = "";


		this.submitKey = function() {
			
			$http.post('/hashKey', self.keyInfo)

				.success(function(data) { 
					self.encryptedKey = data.hash;
					
				});
		}


	})


	.controller('compareKeyCtrl', function($http){
		
		var self = this;

		this.keys =  {
			clean: "",
			encrypted: ""
		}

		this.passEncryption = null;


		this.compareKey = function() {
			$http.post('/compareKey',self. keys)
				.success(function(data) {
					self.passEncryption = data.pass;
				});
		}
	})



	.controller('genRandomSaltCtrl', function($http) {
		var self = this;

		this.rounds = {
			numOfRounds: 10
		};

		this.generatedSalt = "";


		this.genSalt = function() {

			$http.post('/genSalt', self.rounds) 
			
				.success(function(data) {
					self.generatedSalt = data.salt;
					
				});
		}
	})