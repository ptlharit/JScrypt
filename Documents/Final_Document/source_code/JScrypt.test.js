// Import all required npm modules
var mocha = require('mocha'),
	sinon = require('sinon'),
	chai  = require('chai'),
	expect = chai.expect;

// Import JScrypt functions
var JScrypt = require('./JScrypt.js');

// Functions tests
describe('Unit tests for JScrypt functions', function(){

	describe('generateRandomSalt tests', function(){
		var output;

		beforeEach(function(){
			var rounds = 10;
			output = JScrypt.generateRandomSalt(rounds);
		})

		afterEach(function(){
			output = null;
		})

		it('function should return a string', function(){
			expect(typeof output).to.equal('string');
		})

		it('returned output should have length 22', function(){
			expect(output.length).to.equal(22);
		})		
	})

	describe('hashKey tests', function(){
		var output;
		var rounds;
		var key;

		afterEach(function(){
			output = null;
		})


		it('should return null if key is an empty string', function(){
			key = "";
			rounds = 8;
			output = JScrypt.hashKey(key, rounds);
			expect(output).to.be.null;
		})

		it('should return a hash since rounds will be changed to default', function(){
			key = "superSecretKey";
			rounds = 1;
			output = JScrypt.hashKey(key, rounds);
			expect(output).to.not.equal(null);
			expect(typeof output).to.equal('string');
		})

		it('should return a hash provided appropriate inputs', function(){
			key = "superSecretKey";
			rounds = 8;
			output = JScrypt.hashKey(key, rounds);
			expect(output).to.not.equal(null);
			expect(typeof output).to.equal('string');
		})

		it('should return null if key is null', function(){
			key = null;
			rounds = 8;
			output = JScrypt.hashKey(key, rounds);
			expect(output).to.be.null;
		})
	})


	describe('getComponents tests', function(){
		var key;
		var output;

		afterEach(function(){
			output = null;
		})

		it('returns false if the haskKey input is an empty string', function(){
			key = "";
			output = JScrypt.getComponents(key);
			expect(output).to.eql([]);
		})

		it('returns false if the haskKey doesn\'t match BCRYPT_VERSION', function(){

			//note, the version in the below string is 2b, not 2a
			key = "$2b$10$IpocdZqL9TA8ZW2EWvpBJAa5w1QjNqmxAAAAAAGqoVPw=="
			output = JScrypt.getComponents(key);
			expect(output).to.eql([]);
		})

		it('returns false if number of rounds is not within expected range', function(){
			
			// number of rounds here is 4, below the minimum of 6
			var key1 = '$2a$04$IpocdZqL9TA8ZW2EWvpBJAa5w1QjNqmxAAAAAAGqoVPw=='
			var output1 = JScrypt.getComponents(key1);

			//number of rounds here is 34, greater than the maximum of 31
			key = '$2a$34$IpocdZqL9TA8ZW2EWvpBJAa5w1QjNqmxAAAAAAGqoVPw=='
			output = JScrypt.getComponents(key);

			expect(output).to.eql([]);
			expect(output1).to.eql([]);
		})

		it('returns false if the length of haskKey is longer than expected', function(){
			key = '$2a$10$IpocdZqL9TA8ZW2EWvpBJAa5w1QjNqmxAAAAAAGqoVPw%%=='
			output = JScrypt.getComponents(key);
			expect(output).to.eql([]);
		})

		it('returns an array of components if haskKey follows all proper format', function(){
			key = "$2a$10$IpocdZqL9TA8ZW2EWvpBJAa5w1QjNqmxAAAAAAGqoVPw==";
			output = JScrypt.getComponents(key);
			expect(output).to.eql(['2a',10,'IpocdZqL9TA8ZW2EWvpBJA','a5w1QjNqmxAAAAAAGqoVPw==']);
		})
	})

	describe('conpareKey test', function(){
		var clean;
		var hash;
		var output;

		afterEach(function(){
			output = null;
		})

		it('returns false if keys do not match', function(){
			clean = "password123";
			hash = "$2a$10$K86nOX5LUsm/FppRpefo8ADNnx+B+oMlxxxxxGAAAAAA==";
			output = JScrypt.compareKey(clean, hash);
			expect(output).to.be.false;
		})

		it('returns true if both keys match', function(){
			clean = "password123";
			hash = "$2a$10$K86nOX5LUsm/FppRpefo8ADNnx+B+oMldIhZ0GAAAAAA==";
			output = JScrypt.compareKey(clean, hash);
			expect(output).to.be.true;
		})

	})

})


