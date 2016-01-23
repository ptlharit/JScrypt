// Import all required npm modules
var mocha = require('mocha'),
	sinon = require('sinon'),
	chai  = require('chai'),
	expect = chai.expect;

// Import eksBlowfish functions
var eks = require('./eksBlowfish.js');

describe('Tests for eksBlowfish algorithm', function(){

	describe('feistel_cipher tests', function(){
		
		var xl;
		var xr;
		var eks_obj;
		var output;

		before(function(){
			eks_obj = new eks.eksObj();
		})

		it('returns expected output using p_array given appropriate xl and xr values', function(){

			xl = 112888726;
			xr = -1272277262;

			output = eks_obj.eksblowfish.feistel_cipher(xl, xr);
			expect(output).to.eql([419532600,26624517]);
		})
	})

	describe('feistel_F tests', function(){

		var xl;
		var eks_obj2;
		var output;

		before(function(){
			eks_obj2 = new eks.eksObj();
		})

		it('returns expected value using s_boxes given appropriate xl value', function(){

			xl = 579199262;

			output = eks_obj2.eksblowfish.feistel_F(xl);
			expect(output).to.eql(2684460832);
		})
		
	})

})


