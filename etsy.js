var fs					= require('fs');
var http				= require('http');
//var https			= require('https');
var querystring = require('querystring');
var url					= require('url');

var etsy_oauth 	= require('./etsy-oauth');
require('./underscore');

server = http.createServer(function (req, res) {
	var urlp = url.parse(req.url,true);
	//console.log(JSON.stringify(url));
	var routes = {};
	routes[urlp.pathname] = 1;
	if (routes['/oauth']) {	oauth(req,res); return; }
	if (routes['/oauth_callback']) {	oauth_callback(req,res); return; }
	if (routes['/test']) {	test(req,res); return; }
	res.writeHead(404);
}).listen(1337, "127.0.0.1");

function oauth(req, res) {
	//var props = JSON.parse(fs.readFileSync('conf/etsy.props.js', 'UTF-8')).prod;
	var props = JSON.parse(fs.readFileSync('conf/etsy.props.js', 'UTF-8')).dev;
	/* var props = { }; */
	etsy_oauth.request_token(props,req,res);
} 

function oauth_callback(req,res) {
	//var props = JSON.parse(fs.readFileSync('conf/etsy.props.js', 'UTF-8')).prod;
	var props = JSON.parse(fs.readFileSync('conf/etsy.props.js', 'UTF-8')).dev;
	/* var props = { }; */
	etsy_oauth.access_token(props,req,res);
}

function test(req,res) {
	//var props = JSON.parse(fs.readFileSync('conf/etsy.props.js', 'UTF-8')).prod;
	var props = JSON.parse(fs.readFileSync('conf/etsy.props.js', 'UTF-8')).dev;
	// GETs
	//var url = 'http://sandbox.openapi.etsy.com/v2/listings/active';
	//var url = 'http://openapi.etsy.com/v2/countries';
	//var url = 'http://sandbox.openapi.etsy.com/v2/users/__SELF__';
	//var url = 'http://sandbox.openapi.etsy.com/v2/users/__SELF__/shipping/templates';
	//var url = 'http://openapi.etsy.com/v2/users/__SELF__/shipping/templates';
	//var method = 'GET';
	// POSTs
	var url = 'http://sandbox.openapi.etsy.com/v2/users/__SELF__/carts?user_id=14888350&listing_id=1451';
	//var url = 'http://sandbox.openapi.etsy.com/v2/shipping/templates?title=test&origin_country_id=209&primary_cost=1&secondary_cost=1';
	//var url = 'http://sandbox.openapi.etsy.com/v2/listings?quantity=2&title=test%20thingy&description=test&price=0.99&tags=Art&shipping_template_id=7223828';
	var method = 'POST';
	// 
	etsy_oauth.oauth_request(url, method, props, function(json) {
		if (json.error) {
			res.writeHead(500);
			res.end('Error: ' + json.error);
		}
		res.writeHead(200);
		res.end(JSON.stringify(json));
	});
}
