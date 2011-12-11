var crypto			= require('crypto');
var http 				= require('http');
var querystring = require('querystring');
var url 				= require('url');

(function() {
	exports.request_token = function(props,req,res) {
		var consumer_key = props.consumer_key;
		var shared_secret = props.shared_secret;
		var timestamp = getTimestamp();
		var nonce = getNonce();
		var urlp = url.parse(props.request_url);
		var path = (urlp.search === undefined) ? urlp.pathname : urlp.pathname + urlp.search;
		var callback_url = props.callback_url;
		var options = {
			host: urlp.hostname,
			port: urlp.port,
			method: 'GET',
			path: path,
			headers: { 
				'Authorization': [
					'OAuth realm=""', 
					'oauth_consumer_key="'+consumer_key+'"', 
					'oauth_signature_method="HMAC-SHA1"', 
					'oauth_timestamp="'+timestamp+'"', 
					'oauth_nonce="'+nonce+'"',
					'oauth_version="1.0"',
					'oauth_callback="'+encode(callback_url)+'"'
				] 
			}
		};
		var sbs = generate_sbs(options);
		console.log('SIGNATURE_BASE: ' + sbs); 
		var oauth_signature = sign_request(shared_secret,null,sbs);
		console.log('DIGEST: ' + oauth_signature);
		options.headers.Authorization.push('oauth_signature="'+encode(oauth_signature)+'"');
		_.each(options.headers.Authorization, function(pair) {
			console.log(pair);
		});
		request(options,function(json) {
			if (json.error) {
				res.writeHead(500);
				res.end('Error: ' + json.error);
				return;
			}
			var login_url = decode(querystring.stringify(json)).split('login_url=')[1]; 
			res.writeHead(302, { 
				'Location': login_url, 
				'Set-Cookie': 'oauth_token_secret='+json.oauth_token_secret
				//'Set-Cookie': 'oauth_token='+json.oauth_token[1]+';oauth_token_secret='+json.oauth_token_secret
			});
			res.end();
		});
	},
	exports.access_token = function(props,req,res) { //, callback) {
		if (req.headers.cookie) {
			var cookies = {};
			req.headers.cookie.split(';').forEach(function(cookie) {
				var parts = cookie.split('=');
				cookies[parts[0].trim()] = (parts[1]||'').trim();
			});
		}
		var oauth_token_secret = cookies['oauth_token_secret'];
		console.log('oauth_token_secret: ' + oauth_token_secret);
		var oauth_token = querystring.parse(url.parse(req.url).query).oauth_token;
		console.log('oauth_token: ' + oauth_token);
		var oauth_verifier = querystring.parse(url.parse(req.url).query).oauth_verifier;
		console.log('oauth_verifier: ' + oauth_verifier);
		//
		var consumer_key = props.consumer_key;
		var shared_secret = props.shared_secret;
		var timestamp = getTimestamp();
		var nonce = getNonce();
		var urlp = url.parse(props.access_url);
		var path = (urlp.search === undefined) ? urlp.pathname : urlp.pathname + urlp.search;
		var callback_url = props.callback_url;
		var options = {
			host: urlp.hostname,
			port: urlp.port,
			method: 'GET',
			path: path,
			headers: { 
				'Authorization': [
					'OAuth realm=""', 
					'oauth_consumer_key="'+consumer_key+'"', 
					'oauth_token="'+oauth_token+'"', 
					'oauth_signature_method="HMAC-SHA1"', 
					'oauth_timestamp="'+timestamp+'"', 
					'oauth_nonce="'+nonce+'"',
					'oauth_verifier="'+oauth_verifier+'"'
				] 
			}
		};
		var sbs = generate_sbs(options);
		console.log('2SIGNATURE_BASE: ' + sbs); 
		var oauth_signature = sign_request(shared_secret,oauth_token_secret,sbs);
		console.log('2DIGEST: ' + oauth_signature);
		options.headers.Authorization.push('oauth_signature="'+encode(oauth_signature)+'"');
		_.each(options.headers.Authorization, function(pair) {
			console.log('2'+pair);
		});
		request(options,function(json) {
			if (json.error) {
				res.writeHead(500);
				res.end('Error: ' + json.error);
				return;
			}
			var real_oauth_token = json.oauth_token;
			console.log('real_oauth_token: ' + real_oauth_token);
			var real_oauth_token_secret = json.oauth_token_secret;
			console.log('real_oauth_token_secret: ' + real_oauth_token_secret);
			res.end(JSON.stringify(json));
		});
	},
	//exports.oauth_request = function(urlx,method,props,req,res) {
	exports.oauth_request = function(urlx,method,props,callback) {
		var consumer_key = props.consumer_key;
		var shared_secret = props.shared_secret;
		var token = props.token;
		var token_secret = props.token_secret;
		var verifier = props.verifier;
		var timestamp = getTimestamp();
		var nonce = getNonce();
		var urlp = url.parse(urlx);
		var path = (urlp.search === undefined) ? urlp.pathname : urlp.pathname + urlp.search;
		var options = {
			host: urlp.hostname,
			port: urlp.port,
			method: method,
			path: path,
			headers: { 
				'Content-type': 'application/x-www-form-urlencoded',
				'Authorization': [
					'OAuth realm=""', 
					'oauth_consumer_key="'+consumer_key+'"', 
					'oauth_token="'+token+'"', 
					'oauth_signature_method="HMAC-SHA1"', 
					'oauth_timestamp="'+timestamp+'"', 
					'oauth_nonce="'+nonce+'"',
					'oauth_verifier="'+verifier+'"'
				] 
			}
		};
		var sbs2 = generate_sbs(options);
		console.log('4SIGNATURE_BASE: ' + sbs2); 
		var oauth_signature2 = sign_request(shared_secret,token_secret,sbs2);
		console.log('4DIGEST: ' + oauth_signature2);
		options.headers.Authorization.push('oauth_signature="'+encode(oauth_signature2)+'"');
		_.each(options.headers.Authorization, function(pair) {
			console.log('4'+pair);
		});
		console.log('path: ' + options.path);
		options.path = '/v2/users/__SELF__/carts';
		console.log('path: ' + options.path);
		request(options,function(json) {
			if (json.error) {
				callback({ 'error': ee.message });
				return;
			}
			callback(json);
			return;
		});
	}
})();

function generate_sbs(options) {
	// TODO: is it OK to assume http/https?
	var protocol = (options.port === 443) ? 'https://' : 'http://'; 
	var urlp = url.parse(protocol+options.host+options.path,parseQueryString=true);
	var signature_base = options.method + '&' + encode(urlp.protocol+'//'+urlp.hostname+urlp.pathname) + '&';
	var params = [];
	if (urlp.query) {
		var query = urlp.query;
		for (var key in query) {
			if (query.hasOwnProperty(key)) {
				console.log(key + " -> " + query[key]);
				params.push(encode(key+'='+encode(query[key])));
			}
		}
	}
	//if (urlp.query.scope) params.push(encode('scope='+encode(urlp.query.scope)));	//'listings_r'))); 
	_.each(options.headers.Authorization, function(pair) {
		if (pair.indexOf('OAuth') === -1 && pair.indexOf('realm=') === -1 && pair.indexOf('oauth_signature=') === -1) {
			params.push(encode(pair.replace(/\"/g, "")));
		}
	});
	signature_base += params.sort().join(encode('&'));
	return signature_base;
}

function sign_request(shared_secret,token_secret,sbs) {
	var key = (token_secret === null) ? encode(shared_secret) + '&' : encode(shared_secret) + '&' + encode(token_secret);
	var digest = crypto.createHmac("sha1",key).update(sbs).digest("base64");  
	return digest;
}

function request(options, callback) {
	var req = http.request(options, function(res) {
		console.log('STATUS: ' + res.statusCode);
		console.log('HEADERS: ' + JSON.stringify(res.headers));
		//console.log('TRAILERS: ' + JSON.stringify(res.trailers));
		//console.log('X-Etsy-Request-Uuid: ' + res.headers["X-Etsy-Request-Uuid"]);
		var body = "";
		res.setEncoding('utf8');
		res.on('data', function(chunk) {
			console.log('BODY: ' + chunk);
			body += chunk;
		});
		res.on('end', function() {
			callback(querystring.parse(decode(body)));
		});
	});
	req.on('error', function(ee) {
		callback({ 'error': ee.message });
	});
	req.write('user_id=14888350&listing_id=1451', encoding='utf8');
	req.end();
}

function encode(chars) {
	if (chars === null || chars === "") return '';
	var result = encodeURIComponent(chars);
	// Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
	return result.replace(/\!/g, "%21")
							 .replace(/\'/g, "%27")
							 .replace(/\(/g, "%28")
							 .replace(/\)/g, "%29")
							 .replace(/\*/g, "%2A");
}

function decode(chars) {
	if (chars === null || chars === "") return '';
	var result = decodeURIComponent(chars);
	return result;
}

function getTimestamp() {
	return Math.round(new Date().getTime()/1000.0);
}

function getNonce() {
	return getTimestamp();
}

String.prototype.trim = function() {
	return this.replace(/^\s\s*/, '').replace(/\s\s*$/, ''); 
}
