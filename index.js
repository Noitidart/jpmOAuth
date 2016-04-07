var self = require("sdk/self");
var tabs = require("sdk/tabs");
var Request = require("sdk/request").Request;
var {Cu} = require('chrome');

Cu.import('resource://gre/modules/Services.jsm');

Services.scriptloader.loadSubScript(self.data.url('hmac-sha1.js'));
// console.error('CryptoJS:', CryptoJS.HmacSHA1("rawr", "11").toString(CryptoJS.enc.Hex));

// rev1 - https://gist.github.com/Noitidart/6c172e77fe48f78521f2
var jQLike = { // my stand alone jquery like functions
    serialize: function(aSerializeObject) {
        var serializedStrArr = [];
        for (var cSerializeKey in aSerializeObject) {
            serializedStrArr.push(encodeURIComponent(cSerializeKey) + '=' + encodeURIComponent(aSerializeObject[cSerializeKey]));
        }
        return serializedStrArr.join('&');
    }
};

function to_rfc3986(aStr) {
	// https://af-design.com/2008/03/14/rfc-3986-compliant-uri-encoding-in-javascript/
	var tmp =  encodeURIComponent(aStr);
	tmp = tmp.replace('!','%21');
	tmp = tmp.replace('*','%2A');
	tmp = tmp.replace('(','%28');
	tmp = tmp.replace(')','%29');
	tmp = tmp.replace("'",'%27');
	return tmp;
}

function nonce(length) {
	// generates a nonce
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for(var i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

function twitterRequestDetails(aURL, aMethod, aRawPostDataObj={}, aCallback, aConsumerKey, aOauthTokenSecret=null) {
	// generates a twitter signature
	// rawPostDataObj is the post data non url encoded/escpaed
	
	var oauth_params = {
		oauth_nonce: nonce(42),
		oauth_signature_method: 'HMAC-SHA1',
		// oauth_callback: encodeURIComponent(aCallback),
		oauth_timestamp: Math.floor((new Date()).getTime() / 1000),
		oauth_consumer_key: aConsumerKey,
		oauth_version: '1.0'
		// oauth_signature: '???' // added in later after sig is created
	};
	if (aOauthTokenSecret) {
		oauth_params.oauth_token = aOauthTokenSecret;
	}
	
	// for signautre reasons twitter docs say "Sort the list of parameters alphabetically[1] by encoded key[2]." here - https://dev.twitter.com/oauth/overview/creating-signatures
	// create oauth_signature
	var sig_arr = [];
	for (var cOauthParam in oauth_params) {
		if (cOauthParam == 'oauth_signature') {
			continue;
		}
		sig_arr.push([to_rfc3986(cOauthParam), to_rfc3986(oauth_params[cOauthParam])]);
	}
	for (var cRawPostEntry in aRawPostDataObj) {
		sig_arr.push([to_rfc3986(cRawPostEntry), to_rfc3986(aRawPostDataObj[cRawPostEntry])]);
	}
	sig_arr.sort(function(a, b) {
		return a[0].localeCompare(b[0]);
	});
	
	console.error('sig_arr:', sig_arr);
	
	var sig_str = [];
	for (var i=0; i<sig_arr.length; i++) {
		sig_str.push(sig_arr[i][0] + '=' + sig_arr[i][1] + '');
	}
	sig_str = sig_str.join('&');
	
	sig_str = aMethod.toUpperCase() + '&' + to_rfc3986(aURL) + '&' + to_rfc3986(sig_str);
	
	console.error('sig_str:', sig_str);
	
	// create signing key
	var sig_key = to_rfc3986(aConsumerKey) + '&';
	
	if (aOauthTokenSecret) {
		sig_key += to_rfc3986(aOauthTokenSecret);
	}
	console.error('sig_key:', sig_key);
	
	// create encoded sig
	var sig_hmac_sha1_base64 = CryptoJS.HmacSHA1(sig_str, sig_key).toString(CryptoJS.enc.Base64);
	oauth_params.oauth_signature = sig_hmac_sha1_base64;
	
	// create header_auth_str
	var header_auth = [];
	for (var cOauthParam in oauth_params) {
		header_auth.push([cOauthParam, oauth_params[cOauthParam]]);
	}
	
	header_auth.sort(function(a, b) {
		return a[0].localeCompare(b[0]);
	});
	console.error('header_auth:', header_auth);
	
	var header_auth_str = [];
	for (var i=0; i<header_auth.length; i++) {
		header_auth_str.push(to_rfc3986(header_auth[i][0]) + '="' + to_rfc3986(header_auth[i][1]) + '"');
	}
	header_auth_str = header_auth_str.join(', ');
	
		// 'OAuth oauth_consumer_key="AjONvgAdbD8YWCtRn5U9yA"',
		// 'oauth_nonce="' + nonce(42) + '"',
		// 'oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D"',
		// 'oauth_signature_method="HMAC-SHA1"',
		// 'oauth_timestamp="' + (new Date()).getTime() + '"',
		// 'oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"',
		// 'oauth_version="1.0"'
		
		// 'OAuth oauth_nonce="' + nonce(42) + '"',
		// 'oauth_callback="' + encodeURIComponent('http://127.0.0.1/floppers') + '"',
		// 'oauth_signature_method="HMAC-SHA1"',
		// 'oauth_timestamp="' + (new Date()).getTime() + '"',
		// 'oauth_consumer_key="AjONvgAdbD8YWCtRn5U9yA"',
		// 'oauth_signature="Pc%2BMLdv028fxCErFyi8KXFM%2BddU%3D"',
		// 'oauth_version="1.0"'
	
	console.error('header_auth_str:', header_auth_str);
	return {
		url: aURL,
		header_auth: 'OAuth ' + header_auth_str,
		postDataStrSerialized: jQLike.serialize(aRawPostDataObj)
	};
}

var cReqDetail = twitterRequestDetails('https://api.twitter.com/oauth/request_token', 'POST', {
  oauth_callback: 'http://127.0.0.1/floppers'
}, 'http://127.0.0.1/floppers', 'AjONvgAdbD8YWCtRn5U9yA', null);
console.error('cReqDetail:', cReqDetail);

var req = {
	url: cReqDetail.url,
	content: cReqDetail.postDataStrSerialized,
	headers: {
		Authorization: cReqDetail.header_auth
	},
	onComplete: function (response) {
		console.error(response.text, response.json);
		
	// tabs.open('https://api.twitter.com/oauth2/token?' + jQLike.serialize({
		// oauth_token: response.json.oauth_token,
	// });
	}
};
console.error('req:', req);
Request(req).post();

console.error('ok did req');