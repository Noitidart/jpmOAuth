var self = require("sdk/self");
var tabs = require("sdk/tabs");
var Request = require("sdk/request").Request;
var {Cu} = require('chrome');

Cu.import('resource://gre/modules/Services.jsm');

Services.scriptloader.loadSubScript(self.data.url('hmac-sha1.js'));
Services.scriptloader.loadSubScript(self.data.url('enc-base64-min.js'));
// console.error('CryptoJS:', CryptoJS.HmacSHA1("rawr", "11").toString(CryptoJS.enc.Hex));

// start - common functions
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

// rev1 - https://gist.github.com/Noitidart/c4ab4ca10ff5861c720b
function validateOptionsObj(aOptions, aOptionsDefaults) {
	// ensures no invalid keys are found in aOptions, any key found in aOptions not having a key in aOptionsDefaults causes throw new Error as invalid option
	for (var aOptKey in aOptions) {
		if (!(aOptKey in aOptionsDefaults)) {
			console.error('aOptKey of ' + aOptKey + ' is an invalid key, as it has no default value, aOptionsDefaults:', aOptionsDefaults, 'aOptions:', aOptions);
			throw new Error('aOptKey of ' + aOptKey + ' is an invalid key, as it has no default value');
		}
	}
	
	// if a key is not found in aOptions, but is found in aOptionsDefaults, it sets the key in aOptions to the default value
	for (var aOptKey in aOptionsDefaults) {
		if (!(aOptKey in aOptions)) {
			aOptions[aOptKey] = aOptionsDefaults[aOptKey];
		}
	}
}

function spliceObj(obj1, obj2) {
	/**
	 * By reference. Adds all of obj2 keys to obj1. Overwriting any old values in obj1.
	 * Was previously called `usurpObjWithObj`
	 * @param obj1
	 * @param obj2
	 * @returns undefined
	 */
	for (var attrname in obj2) { obj1[attrname] = obj2[attrname]; }
}
function overwriteObjWithObj(obj1, obj2){
	/**
	 * No by reference. Creates a new object. With all the keys/values from obj2. Adds in the keys/values that are in obj1 that were not in obj2.
	 * @param obj1
	 * @param obj2
	 * @returns obj3 a new object based on obj1 and obj2
	 */

    var obj3 = {};
    for (var attrname in obj1) { obj3[attrname] = obj1[attrname]; }
    for (var attrname in obj2) { obj3[attrname] = obj2[attrname]; }
    return obj3;
}

function alphaStrOfObj(aObj, aParseFunc, aJoinStr, aDblQuot) {	
	var arr = Object.keys(aObj);
	arr.sort();
	
	if (!aParseFunc) {
		aParseFunc = function(aToBeParsed) {
			return aToBeParsed;
		};
	}
	
	for (var i=0; i<arr.length; i++) {
		arr[i] = aParseFunc(arr[i]) + '=' + (aDblQuot ? '"' : '') + aParseFunc(aObj[arr[i]]) + (aDblQuot ? '"' : '');
	}
	
	return arr.join(aJoinStr);
}

function to_rfc3986(aStr) {
	// https://af-design.com/2008/03/14/rfc-3986-compliant-uri-encoding-in-javascript/
	// i should test with the samples given here - https://dev.twitter.com/oauth/overview/percent-encoding-parameters
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
// end - common functions

function twitterRequestDetails(aURL, aMethod, aConsumerKey, aOptions) {
	// generates a twitter signature
	// rawPostDataObj is the post data non url encoded/escpaed
	
	var aOptionsDefaults = {
		postData: null, // object
		oauthTokenSecret: null, // string
		extraOauthParams: null // object
	};
	
	validateOptionsObj(aOptions, aOptionsDefaults);
	
	var oauth_params = {
		oauth_nonce: nonce(42),
		oauth_signature_method: 'HMAC-SHA1',
		// oauth_callback: encodeURIComponent(aCallback),
		oauth_timestamp: Math.floor((new Date()).getTime() / 1000),
		oauth_consumer_key: aConsumerKey,
		oauth_version: '1.0'
		// oauth_signature: '???' // added in later after sig is created
	};
	if (aOptions.oauthTokenSecret) {
		oauth_params.oauth_token = aOptions.oauthTokenSecret;
	}
	
	if (aOptions.extraOauthParams) {
		spliceObj(oauth_params, aOptions.extraOauthParams);
	}
	
	// for signautre reasons twitter docs say "Sort the list of parameters alphabetically[1] by encoded key[2]." here - https://dev.twitter.com/oauth/overview/creating-signatures
	// create oauth_signature
	var sig_collection;
	if (aOptions.postData) {
		sig_collection = overwriteObjWithObj(oauth_params, aOptions.postData);
	} else {
		sig_collection = oauth_params;
	}
	console.error('sig_collection:', sig_collection);
	
	var sig_str = aMethod.toUpperCase() + '&' + to_rfc3986(aURL) + '&' + to_rfc3986(alphaStrOfObj(sig_collection, to_rfc3986, '&'));
	console.error('sig_str:', sig_str);
	
	// create signing key
	var sig_key = to_rfc3986(aConsumerKey) + '&' + (aOptions.oauthTokenSecret ? to_rfc3986(aOptions.oauthTokenSecret) : '');
	console.error('sig_key:', sig_key);
	
	// create encoded sig
	var sig_hmac_sha1_base64 = CryptoJS.HmacSHA1(sig_str, sig_key).toString(CryptoJS.enc.Base64);
	console.error('sig_hmac_sha1_base64:', sig_hmac_sha1_base64);
	oauth_params.oauth_signature = sig_hmac_sha1_base64;
	
	// create header_auth_str
	var header_auth_str = alphaStrOfObj(oauth_params, to_rfc3986, ', ', true);
	console.error('header_auth_str:', header_auth_str);
	
	return {
		url: aURL,
		method: aMethod,
		header_auth: 'OAuth ' + header_auth_str,
		postDataStr: aOptions.postData ? jQLike.serialize(aOptions.postData) : null // this is a serialized version of the aOptions.postData object
	};
}

var cReqDetail = twitterRequestDetails('https://api.twitter.com/oauth/request_token', 'POST', 'AjONvgAdbD8YWCtRn5U9yA', {
	extraOauthParams: {
		oauth_callback: 'http://127.0.0.1/floppers'
	}
});
console.error('cReqDetail:', cReqDetail);
Request({
	url: cReqDetail.url,
	anonymous: true,
	headers: {
		Authorization: cReqDetail.header_auth
	},
	onComplete: function (response) {
		console.error(response.text, response.json);
		
		// tabs.open('https://api.twitter.com/oauth2/token?' + jQLike.serialize({
			// oauth_token: response.json.oauth_token,
		// });
	}
})[cReqDetail.method.toLowerCase()]();

console.error('ok did req');