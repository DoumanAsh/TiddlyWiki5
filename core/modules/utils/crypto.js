/*\
title: $:/core/modules/utils/crypto.js
type: application/javascript
module-type: utils

Utility functions related to crypto.

\*/
(function(){

/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

/**
 * Creates Crypto instance with optional `salt` to derive key components
 *
 * If not used use some pre-defined constant
 */
exports.Crypto = function(salt) {
    //node.js provides compatibility with Web API
    var inner = typeof window !== 'undefined' ? window.crypto : require('crypto').webcrypto;

    //node.js compatibility do not have these globally exported
    if (typeof window === 'undefined') {
        var { TextEncoder, TextDecoder } = require("util");
    }

    var enc = new TextEncoder();
    var dec = new TextDecoder();

    if (typeof salt === 'string') {
        salt = enc.encode(salt)
    } else if (typeof salt === 'undefined') {
        salt = Uint8Array.from([84, 105, 100, 100, 108, 121, 87, 105, 107, 105, 53])
    }

    function randomLen(length) {
        return inner.getRandomValues(new Uint8Array(length));
    }

    function importKey(password) {
        return inner.subtle.importKey(
            "raw",
            enc.encode(password),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"],
        );
    }
    function deriveKey(keyMaterial) {
        var params = {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256",
        };
        return inner.subtle.deriveKey(
            params,
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"],
        );
    }

    function generateKey(password) {
        return importKey(password).then(deriveKey)
    }

    function encrypt(input, key_or_password) {
        var key = typeof key_or_password === 'CryptoKey' ? Promise.resolve(key_or_password) : this.generateKey(key_or_password);
        var algo = {
            name: "AES-GCM",
            //AES-GCM needs 12 bytes nonce
            iv: randomLen(12),
        };
        function perform_encrypt(key) {
            return inner.subtle.encrypt(algo, key, enc.encode(input));
        }

        function encode(buffer) {
            //Not the most subtle encoding so could use improvement
            return JSON.stringify({
                data: Array.from(new Uint8Array(buffer)),
                iv: Array.from(algo.iv)
            });
        }

        return key.then(perform_encrypt).then(encode);
    }

    function decrypt(input, key_or_password) {
        var key = typeof key_or_password === 'CryptoKey' ? Promise.resolve(key_or_password) : this.generateKey(key_or_password);

        function perform_decrypt(key)  {
            input = JSON.parse(input);
            var algo = {
                name: "AES-GCM",
                iv: Uint8Array.from(input.iv)
            };

            return inner.subtle.decrypt(algo, key, Uint8Array.from(input.data));
        }

        function decode(buffer) {
            var result = dec.decode(new Uint8Array(buffer));
            return Promise.resolve(result);
        }

        return key.then(perform_decrypt).then(decode)
    }

    return {
        ///Async function to generate Key for AES-GCM algo
        generateKey,
        ///Async function to perform AES encryption
        encrypt,
        ///Async function to perform AES decryption
        decrypt,
    };
}

/*
Look for an encrypted store area in the text of a TiddlyWiki file
*/
exports.extractEncryptedStoreArea = function(text) {
	var encryptedStoreAreaStartMarker = "<pre id=\"encryptedStoreArea\" type=\"text/plain\" style=\"display:none;\">",
		encryptedStoreAreaStart = text.indexOf(encryptedStoreAreaStartMarker);
	if(encryptedStoreAreaStart !== -1) {
		var encryptedStoreAreaEnd = text.indexOf("</pre>",encryptedStoreAreaStart);
		if(encryptedStoreAreaEnd !== -1) {
			return $tw.utils.htmlDecode(text.substring(encryptedStoreAreaStart + encryptedStoreAreaStartMarker.length,encryptedStoreAreaEnd));
		}
	}
	return null;
};

/*
Attempt to extract the tiddlers from an encrypted store area using the current password. If the password is not provided then the password in the password store will be used
*/
exports.decryptStoreArea = function(encryptedStoreArea,password) {
	var decryptedText = $tw.crypto.decrypt(encryptedStoreArea,password);
	if(decryptedText) {
		var json = $tw.utils.parseJSONSafe(decryptedText),
			tiddlers = [];
		for(var title in json) {
			if(title !== "$:/isEncrypted") {
				tiddlers.push(json[title]);
			}
		}
		return tiddlers;
	} else {
		return null;
	}
};


/*
Attempt to extract the tiddlers from an encrypted store area using the current password. If that fails, the user is prompted for a password.
encryptedStoreArea: text of the TiddlyWiki encrypted store area
callback: function(tiddlers) called with the array of decrypted tiddlers

The following configuration settings are supported:

$tw.config.usePasswordVault: causes any password entered by the user to also be put into the system password vault
*/
exports.decryptStoreAreaInteractive = function(encryptedStoreArea,callback,options) {
	// Try to decrypt with the current password
	var tiddlers = $tw.utils.decryptStoreArea(encryptedStoreArea);
	if(tiddlers) {
		callback(tiddlers);
	} else {
		// Prompt for a new password and keep trying
		$tw.passwordPrompt.createPrompt({
			serviceName: "Enter a password to decrypt the imported TiddlyWiki",
			noUserName: true,
			canCancel: true,
			submitText: "Decrypt",
			callback: function(data) {
				// Exit if the user cancelled
				if(!data) {
					return false;
				}
				// Attempt to decrypt the tiddlers
				var tiddlers = $tw.utils.decryptStoreArea(encryptedStoreArea,data.password);
				if(tiddlers) {
					if($tw.config.usePasswordVault) {
						$tw.crypto.setPassword(data.password);
					}
					callback(tiddlers);
					// Exit and remove the password prompt
					return true;
				} else {
					// We didn't decrypt everything, so continue to prompt for password
					return false;
				}
			}
		});
	}
};

})();
