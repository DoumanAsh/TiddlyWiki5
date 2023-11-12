/*\
title: modules/utils/test-crypto.js
type: application/javascript
tags: [[$:/tags/test-spec]]

Tests crypto

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

describe('CRYPTO', function() {

    it('AES with plain password', async function() {
        var crypto = require("$:/core/modules/utils/crypto.js");
        var aes = crypto.Crypto('test');
        var input = "my cute input idk";

        var encrypted = await aes.encrypt(input, "password1");
        var decrypted = await aes.decrypt(encrypted, "password1");
        expect(input).withContext("Decrypted output must match initial").toEqual(decrypted);
    });

    it('AES with prepared key', async function() {
        var crypto = require("$:/core/modules/utils/crypto.js");
        var aes = crypto.Crypto('test');
        var key = await aes.generateKey("password1");
        var input = "my cute input idk";

        var encrypted = await aes.encrypt(input, key);
        var decrypted = await aes.decrypt(encrypted, key);
        expect(input).withContext("Decrypted output must match initial").toEqual(decrypted);
    });

});

})();
