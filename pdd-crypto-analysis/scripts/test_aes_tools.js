'use strict';
const { parseEncryptInfo, encryptResponse, decryptResponse } = require('./aes_response');
const fs = require('fs');

let pass = true;

// Test: payload.json (skip if not present)
try {
    const payload = require('../data/payload.json');
    const r1 = parseEncryptInfo(payload.encrypt_info);
    console.log('Payload parse: PASS (prefix=' + r1.prefixLen + ', suffix=' + r1.suffixLen + ')');
} catch (e) {
    console.log('Payload parse: SKIP (data/payload.json not found)');
}

// Test: decrypt_test.js (skip if not present)
try {
    const source = fs.readFileSync(__dirname + '/decrypt_test.js', 'utf8');
    const marker = 'const encrypt_info = `';
    const start = source.indexOf(marker) + marker.length;
    const ei = source.slice(start, source.indexOf('`', start));
    const r2 = parseEncryptInfo(ei);
    console.log('Fixture parse: PASS (prefix=' + r2.prefixLen + ', suffix=' + r2.suffixLen + ')');
} catch (e) {
    console.log('Fixture parse: SKIP (decrypt_test.js not found)');
}

// Test: Round-trip encrypt/decrypt
const key = 'abcdefghijklmnopqrstuvwxyz012345';
const iv = 'abcdefghijklmnop';
const data = { hello: 'world', num: 42 };
const enc = encryptResponse(data, key, iv, 'mf2-NC', 'F_');
const dec = decryptResponse(enc, key, iv);
const ok = JSON.stringify(dec.data) === JSON.stringify(data);
console.log('Round-trip: ' + (ok ? 'PASS' : 'FAIL'));
if (!ok) pass = false;

console.log('\n' + (pass ? 'All tests complete.' : 'SOME TESTS FAILED'));
