'use strict';
const { parseEncryptInfo, encryptResponse, decryptResponse } = require('./aes_response');
const fs = require('fs');

let pass = true;

// Test: payload.json (skip only when the optional fixture is absent)
const payloadPath = __dirname + '/../data/payload.json';
if (fs.existsSync(payloadPath)) {
    const payload = JSON.parse(fs.readFileSync(payloadPath, 'utf8'));
    const r1 = parseEncryptInfo(payload.encrypt_info);
    console.log('Payload parse: PASS (marker=' + JSON.stringify(r1.compressionMarker) + ')');
} else {
    console.log('Payload parse: SKIP (data/payload.json not found)');
}

// Test: decrypt_test.js (skip only when the optional fixture is absent)
const legacyFixturePath = __dirname + '/decrypt_test.js';
if (fs.existsSync(legacyFixturePath)) {
    const source = fs.readFileSync(legacyFixturePath, 'utf8');
    const marker = 'const encrypt_info = `';
    const start = source.indexOf(marker) + marker.length;
    const ei = source.slice(start, source.indexOf('`', start));
    const r2 = parseEncryptInfo(ei);
    console.log('Fixture parse: PASS (marker=' + JSON.stringify(r2.compressionMarker) + ')');
} else {
    console.log('Fixture parse: SKIP (decrypt_test.js not found)');
}

// Test: Round-trip encrypt/decrypt
const key = 'abcdefghijklmnopqrstuvwxyz012345';
const iv = 'abcdefghijklmnop';
const data = { hello: 'world', num: 42 };
const enc = encryptResponse(data, key, iv, { compress: true });
const parsed = parseEncryptInfo(enc);
if (parsed.compressionMarker !== '1' || parsed.prefixLen !== 0 || parsed.suffixLen !== 1) {
    throw new Error('compressed wire marker mismatch');
}
const dec = decryptResponse(enc, key, iv);
const ok = JSON.stringify(dec.data) === JSON.stringify(data);
console.log('Round-trip: ' + (ok ? 'PASS' : 'FAIL'));
if (!ok) pass = false;

const plainEnc = encryptResponse(data, key, iv, { compress: false });
const plainDec = decryptResponse(plainEnc, key, iv);
const plainOk = plainEnc.endsWith('0') && JSON.stringify(plainDec.data) === JSON.stringify(data);
console.log('Uncompressed marker: ' + (plainOk ? 'PASS' : 'FAIL'));
if (!plainOk) pass = false;

console.log('\n' + (pass ? 'All tests complete.' : 'SOME TESTS FAILED'));
