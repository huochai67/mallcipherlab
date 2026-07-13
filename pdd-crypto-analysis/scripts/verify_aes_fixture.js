'use strict';

/**
 * Verify the encrypt_info wire format by round-tripping a known sample.
 */
const { encryptResponse, parseEncryptInfo, decryptResponse } = require('./aes_response');

const key = 'abcdefghijklmnopqrstuvwxyz012345';
const iv = 'abcdefghijklmnop';
const sample = { goods: { goods_id: 1 }, price: { min_group_price: 100 } };

// Generate encrypt_info with known prefix/suffix
const enc = encryptResponse(sample, key, iv, 'mf2-NC', 'F_');

// Parse it back
const parsed = parseEncryptInfo(enc);
console.log('transport prefix:', JSON.stringify(parsed.transportPrefix));
console.log('transport suffix:', JSON.stringify(parsed.transportSuffix));
console.log('ciphertext length:', parsed.ciphertext.length);
console.log('prefix len:', parsed.prefixLen, 'suffix len:', parsed.suffixLen);

if (parsed.ciphertext.length === 0 || parsed.ciphertext.length % 16 !== 0) {
    throw new Error('ciphertext is not AES block aligned');
}

// Full round-trip
const dec = decryptResponse(enc, key, iv);
if (JSON.stringify(dec.data) === JSON.stringify(sample)) {
    console.log('wire-format fixture: PASS');
} else {
    throw new Error('round-trip mismatch');
}
