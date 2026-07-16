'use strict';

/**
 * Verify the encrypt_info wire format by round-tripping a known sample.
 */
const { encryptResponse, parseEncryptInfo, decryptResponse } = require('./aes_response');

const key = 'abcdefghijklmnopqrstuvwxyz012345';
const iv = 'abcdefghijklmnop';
const sample = { goods: { goods_id: 1 }, price: { min_group_price: 100 } };

// Generate exact Qre wire format: unpadded base64url ciphertext + marker "1".
const enc = encryptResponse(sample, key, iv, { compress: true });

// Parse it back
const parsed = parseEncryptInfo(enc);
console.log('compression marker:', JSON.stringify(parsed.compressionMarker));
console.log('ciphertext length:', parsed.ciphertext.length);
console.log('base64url core length:', parsed.core.length);

if (parsed.ciphertext.length === 0 || parsed.ciphertext.length % 16 !== 0) {
    throw new Error('ciphertext is not AES block aligned');
}
if (parsed.compressionMarker !== '1' || parsed.prefixLen !== 0 || parsed.suffixLen !== 1) {
    throw new Error('Qre wire marker mismatch');
}

// Full round-trip
const dec = decryptResponse(enc, key, iv);
if (JSON.stringify(dec.data) === JSON.stringify(sample)) {
    console.log('wire-format fixture: PASS');
} else {
    throw new Error('round-trip mismatch');
}
