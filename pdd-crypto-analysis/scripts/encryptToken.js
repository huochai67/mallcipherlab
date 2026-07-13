'use strict';

/**
 * PDD crypto module: csr_risk_token generation + response decryption.
 *
 * Usage:
 *   const { getcsr_risk_token, decryptResponse } = require('./encryptToken');
 *
 *   const token = getcsr_risk_token();
 *   // → { encryptedData, key, iv }
 *   // encryptedData → request body csr_risk_token
 *   // key (32 base64url chars) + iv (16 base64url chars) → decrypt response
 *
 *   const data = decryptResponse(resp.encrypt_info, token.key, token.iv);
 */
const crypto = require('crypto');
const { decrypt } = require('./aes_response');

// ── RSA public key extracted from PDD main bundle Hk()[41] ──
const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkzFlw7BUJTlbFYd9VYUZ
lsgd40jdVCoxdFi1l6UO6HflptLWHAU+IZItMBVHrIEd3FVgVCeA9idY9XaQAABu
P4irOLm4haXvvsJZP7hi6SjORh/c/ZEDExEjLfzvMcGDL1k36ILqq49tvY4dEgaZ
sm9+LFOcL1IP0AtcMWZrLKC2H5jpTg6AUY4BjTZZ2gatFrNBVNYzFOS5VDGa8Vjr
Nlo8QsEFzQQjQCC7A5PToo/F2GnUfKADnRuLfLG1eujUMfmZBs9TD8XByj3HZzkb
AQJ1nanImWwggnuPq3aGvKmGMmc8Ue9E82kaz98VhpR7tv8EKKnkXNsI26NSrmcU
XwIDAQAB
-----END PUBLIC KEY-----`;

// ── key/IV generation ─────────────────────────────────────
// Browser Xre() generates base64url-encoded random bytes:
//   24 random bytes → 32 base64url chars (key)
//   12 random bytes → 16 base64url chars (iv)
// Observed from browser-captured keys: they contain '-' (a base64url character)
const KEY_BYTES = 24;
const IV_BYTES = 12;

function toBase64url(buf) {
    return buf.toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Generate csr_risk_token for a request.
 * Returns { encryptedData, key, iv }.
 */
function getcsr_risk_token() {
    const rawKey = crypto.randomBytes(KEY_BYTES);   // 24 bytes
    const rawIv = crypto.randomBytes(IV_BYTES);     // 12 bytes
    const key = toBase64url(rawKey);                 // 32 base64url chars
    const iv = toBase64url(rawIv);                   // 16 base64url chars

    // RSA encrypt key+iv (48 ASCII bytes) with PKCS#1 v1.5
    const plaintext = key + iv;
    const encrypted = crypto.publicEncrypt({
        key: RSA_PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, Buffer.from(plaintext, 'utf-8'));

    return {
        encryptedData: encrypted.toString('base64'),   // ~344 chars → csr_risk_token
        key,      // 32 chars → AES decrypt
        iv,       // 16 chars → AES decrypt
        rawKey,   // 24 raw bytes (for alternative AES-192 mode)
        rawIv     // 12 raw bytes
    };
}

/**
 * Decrypt encrypt_info from server response.
 * Complete pipeline: transport → base64url → AES-256-CBC → zlib → JSON.
 */
function decryptResponse(encryptInfo, key, iv) {
    const result = decrypt(encryptInfo, key, iv);
    if (!result.data) {
        throw new Error('Decryption produced non-JSON: ' + (result.jsonStr || '').substring(0, 100));
    }
    return result.data;
}

module.exports = { getcsr_risk_token, decryptResponse, RSA_PUBLIC_KEY };
