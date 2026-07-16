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
 *   // key (32 UTF-8 chars) + iv (16 hex chars) → decrypt response
 *
 *   const data = decryptResponse(resp.encrypt_info, token.key, token.iv);
 */
const crypto = require('crypto');
const { decrypt } = require('./aes_response');
const { generateKeyIv } = require('./keygen');

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

/**
 * Generate csr_risk_token for a request.
 * Returns { encryptedData, key, iv }.
 */
function getcsr_risk_token(options = {}) {
    const { key, iv } = generateKeyIv(options);

    // VM program 0 pushes IV first and then key before ADD: plaintext = iv + key.
    // This ordering is protocol-significant even though the total stays 48 bytes.
    const plaintext = iv + key;
    const encrypted = crypto.publicEncrypt({
        key: RSA_PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, Buffer.from(plaintext, 'utf-8'));

    return {
        encryptedData: encrypted.toString('base64'),   // ~344 chars → csr_risk_token
        key,
        iv,
    };
}

/**
 * Decrypt encrypt_info from server response.
 * Complete pipeline: final marker → base64url → AES-256-CBC → optional zlib → JSON.
 */
function decryptResponse(encryptInfo, key, iv) {
    const result = decrypt(encryptInfo, key, iv);
    if (!result.data) {
        throw new Error('Decryption produced non-JSON: ' + (result.jsonStr || '').substring(0, 100));
    }
    return result.data;
}

module.exports = { getcsr_risk_token, decryptResponse, RSA_PUBLIC_KEY };
