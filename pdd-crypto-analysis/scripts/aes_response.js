'use strict';

/**
 * PDD encrypt_info AES-256-CBC decrypt + zlib inflate.
 *
 * Complete pipeline:
 *   1. Strip transport prefix+suffix from base64url encrypt_info
 *   2. Base64url decode → AES-256-CBC ciphertext (16-byte aligned)
 *   3. AES decrypt with key(32B UTF-8) + IV(16B UTF-8) → deflate-compressed JSON
 *   4. zlib.inflate → JSON string
 *   5. JSON.parse → goods data
 *
 * Usage:
 *   node scripts/aes_response.js '<encrypt_info>' '<32-byte-key>' '<16-byte-iv>'
 *
 *   const { parseEncryptInfo, decrypt } = require('./aes_response');
 *   const { goods, price, sku } = decrypt(encryptInfo, key, iv);
 */
const crypto = require('crypto');
const zlib = require('zlib');

const TRANSPORT_PREFIX_LENGTH = 6;
const TRANSPORT_SUFFIX_LENGTH = 2;

/**
 * Parse encrypt_info, automatically detecting prefix/suffix boundaries.
 * The ciphertext base64url portion must have length divisible by 4,
 * and decode to a length divisible by 16 (AES block size).
 */
function parseEncryptInfo(encryptInfo) {
    if (typeof encryptInfo !== 'string' || encryptInfo.length < 16) {
        throw new TypeError('encrypt_info must be a non-empty string');
    }

    // Known format from reverse engineering: 6-char prefix + base64url + 2-char suffix.
    // Try this first (most common). The prefix+suffix chars adjust so the core
    // base64url portion has length divisible by 4.
    const preferredPairs = [
        [6, 2],   // most common: seen in decrypt_test.js sample
        [0, 1],   // seen in payload.json sample
    ];
    const allPairs = [];
    for (const [pl, sl] of preferredPairs) {
        allPairs.push([pl, sl]);
    }
    for (let prefixLen = 0; prefixLen <= 10; prefixLen++) {
        for (let suffixLen = 0; suffixLen <= 10; suffixLen++) {
            const key = prefixLen * 100 + suffixLen;
            if (!preferredPairs.some(([pl, sl]) => pl === prefixLen && sl === suffixLen)) {
                allPairs.push([prefixLen, suffixLen]);
            }
        }
    }

    for (const [prefixLen, suffixLen] of allPairs) {
        if (prefixLen + suffixLen >= encryptInfo.length) continue;

        const core = encryptInfo.slice(prefixLen, suffixLen > 0 ? -suffixLen : undefined);
        if (core.length % 4 !== 0) continue;

        const b64 = core.replace(/-/g, '+').replace(/_/g, '/');
        const decoded = Buffer.from(b64, 'base64');
        if (decoded.length === 0) continue;
        if (decoded.length % 16 !== 0) continue;

        return {
            transportPrefix: encryptInfo.slice(0, prefixLen),
            transportSuffix: suffixLen > 0 ? encryptInfo.slice(-suffixLen) : '',
            prefixLen,
            suffixLen,
            ciphertext: decoded
        };
    }

    throw new Error('Could not parse encrypt_info: no valid AES-aligned boundaries found');
}

/**
 * Decrypt encrypt_info with the given AES-256-CBC key and IV.
 * Handles zlib-compressed plaintext (PDD compresses response JSON with deflate).
 *
 * Key must be 32 chars UTF-8, IV must be 16 chars UTF-8.
 * Returns { transportPrefix, transportSuffix, plaintext, decompressed, data }
 */
function decrypt(encryptInfo, key, iv) {
    const keyBuf = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
    const ivBuf = typeof iv === 'string' ? Buffer.from(iv, 'utf8') : iv;

    if (keyBuf.length !== 32) throw new RangeError(`AES-256-CBC requires 32-byte key, got ${keyBuf.length}`);
    if (ivBuf.length !== 16) throw new RangeError(`AES-256-CBC requires 16-byte IV, got ${ivBuf.length}`);

    const { transportPrefix, transportSuffix, ciphertext, prefixLen, suffixLen } = parseEncryptInfo(encryptInfo);

    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuf, ivBuf);
    decipher.setAutoPadding(true);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // The plaintext is zlib (deflate) compressed JSON
    let decompressed;
    try {
        decompressed = zlib.inflateSync(plaintext);
    } catch(e) {
        // Fallback: may be uncompressed JSON (small responses or older versions)
        decompressed = plaintext;
    }

    const jsonStr = decompressed.toString('utf8');
    try {
        const data = JSON.parse(jsonStr);
        return { transportPrefix, transportSuffix, prefixLen, suffixLen, plaintext, decompressed, jsonStr, data };
    } catch (e) {
        return { transportPrefix, transportSuffix, prefixLen, suffixLen, plaintext, decompressed, jsonStr, data: null, parseError: e.message };
    }
}

// Backward compat alias
function decryptResponse(encryptInfo, key, iv) {
    return decrypt(encryptInfo, key, iv);
}

/**
 * Encrypt JSON data, matching PDD's format (zlib deflate + AES-256-CBC).
 */
function encrypt(data, key, iv, transportPrefix, transportSuffix) {
    const keyBuf = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
    const ivBuf = typeof iv === 'string' ? Buffer.from(iv, 'utf8') : iv;

    if (keyBuf.length !== 32) throw new RangeError(`AES-256-CBC requires 32-byte key, got ${keyBuf.length}`);
    if (ivBuf.length !== 16) throw new RangeError(`AES-256-CBC requires 16-byte IV, got ${ivBuf.length}`);

    if (!transportPrefix) transportPrefix = '';
    if (!transportSuffix) transportSuffix = '';

    // Step 1: JSON → deflate compress
    const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
    const compressed = zlib.deflateSync(Buffer.from(jsonStr, 'utf8'));

    // Step 2: AES-256-CBC encrypt
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuf, ivBuf);
    cipher.setAutoPadding(true);
    const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);

    // Step 3: Base64url encode + transport wrapper
    const fullB64 = ciphertext.toString('base64');
    const b64url = fullB64.replace(/\+/g, '-').replace(/\//g, '_');

    let core = b64url;
    if (core.length % 4 !== 0) {
        core = core.replace(/=+$/g, '');
    }

    return transportPrefix + core + transportSuffix;
}

// Backward compat
function encryptResponse(data, key, iv, transportPrefix, transportSuffix) {
    return encrypt(data, key, iv, transportPrefix, transportSuffix);
}

module.exports = {
    TRANSPORT_PREFIX_LENGTH,
    TRANSPORT_SUFFIX_LENGTH,
    parseEncryptInfo,
    decrypt,
    encrypt,
    decryptResponse,
    encryptResponse
};

if (require.main === module) {
    const [encryptInfo, key, iv] = process.argv.slice(2);
    if (!encryptInfo || !key || !iv) {
        console.error('Usage: node scripts/aes_response.js <encrypt_info> <key-32-chars> <iv-16-chars>');
        console.error('');
        console.error('Decrypts PDD goods API response. Key/IV are UTF-8 strings captured');
        console.error('from browser CryptoJS.AES.decrypt breakpoint.');
        process.exitCode = 2;
    } else {
        try {
            const result = decrypt(encryptInfo, key, iv);
            if (result.data) {
                console.log('SUCCESS');
                console.log(`Prefix: ${JSON.stringify(result.transportPrefix)} (${result.prefixLen})`);
                console.log(`Suffix: ${JSON.stringify(result.transportSuffix)} (${result.suffixLen})`);
                if (result.data.goods) {
                    console.log(`Goods:  ${result.data.goods.goods_id} | ${result.data.goods.goods_name}`);
                }
                if (result.data.price) {
                    console.log(`Price:  min=${result.data.price.min_group_price} max=${result.data.price.max_group_price}`);
                }
                console.log('Data:', JSON.stringify(result.data, null, 2));
            } else {
                console.error('FAILED: plaintext is not valid JSON');
                console.error(result.jsonStr ? result.jsonStr.substring(0, 300) : 'empty');
            }
        } catch (e) {
            console.error('ERROR:', e.message);
            process.exitCode = 1;
        }
    }
}
