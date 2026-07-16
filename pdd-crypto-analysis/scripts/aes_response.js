'use strict';

/**
 * PDD encrypt_info AES-256-CBC decrypt + optional zlib inflate.
 *
 * Complete pipeline:
 *   1. Read the final compression marker and strip that one character
 *   2. Base64url decode → AES-256-CBC ciphertext (16-byte aligned)
 *   3. AES decrypt with key(32B UTF-8) + IV(16B UTF-8)
 *   4. marker === "1" ? zlib.inflate(plaintext) : plaintext
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

const TRANSPORT_PREFIX_LENGTH = 0;
const TRANSPORT_SUFFIX_LENGTH = 1;

/**
 * Exact Qre program-1 wire format:
 *
 *   encrypt_info = base64url(ciphertext, padding optional) + compressionMarker
 *   compressionMarker === "1" means zlib; every other marker means plaintext.
 */
function parseEncryptInfo(encryptInfo) {
    if (typeof encryptInfo !== 'string' || encryptInfo.length < 2) {
        throw new TypeError('encrypt_info must be a non-empty string');
    }

    const compressionMarker = encryptInfo.slice(-1);
    const core = encryptInfo.slice(0, -1);
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(core)) {
        throw new Error('encrypt_info ciphertext is not valid base64url');
    }

    let b64 = core.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const ciphertext = Buffer.from(b64, 'base64');
    if (!ciphertext.length || ciphertext.length % 16 !== 0) {
        throw new Error('encrypt_info ciphertext is not AES block aligned');
    }

    return {
        core,
        compressionMarker,
        compressed: compressionMarker === '1',
        ciphertext,
        // Compatibility fields retained for existing callers.
        transportPrefix: '',
        transportSuffix: compressionMarker,
        prefixLen: 0,
        suffixLen: 1,
    };
}

/**
 * Decrypt encrypt_info with the given AES-256-CBC key and IV.
 * Follows the final compression marker exactly as Qre program 1 does.
 *
 * Key must be 32 chars UTF-8, IV must be 16 chars UTF-8.
 * Returns { compressionMarker, compressed, plaintext, decompressed, data }
 */
function decrypt(encryptInfo, key, iv) {
    const keyBuf = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
    const ivBuf = typeof iv === 'string' ? Buffer.from(iv, 'utf8') : iv;

    if (keyBuf.length !== 32) throw new RangeError(`AES-256-CBC requires 32-byte key, got ${keyBuf.length}`);
    if (ivBuf.length !== 16) throw new RangeError(`AES-256-CBC requires 16-byte IV, got ${ivBuf.length}`);

    const parsed = parseEncryptInfo(encryptInfo);
    const { ciphertext, compressed, compressionMarker } = parsed;

    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuf, ivBuf);
    decipher.setAutoPadding(true);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    const decompressed = compressed ? zlib.inflateSync(plaintext) : plaintext;

    const jsonStr = decompressed.toString('utf8');
    try {
        const data = JSON.parse(jsonStr);
        return { ...parsed, compressionMarker, plaintext, decompressed, jsonStr, data };
    } catch (e) {
        return { ...parsed, compressionMarker, plaintext, decompressed, jsonStr, data: null, parseError: e.message };
    }
}

// Backward compat alias
function decryptResponse(encryptInfo, key, iv) {
    return decrypt(encryptInfo, key, iv);
}

/**
 * Encrypt JSON data using the exact Qre program-1 wire format.
 */
function encrypt(data, key, iv, options = {}) {
    const keyBuf = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
    const ivBuf = typeof iv === 'string' ? Buffer.from(iv, 'utf8') : iv;

    if (keyBuf.length !== 32) throw new RangeError(`AES-256-CBC requires 32-byte key, got ${keyBuf.length}`);
    if (ivBuf.length !== 16) throw new RangeError(`AES-256-CBC requires 16-byte IV, got ${ivBuf.length}`);

    if (typeof options === 'boolean') options = { compress: options };
    const compressed = options.compress !== false;

    // Step 1: JSON → optionally deflate-compressed bytes
    const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
    const plaintext = compressed
        ? zlib.deflateSync(Buffer.from(jsonStr, 'utf8'))
        : Buffer.from(jsonStr, 'utf8');

    // Step 2: AES-256-CBC encrypt
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuf, ivBuf);
    cipher.setAutoPadding(true);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    // Step 3: Base64url encode + one-character compression marker
    const core = ciphertext.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
    return core + (compressed ? '1' : '0');
}

// Backward compat
function encryptResponse(data, key, iv, options) {
    return encrypt(data, key, iv, options);
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
                console.log(`Compression marker: ${JSON.stringify(result.compressionMarker)}`);
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
