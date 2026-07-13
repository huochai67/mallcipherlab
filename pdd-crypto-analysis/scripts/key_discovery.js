'use strict';

/**
 * AES Key Discovery Harness for PDD encrypt_info.
 *
 * The core problem: Xre() generates a random 32-char key and 16-char IV,
 * sends them via csr_risk_token (RSA-encrypted), but decrypting the response
 * with the same key/IV FAILS.
 *
 * This script tests multiple key derivation strategies to find the actual
 * decryption key used by the Rre VM / CryptoJS.AES.decrypt.
 *
 * Usage:
 *   node scripts/key_discovery.js '<encrypt_info>' '<captured-key>' '<captured-iv>'
 *
 * To capture key/IV from browser:
 *   1. Open PDD goods page in Chrome
 *   2. Pause on Script First Statement
 *   3. Set breakpoint on CryptoJS.AES.decrypt
 *   4. Record: keyWA.toString(CryptoJS.enc.Utf8) and ivWA.toString(CryptoJS.enc.Utf8)
 *   5. Feed them to this script
 */

const crypto = require('crypto');
const zlib = require('zlib');
const { parseEncryptInfo } = require('./aes_response');

// ============================================================
// Key Derivation Strategies
// ============================================================

const STRATEGIES = {

    /**
     * Strategy 1: Direct use of captured key/IV as UTF-8 strings.
     * This is what Xre() returns: 32-char alphanumeric key + 16-char alphanumeric IV.
     */
    direct(key, iv) {
        return { name: 'direct (UTF-8 pass-through)', key: Buffer.from(key, 'utf8'), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 2: MD5 hash of key string → 16-byte key (AES-128)
     */
    md5Key(key, iv) {
        return { name: 'MD5(key)', key: crypto.createHash('md5').update(key).digest(), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 3: MD5 hash of key+iv concatenation → 16-byte key
     */
    md5KeyIv(key, iv) {
        const h = crypto.createHash('md5').update(key + iv).digest();
        return { name: 'MD5(key+iv)', key: h, iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 4: SHA-256 of key → 32-byte key
     */
    sha256Key(key, iv) {
        return { name: 'SHA-256(key)', key: crypto.createHash('sha256').update(key).digest(), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 5: SHA-256 of (key+iv) → 32-byte key
     */
    sha256KeyIv(key, iv) {
        const h = crypto.createHash('sha256').update(key + iv).digest();
        return { name: 'SHA-256(key+iv)', key: h, iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 6: SHA-256 of key → first 16 bytes as key (AES-128)
     */
    sha256Key128(key, iv) {
        return { name: 'SHA-256(key)[0:16] (AES-128)', key: crypto.createHash('sha256').update(key).digest().slice(0, 16), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 7: MD5 of key as hex → 32-char hex string → 32-byte UTF-8 key
     */
    md5KeyHex(key, iv) {
        const hex = crypto.createHash('md5').update(key).digest('hex');
        return { name: 'MD5(key).hex as UTF-8', key: Buffer.from(hex, 'utf8'), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 8: SHA-256 of key as hex → 64-char hex string → 64-byte (truncate to 32 for AES-256)
     */
    sha256KeyHex(key, iv) {
        const hex = crypto.createHash('sha256').update(key).digest('hex');
        return { name: 'SHA-256(key).hex[0:32] as UTF-8', key: Buffer.from(hex.slice(0, 32), 'utf8'), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 9: HMAC-SHA256 with key as message, iv as HMAC key → 32 bytes
     */
    hmacKeyIv(key, iv) {
        const h = crypto.createHmac('sha256', iv).update(key).digest();
        return { name: 'HMAC-SHA256(iv, key)', key: h, iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 10: HMAC-SHA256 with iv as message, key as HMAC key → 32 bytes
     */
    hmacIvKey(key, iv) {
        const h = crypto.createHmac('sha256', key).update(iv).digest();
        return { name: 'HMAC-SHA256(key, iv)', key: h, iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 11: XOR key bytes with IV bytes (repeating IV)
     */
    xorWithIv(key, iv) {
        const k = Buffer.from(key, 'utf8');
        const i = Buffer.from(iv, 'utf8');
        const result = Buffer.alloc(32);
        for (let j = 0; j < 32; j++) {
            result[j] = k[j % k.length] ^ i[j % i.length];
        }
        return { name: 'XOR(key, iv-repeat)', key: result, iv: i };
    },

    /**
     * Strategy 12: Key as bytes and IV as bytes (no UTF-8 encoding)
     * Some libraries treat alphanumeric strings as byte arrays.
     */
    keyAsBytesWithPad(key, iv) {
        const k = Buffer.from(key, 'utf8');
        const i = Buffer.from(iv, 'utf8');
        const padded = Buffer.alloc(32);
        k.copy(padded, 0, 0, Math.min(k.length, 32));
        return { name: 'key bytes padded to 32', key: padded, iv: i };
    },

    /**
     * Strategy 13: Key reversed + IV reversed
     */
    reversed(key, iv) {
        const kr = Buffer.from(key.split('').reverse().join(''), 'utf8');
        const ir = Buffer.from(iv.split('').reverse().join(''), 'utf8');
        return { name: 'reversed(key+iv)', key: kr, iv: ir };
    },

    /**
     * Strategy 14: AES-128-CBC (first 16 bytes of key)
     */
    aes128(key, iv) {
        return { name: 'AES-128-CBC (key[0:16])', key: Buffer.from(key.slice(0, 16), 'utf8'), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 15: AES-192-CBC (first 24 bytes of key)
     */
    aes192(key, iv) {
        return { name: 'AES-192-CBC (key[0:24])', key: Buffer.from(key.slice(0, 24), 'utf8'), iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 16: PBKDF2 (key, iv, 1 iteration, 32 bytes)
     */
    pbkdf2_1(key, iv) {
        const derived = crypto.pbkdf2Sync(key, iv, 1, 32, 'sha256');
        return { name: 'PBKDF2-SHA256(key, iv, iter=1)', key: derived, iv: Buffer.from(iv, 'utf8') };
    },

    /**
     * Strategy 17: PBKDF2 (key, iv, 1000 iterations, 32+16 bytes)
     */
    pbkdf2_1000(key, iv) {
        const derived = crypto.pbkdf2Sync(key, iv, 1000, 48, 'sha256');
        return { name: 'PBKDF2-SHA256(key, iv, iter=1000, 48B)', key: derived.slice(0, 32), iv: derived.slice(32, 48) };
    },

    /**
     * Strategy 18: MD5 of csr_risk_token as key
     */
    md5CsrToken(key, iv) {
        return { name: 'MD5(csr_token as key)', key: crypto.createHash('md5').update(key).digest(), iv: crypto.createHash('md5').update(iv).digest() };
    },
};

// ============================================================
// Decryption Test
// ============================================================

function tryDecrypt(ciphertext, keyBuf, ivBuf, strategyName) {
    const keyLen = keyBuf.length;
    const algo = keyLen === 32 ? 'aes-256-cbc' : keyLen === 24 ? 'aes-192-cbc' : keyLen === 16 ? 'aes-128-cbc' : null;

    if (!algo) {
        return { strategy: strategyName, success: false, error: `Invalid key length: ${keyLen}` };
    }

    try {
        const decipher = crypto.createDecipheriv(algo, keyBuf, ivBuf);
        decipher.setAutoPadding(true);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

        // Try direct JSON parse first (small/old responses may not be compressed)
        try {
            const text = plaintext.toString('utf8');
            JSON.parse(text);
            return { strategy: strategyName, success: true, algo, plaintext: text };
        } catch (e) { /* not uncompressed JSON */ }

        // Try zlib inflate (PDD compresses response JSON with deflate)
        try {
            const decompressed = zlib.inflateSync(plaintext).toString('utf8');
            JSON.parse(decompressed);
            return { strategy: strategyName, success: true, algo, inflated: true, plaintext: decompressed };
        } catch (e) { /* not compressed either */ }

        return { strategy: strategyName, success: false, algo,
            partial: plaintext.slice(0, 40).toString('hex'),
            error: 'decrypted but not JSON/not inflatable' };
    } catch (e) {
        return { strategy: strategyName, success: false, algo, error: e.message.substring(0, 80) };
    }
}

// ============================================================
// Main
// ============================================================

function discoverKey(encryptInfo, rawKey, rawIv) {
    console.log('='.repeat(70));
    console.log('PDD AES Key Discovery Harness');
    console.log('='.repeat(70));

    let parsed;
    try {
        parsed = parseEncryptInfo(encryptInfo);
    } catch (e) {
        console.error('Failed to parse encrypt_info:', e.message);
        return;
    }

    console.log(`\nParsed encrypt_info:`);
    console.log(`  Transport prefix: "${parsed.transportPrefix}" (${parsed.prefixLen} chars)`);
    console.log(`  Transport suffix: "${parsed.transportSuffix}" (${parsed.suffixLen} chars)`);
    console.log(`  AES ciphertext: ${parsed.ciphertext.length} bytes (${parsed.ciphertext.length / 16} blocks)`);
    console.log(`\nInput key (from browser): "${rawKey}" (${rawKey.length} chars)`);
    console.log(`Input IV  (from browser):  "${rawIv}" (${rawIv.length} chars)`);

    console.log(`\n${'─'.repeat(70)}`);
    console.log('Testing derivation strategies...');
    console.log(`${'─'.repeat(70)}`);

    const results = [];
    for (const [stratName, stratFn] of Object.entries(STRATEGIES)) {
        const { name, key, iv } = stratFn(rawKey, rawIv);
        const result = tryDecrypt(parsed.ciphertext, key, iv, name);

        const marker = result.success ? '✓' : '✗';
        const detail = result.success ? ('SUCCESS' + (result.inflated ? ' (zlib)' : '')) : (result.error || result.detail || 'unknown');
        console.log(`  ${marker} ${name.padEnd(42)} | ${detail.substring(0, 45)}`);

        if (result.success) {
            results.push(result);
        }
    }

    console.log(`\n${'─'.repeat(70)}`);

    if (results.length > 0) {
        console.log(`\n✓✓✓ SUCCESS! ${results.length} strategies decrypted successfully.`);
        for (const r of results) {
            console.log(`\nStrategy: ${r.strategy}`);
            console.log(`Algorithm: ${r.algo}`);
            console.log(`Decrypted data preview:`);
            try {
                const data = JSON.parse(r.plaintext);
                console.log(JSON.stringify(data, null, 2).substring(0, 1000));
            } catch (e) {
                console.log(r.plaintext.substring(0, 500));
            }
        }
    } else {
        console.log('\nNo strategy succeeded. Possible causes:');
        console.log('  1. The captured key/IV are from a different session than the encrypt_info');
        console.log('  2. The key/IV captured from browser are not the actual decrypt parameters');
        console.log('  3. The plaintext is compressed (zlib deflate) — already handled automatically');
        console.log('');
        console.log('Next steps:');
        console.log('  - Ensure encrypt_info and key/IV are from the SAME API call');
        console.log('  - In Chrome, verify: window.__pdd.encrypted.encrypt_info matches Network tab');
    }
}

// CLI
if (require.main === module) {
    const [encryptInfo, key, iv] = process.argv.slice(2);
    if (!encryptInfo || !key || !iv) {
        console.log('Usage: node scripts/key_discovery.js <encrypt_info> <key-32-chars> <iv-16-chars>');
        console.log('');
        console.log('Example:');
        console.log('  node scripts/key_discovery.js "<encrypt_info>" "v2178xxxxxxxxxxxxxxxxxxxxxxxxxxx" "xxxxxxxxxxxxxxxx"');
        console.log('');
        console.log('To capture key/IV from browser:');
        console.log('  // In Chrome DevTools console (after breakpoint on CryptoJS.AES.decrypt):');
        console.log('  keyWA.toString(CryptoJS.enc.Utf8)  // → 32-char string');
        console.log('  ivWA.toString(CryptoJS.enc.Utf8)   // → 16-char string');
        process.exit(2);
    }

    discoverKey(encryptInfo, key, iv);
}

module.exports = { discoverKey, STRATEGIES, tryDecrypt };
