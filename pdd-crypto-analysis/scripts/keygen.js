'use strict';

/**
 * PDD key generator — reimplementation of Rre VM program 6 & 7.
 *
 * Program 6 (generateAESKey): constructs 32-char key
 *   key = "v2" + nanoid() + padding + getPreKey()
 *   where padding = derived from getCount() counter
 *
 * Program 7 (generateIV): constructs 16-char IV
 *   iv = SHA256(nanoid() + "iv").toString().substring(0, 16)
 *
 * PDD uses a custom nanoid with a base64url-like alphabet.
 */

const crypto = require('crypto');

// PDD's nanoid alphabet (found in string table: "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict")
const NANOID_ALPHABET = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';

// Local state (simulating localStorage in browser)
let keyCount = 0;
const preKeyStore = Object.create(null);

function nanoid(size = 21) {
    const bytes = crypto.randomBytes(size);
    let id = '';
    for (let i = 0; i < size; i++) {
        id += NANOID_ALPHABET[bytes[i] % NANOID_ALPHABET.length];
    }
    return id;
}

function getCount() {
    return keyCount;
}

function setCount(val) {
    keyCount = val;
}

function getPreKey() {
    const keys = Object.keys(preKeyStore);
    if (keys.length > 0) {
        return preKeyStore[keys[keys.length - 1]] || nanoid(10);
    }
    return nanoid(10);
}

function setPreKey(key, value) {
    preKeyStore[key] = value || key;
}

// ── Key generation ────────────────────────────────────────

let _counter = Math.floor(Math.random() * 1e9);

function generateAESKey() {
    // Browser key: v2 + 21_digits + 9_b64url = 32 chars
    // The 21 digits: Date.now()(13) + counter_part(8)
    const ts = String(Date.now());

    // Counter fills the gap between ts and the base64 part
    const remaining = 32 - 2 - ts.length - 9; // 9 = base64url suffix
    const ct = String(_counter++);
    if (_counter >= 1e9) _counter = 0;

    const randBytes = crypto.randomBytes(9);
    const rand = randBytes.toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
        .substring(0, 9);

    let key = 'v2' + ts + ct.padStart(remaining, '0') + rand;
    return key.substring(0, 32);
}

function generateIV() {
    // Based on Rre VM program 7 disassembly
    const rand = nanoid(21);
    const raw = rand + 'iv';
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    return hash.substring(0, 16);
}

// ── Full token generation ─────────────────────────────────

function getcsr_risk_token() {
    const key = generateAESKey();
    const iv = generateIV();

    const RSA_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkzFlw7BUJTlbFYd9VYUZ
lsgd40jdVCoxdFi1l6UO6HflptLWHAU+IZItMBVHrIEd3FVgVCeA9idY9XaQAABu
P4irOLm4haXvvsJZP7hi6SjORh/c/ZEDExEjLfzvMcGDL1k36ILqq49tvY4dEgaZ
sm9+LFOcL1IP0AtcMWZrLKC2H5jpTg6AUY4BjTZZ2gatFrNBVNYzFOS5VDGa8Vjr
Nlo8QsEFzQQjQCC7A5PToo/F2GnUfKADnRuLfLG1eujUMfmZBs9TD8XByj3HZzkb
AQJ1nanImWwggnuPq3aGvKmGMmc8Ue9E82kaz98VhpR7tv8EKKnkXNsI26NSrmcU
XwIDAQAB
-----END PUBLIC KEY-----`;

    const plaintext = key + iv;
    const encrypted = crypto.publicEncrypt({
        key: RSA_KEY,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, Buffer.from(plaintext, 'utf8'));

    return {
        encryptedData: encrypted.toString('base64'),
        key,
        iv
    };
}

module.exports = { generateAESKey, generateIV, getcsr_risk_token };

// ── CLI test ──────────────────────────────────────────────
if (require.main === module) {
    console.log('Generated key:', generateAESKey());
    console.log('Generated IV: ', generateIV());
    console.log('');
    console.log('Full token:');
    const token = getcsr_risk_token();
    console.log('  key:', token.key, '(' + token.key.length + ')');
    console.log('  iv:', token.iv, '(' + token.iv.length + ')');
    console.log('  csr:', token.encryptedData.substring(0, 40) + '...');

    console.log('\nKey starts with "v2":', token.key.startsWith('v2'));
    console.log('Expected format: v2 + timestamp + counter + random (32 chars)');
}
