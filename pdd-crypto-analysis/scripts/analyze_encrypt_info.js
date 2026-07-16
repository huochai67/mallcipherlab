'use strict';

/** Inspect the exact Qre program-1 encrypt_info wire format. */

const fs = require('fs');
const path = require('path');
const { parseEncryptInfo } = require('./aes_response');

function analyze(encryptInfo) {
    const parsed = parseEncryptInfo(encryptInfo);
    const paddingNeeded = (4 - (parsed.core.length % 4)) % 4;
    const result = {
        totalChars: encryptInfo.length,
        coreChars: parsed.core.length,
        compressionMarker: parsed.compressionMarker,
        compressed: parsed.compressed,
        base64PaddingNeeded: paddingNeeded,
        ciphertextBytes: parsed.ciphertext.length,
        aesBlocks: parsed.ciphertext.length / 16,
    };

    console.log(JSON.stringify(result, null, 2));
    return result;
}

function loadDefaultFixture() {
    const payloadPath = path.join(__dirname, '..', 'data', 'payload.json');
    if (!fs.existsSync(payloadPath)) return null;
    const payload = JSON.parse(fs.readFileSync(payloadPath, 'utf8'));
    return payload.encrypt_info || null;
}

if (require.main === module) {
    const encryptInfo = process.argv[2] || loadDefaultFixture();
    if (!encryptInfo) {
        console.error('Usage: node scripts/analyze_encrypt_info.js <encrypt_info>');
        process.exitCode = 2;
    } else {
        try {
            analyze(encryptInfo);
        } catch (error) {
            console.error('ERROR:', error.message);
            process.exitCode = 1;
        }
    }
}

module.exports = { analyze };
