'use strict';

/**
 * Analyzes encrypt_info to determine transport prefix/suffix boundaries.
 * 
 * Key insight: base64 encodes 3 bytes → 4 chars. The ciphertext portion
 * must be a multiple of 4 base64url chars to decode to a multiple of 16 bytes.
 * This constrains valid (prefixLen, suffixLen) pairs.
 */
const crypto = require('crypto');
const fs = require('fs');

function base64urlDecode(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - b64.length % 4) % 4;
    return { raw: Buffer.from(b64 + '='.repeat(pad), 'base64'), b64, pad };
}

function analyze(encryptInfo, label) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`ANALYZING: ${label}`);
    console.log(`${'='.repeat(60)}`);
    console.log(`Total chars: ${encryptInfo.length}`);
    
    const candidates = [];
    
    for (let prefixLen = 0; prefixLen <= 10; prefixLen++) {
        for (let suffixLen = 0; suffixLen <= 10; suffixLen++) {
            if (prefixLen + suffixLen >= encryptInfo.length) continue;
            
            const core = encryptInfo.slice(prefixLen, suffixLen > 0 ? -suffixLen : undefined);
            // Core must be divisible by 4 (complete base64 groups)
            if (core.length % 4 !== 0) continue;
            
            const decoded = base64urlDecode(core);
            if (decoded.raw.length === 0) continue;
            if (decoded.raw.length % 16 !== 0) continue;
            
            candidates.push({
                prefix: encryptInfo.slice(0, prefixLen),
                suffix: suffixLen > 0 ? encryptInfo.slice(-suffixLen) : '',
                prefixLen, suffixLen,
                coreLen: core.length,
                ctBytes: decoded.raw.length,
                ctBlocks: decoded.raw.length / 16,
                ciphertext: decoded.raw
            });
        }
    }
    
    if (candidates.length === 0) {
        console.log('No valid AES-aligned boundaries found (prefix/suffix up to 10 chars).');
        return null;
    }
    
    console.log(`Found ${candidates.length} valid boundary candidates:`);
    for (const c of candidates) {
        console.log(`  prefix="${c.prefix}" (${c.prefixLen}) + ${c.coreLen} b64url + suffix="${c.suffix}" (${c.suffixLen}) → ${c.ctBytes} bytes (${c.ctBlocks} blocks)`);
    }
    
    const best = candidates[0];
    console.log(`\nBest candidate: prefix=${best.prefixLen} suffix=${best.suffixLen}, ${best.ctBytes} bytes ciphertext`);
    return best;
}

// Load samples
const source = fs.readFileSync(__dirname + '/decrypt_test.js', 'utf8');
const marker = 'const encrypt_info = `';
const start1 = source.indexOf(marker) + marker.length;
const encryptInfo1 = source.slice(start1, source.indexOf('`', start1));

const payload = require('../data/payload.json');
const encryptInfo2 = payload.encrypt_info;

const r1 = analyze(encryptInfo1, 'Sample 1 (decrypt_test.js - browser)');
const r2 = analyze(encryptInfo2, 'Sample 2 (payload.json - saved)');

// Verify Sample 1
if (r1) {
    console.log(`\n--- VERIFY Sample 1 ---`);
    console.log(`Known: prefix="mf2-NC"(6) suffix="F_"(2) ct=3744 bytes`);
    const match = candidates => candidates.find(c => c.prefix === 'mf2-NC' && c.suffix === 'F_');
    // need to re-find
}

// Summary
console.log(`\n--- CONCLUSION ---`);
if (r2) {
    console.log(`Sample 2 format: ${r2.prefixLen}-byte prefix + AES ciphertext + ${r2.suffixLen}-byte suffix`);
    console.log(`Needs a 32-byte key + 16-byte IV for AES-256-CBC/PKCS7`);
}
