'use strict';

/**
 * Full PDD goods API request pipeline: generate → send → decrypt.
 *
 * Usage:
 *   node scripts/generate_request.js [goods_id] [key] [iv]
 *
 * If key+iv are provided (from browser Xre() capture), they are used directly.
 * Otherwise a simulated key/iv is generated (may not match server encryption).
 *
 * Prerequisites:
 *   $env:PDD_COOKIES = "api_uid=...; PDDAccessToken=..."
 */

const { getcsr_risk_token, decryptResponse } = require('./encryptToken');
const { generateAntiContent } = require('./anti_content');
const https = require('https');

const COOKIES = process.env.PDD_COOKIES;
const GOODS_ID = process.argv[2] || '624625371461';
const EXTERNAL_KEY = process.argv[3] || process.env.PDD_KEY || '';
const EXTERNAL_IV  = process.argv[4] || process.env.PDD_IV  || '';

if (!COOKIES) {
    console.error('ERROR: Set PDD_COOKIES env var');
    process.exit(1);
}

// ── anti_content ──────────────────────────────────────────
console.log('Generating anti_content...');
let anti_content;
try {
    anti_content = generateAntiContent();
    console.log('  length:', anti_content.length, 'chars');
} catch (e) {
    console.error('anti_content failed:', e.message);
    process.exit(1);
}

// ── key/IV ────────────────────────────────────────────────
let key, iv;
if (EXTERNAL_KEY && EXTERNAL_IV) {
    key = EXTERNAL_KEY;
    iv = EXTERNAL_IV;
    console.log('Using external key:', key);
    console.log('Using external IV: ', iv);
    // Build csr_token with this key
    const crypto = require('crypto');
    const { RSA_PUBLIC_KEY } = require('./encryptToken');
    const csr = crypto.publicEncrypt(
        { key: RSA_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(key + iv, 'utf8')
    ).toString('base64');
    var csr_token = csr;
} else {
    const token = getcsr_risk_token();
    key = token.key;
    iv = token.iv;
    csr_token = token.encryptedData;
    console.log('Generated session key:', key);
    console.log('Generated session IV: ', iv);
    console.log('WARNING: simulated key may not match server encryption.');
    console.log('Capture real key/IV from browser Xre() breakpoint for full decryption.');
}

// ── build request ─────────────────────────────────────────
const now = Date.now();
const body = JSON.stringify({
    page_version: 7,
    goods_id: parseInt(GOODS_ID),
    page_from: 23,
    hostname: 'mobile.pinduoduo.com',
    client_time: now,
    refer_page_sn: '10015',
    page_sn: 10014,
    page_id: `10014_${now}_${Math.random().toString(36).slice(2, 8)}`,
    _oak_rcto: process.env.OAK_RCTO || '',
    anti_content,
    front_supports: [
        'community_purchase', 'split_info_section', 'render_opt_2022',
        'new_price_bottom', 'group_tip_end_time', 'custom_sku'
    ],
    csr_risk_token: csr_token
});

// ── send ──────────────────────────────────────────────────
const url = new URL(`https://mobile.pinduoduo.com/proxy/api/api/oak/integration/render`);

const options = {
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Content-Length': Buffer.byteLength(body),
        'anti-content': anti_content,
        'Cookie': COOKIES,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Origin': 'https://mobile.pinduoduo.com',
        'Referer': `https://mobile.pinduoduo.com/goods.html?goods_id=${GOODS_ID}`,
    }
};

console.log(`\nPOST goods_id=${GOODS_ID} ...`);

const req = https.request(options, (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
        try {
            const parsed = JSON.parse(data);

            if (parsed.error_code) {
                console.log(`Server error: ${parsed.error_code} ${parsed.error_msg}`);
                if (parsed.verify_auth_token) {
                    console.log(`verify_auth_token: ${parsed.verify_auth_token}`);
                }
                return;
            }

            if (parsed.encrypt_status === 3 && parsed.encrypt_info) {
                console.log(`encrypt_status: 3, encrypt_info: ${parsed.encrypt_info.length} chars`);
                const goodsData = decryptResponse(parsed.encrypt_info, key, iv);

                console.log('\n=== DECRYPTED ===');
                if (goodsData.goods) {
                    console.log(`goods_id:   ${goodsData.goods.goods_id}`);
                    console.log(`goods_name: ${goodsData.goods.goods_name}`);
                    console.log(`mall_id:    ${goodsData.goods.mall_id}`);
                }
                if (goodsData.price) {
                    console.log(`price:      min=${goodsData.price.min_group_price} max=${goodsData.price.max_group_price}`);
                }
                if (goodsData.sku) {
                    console.log(`sku count:  ${goodsData.sku.length}`);
                }

                const fs = require('fs');
                const outPath = `data/goods_${GOODS_ID}_${now}.json`;
                fs.writeFileSync(outPath, JSON.stringify(goodsData, null, 2));
                console.log(`\nSaved: ${outPath}`);

            } else {
                console.log('encrypt_status:', parsed.encrypt_status);
                console.log('Keys:', Object.keys(parsed).join(', '));
            }
        } catch (e) {
            console.error('Error:', e.message);
        }
    });
});

req.on('error', (e) => console.error('Request error:', e.message));
req.write(body);
req.end();
