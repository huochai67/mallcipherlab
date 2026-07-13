#!/usr/bin/env node
/**
 * h5st Generator - Standalone CLI
 * Usage: 
 *   node h5st_generator.js <appId> '<JSON params>' [token]
 *   node h5st_generator.js --stdin   (read JSON from stdin)
 */

global.navigator = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    language: 'zh-CN', languages: ['zh-CN', 'zh'], platform: 'Win32',
    hardwareConcurrency: 8, deviceMemory: 8, vendor: 'Google Inc.',
    cookieEnabled: true, plugins: { length: 5 }, mimeTypes: { length: 4 }, webdriver: false,
};
global.window = global; global.self = global;
global.location = { href: 'https://search.jd.com/Search', origin: 'https://search.jd.com', host: 'search.jd.com', hostname: 'search.jd.com', protocol: 'https:' };
global.document = { cookie: '', referrer: '', createElement: () => ({}), getElementsByTagName: () => [], body: { innerHTML: '' }, head: null, currentScript: null };
global.setTimeout = setTimeout; global.clearTimeout = clearTimeout; global.setInterval = setInterval; global.clearInterval = clearInterval;
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.Element = function() {}; global.HTMLAllCollection = function() {};

require('./sha256.js');
require('./js_security_v3_0.1.4.js');

function generateH5st(appId, params, token) {
    const signer = new ParamsSign({ appId });
    if (token) {
        signer._token = token;
        signer._defaultToken = token;
    }
    const result = signer.signSync(params);
    return result;
}

// Parse args
function main() {
    const args = process.argv.slice(2);
    let appId, params, token;
    
    if (args[0] === '--stdin') {
        let body = '';
        process.stdin.on('data', chunk => body += chunk);
        process.stdin.on('end', () => {
            try {
                const input = JSON.parse(body);
                appId = input.appId || input.appid || '';
                params = input.params || input;
                token = input.token || '';
                if (appId && params) {
                    const result = generateH5st(appId, params, token);
                    console.log(JSON.stringify(result));
                } else {
                    console.error(JSON.stringify({ error: 'Missing appId or params' }));
                }
            } catch(e) {
                console.error(JSON.stringify({ error: e.message }));
            }
        });
        return;
    }
    
    if (args.length >= 2) {
        appId = args[0];
        params = JSON.parse(args[1]);
        token = args[2] || '';
        const result = generateH5st(appId, params, token);
        console.log(JSON.stringify(result));
    } else {
        console.error(JSON.stringify({ error: 'Usage: node h5st_generator.js <appId> <jsonParams> [token]' }));
    }
}

main();
