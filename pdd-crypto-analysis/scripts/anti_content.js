'use strict';

/**
 * Load PDD anti_content chunk and provide generateAntiContent().
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ── browser sandbox ──────────────────────────────────────
const sandbox = {
    global: {}, window: {}, self: {},
    navigator: {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        platform: 'Win32',
        appVersion: '5.0',
        language: 'zh-CN',
        cookieEnabled: true
    },
    location: {
        href: 'https://mobile.pinduoduo.com/goods.html',
        hostname: 'mobile.pinduoduo.com',
        protocol: 'https:', pathname: '/goods.html', search: ''
    },
    document: {
        documentElement: { style: {}, scrollTop: 0, scrollLeft: 0 },
        body: { scrollTop: 0, scrollLeft: 0 },
        createElement: () => ({ style: {}, setAttribute: () => { } }),
        getElementsByTagName: () => [],
        addEventListener: () => { }, removeEventListener: () => { },
        querySelector: () => null, querySelectorAll: () => [],
        cookie: '', referrer: ''
    },
    screen: { width: 1920, height: 1080, colorDepth: 24 },
    history: { back() { }, forward() { }, go() { } },
    XMLHttpRequest: function () { }, FormData: function () { },
    Element: function () { }, Node: function () { }, HTMLElement: function () { },
    PageTransitionEvent: function () { },
    __LOADABLE_LOADED_CHUNKS__: [],
    console,
    setTimeout, clearTimeout, setInterval, clearInterval,
    Array, Object, String, Number, Boolean, Date, Math, RegExp, Error,
    JSON, parseInt, parseFloat, isNaN, isFinite,
    encodeURIComponent, decodeURIComponent,
};

sandbox.global = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;

vm.createContext(sandbox);

// ── load chunk ────────────────────────────────────────────
const CHUNK_PATH = process.env.CHUNK_PATH ||
    path.join(__dirname, '..', 'raw', 'react_anti_co_7c53431a4571d3bd55ff_1026.js');

if (!fs.existsSync(CHUNK_PATH)) {
    console.error('ERROR: chunk not found: ' + CHUNK_PATH);
    process.exit(1);
}

const code = fs.readFileSync(CHUNK_PATH, 'utf-8');
const script = new vm.Script(code);
script.runInContext(sandbox);

// ── extract module ────────────────────────────────────────
const chunks = sandbox.__LOADABLE_LOADED_CHUNKS__;
if (!chunks || !chunks[0]) throw new Error('Chunk failed to load');

const [_chunkId, modules] = chunks[0];

const moduleCache = Object.create(null);
function webpackRequire(moduleId) {
    if (moduleCache[moduleId]) return moduleCache[moduleId].exports;
    const func = modules[moduleId];
    if (!func) throw new Error('Module not found: ' + moduleId);
    const mod = { exports: {} };
    moduleCache[moduleId] = mod;
    func(mod, mod.exports, webpackRequire);
    return mod.exports;
}
webpackRequire.r = (e) => Object.defineProperty(e, '__esModule', { value: true });
webpackRequire.d = (e, n, g) => { if (!webpackRequire.o(e, n)) Object.defineProperty(e, n, { enumerable: true, get: g }); };
webpackRequire.o = (o, p) => Object.prototype.hasOwnProperty.call(o, p);
webpackRequire.n = (m) => {
    const getter = m && m.__esModule ? () => m.default : () => m;
    webpackRequire.d(getter, 'a', getter);
    return getter;
};

const AntiContent = webpackRequire(47927).default;
if (typeof AntiContent !== 'function') throw new Error('AntiContent is not a function');

/**
 * Generate anti_content string.
 * Each call produces a unique value.
 */
function generateAntiContent() {
    const instance = new AntiContent({ serverTime: Date.now() });
    return instance.messagePack();
}

module.exports = { generateAntiContent };

if (require.main === module) {
    try {
        process.stdout.write(generateAntiContent());
    } catch (e) {
        console.error('Error:', e.message);
        process.exit(1);
    }
}

module.exports = { generateAntiContent };

// CLI: print anti_content to stdout
if (require.main === module) {
    try {
        const result = generateAntiContent();
        process.stdout.write(result);
    } catch (e) {
        console.error('Error:', e.message);
        process.exit(1);
    }
}
