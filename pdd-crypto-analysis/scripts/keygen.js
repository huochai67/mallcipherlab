'use strict';

/**
 * Exact high-level reimplementation of Qre VM programs 2-7.
 *
 * Program 2: getCount
 * Program 3: setCount
 * Program 4: getPreKey
 * Program 5: setPreKey
 * Program 6: generateAESKey
 * Program 7: generateIV
 *
 * The implementation intentionally keeps the browser storage state visible:
 *   rs_key   = timestamp used by the previous key
 *   rs_count = three-digit rolling counter (000..999)
 */

const crypto = require('crypto');

// Exact 64-character alphabet used by the bundle's nanoid implementation.
const NANOID_ALPHABET =
    'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';

const STORAGE_KEY = 'rs_key';
const STORAGE_COUNT = 'rs_count';

class MemoryStorage {
    constructor(initial = {}) {
        this.values = new Map();
        for (const [key, value] of Object.entries(initial)) {
            this.setItem(key, value);
        }
    }

    getItem(key) {
        key = String(key);
        return this.values.has(key) ? this.values.get(key) : null;
    }

    setItem(key, value) {
        this.values.set(String(key), String(value));
    }

    removeItem(key) {
        this.values.delete(String(key));
    }

    clear() {
        this.values.clear();
    }

    toJSON() {
        return Object.fromEntries(this.values);
    }
}

const defaultStorage = new MemoryStorage();

function resolveStorage(storage) {
    if (storage === null) return null;
    return storage || defaultStorage;
}

function readNow(now) {
    const value = typeof now === 'function' ? now() :
        (now === undefined ? Date.now() : now);
    return String(value);
}

/**
 * Bundle-equivalent nanoid.
 *
 * The original iterates the random byte array backwards and masks each byte
 * with 63, rather than using modulo over the alphabet length.
 */
function nanoid(size = 21, randomBytes = crypto.randomBytes) {
    size |= 0;
    if (size < 0) throw new RangeError('nanoid size must be non-negative');

    const bytes = randomBytes(size);
    if (!bytes || bytes.length < size) {
        throw new Error(`randomBytes returned ${bytes ? bytes.length : 0} bytes; expected ${size}`);
    }

    let id = '';
    while (size--) {
        id += NANOID_ALPHABET[bytes[size] & 63];
    }
    return id;
}

function getCount(storage = defaultStorage) {
    storage = resolveStorage(storage);
    if (!storage) return '000';
    return String(storage.getItem(STORAGE_COUNT) || '000').padStart(3, '0');
}

function setCount(currentCount, storage = defaultStorage) {
    storage = resolveStorage(storage);
    if (!storage) return;

    const incremented = parseInt(currentCount) + 1;
    const next = incremented > 999 ? 0 : incremented;
    storage.setItem(STORAGE_COUNT, String(next).padStart(3, '0'));
}

function getPreKey(storage = defaultStorage) {
    storage = resolveStorage(storage);
    return storage ? (storage.getItem(STORAGE_KEY) || '') : '';
}

function setPreKey(timestamp, storage = defaultStorage) {
    storage = resolveStorage(storage);
    if (storage) storage.setItem(STORAGE_KEY, timestamp);
}

/**
 * Exact pseudocode recovered from VM program 6:
 *
 *   now      = Date.now().toString()
 *   count    = getCount()
 *   previous = getPreKey()
 *   tail     = previous ? previous.slice(-5) : ''
 *   base     = 'v' + '2' + now + tail + count
 *   key      = base + nanoid(max(0, 32 - base.length))
 *   setPreKey(now)
 *   setCount(count)
 */
function generateAESKey(options = {}) {
    const storage = resolveStorage(options.storage);
    const timestamp = readNow(options.now);
    const count = getCount(storage);
    const previous = getPreKey(storage);
    const previousTail = previous ? previous.slice(-5) : '';
    const base = 'v' + '2' + timestamp + previousTail + count;
    const randomLength = Math.max(0, 32 - base.length);
    const random = randomLength > 0
        ? nanoid(randomLength, options.randomBytes || crypto.randomBytes)
        : '';
    const key = base + random;

    setPreKey(timestamp, storage);
    setCount(count, storage);
    return key;
}

/** Exact pseudocode recovered from VM program 7. */
function generateIV(options = {}) {
    const timestamp = readNow(options.now);
    return crypto.createHash('sha256')
        .update(timestamp + 'iv', 'utf8')
        .digest('hex')
        .substring(0, 16);
}

/** Program-0 generation ordering: key first, then IV. RSA packs iv + key. */
function generateKeyIv(options = {}) {
    const key = generateAESKey(options);
    const iv = generateIV(options);
    return { key, iv };
}

function resetDefaultState() {
    defaultStorage.clear();
}

module.exports = {
    NANOID_ALPHABET,
    STORAGE_KEY,
    STORAGE_COUNT,
    MemoryStorage,
    defaultStorage,
    nanoid,
    getCount,
    setCount,
    getPreKey,
    setPreKey,
    generateAESKey,
    generateIV,
    generateKeyIv,
    resetDefaultState,
};

if (require.main === module) {
    const result = generateKeyIv();
    console.log('Generated key:', result.key, `(${result.key.length})`);
    console.log('Generated IV: ', result.iv, `(${result.iv.length})`);
    console.log('State:', defaultStorage.toJSON());
}
