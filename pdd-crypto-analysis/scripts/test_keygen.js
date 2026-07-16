'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {
    MemoryStorage,
    generateAESKey,
    generateIV,
    generateKeyIv,
} = require('./keygen');
const { createOracle, makeStorage } = require('./vm_keygen_oracle');

function sequentialRandom(start = 0) {
    let value = start;
    return size => Buffer.from(Array.from({ length: size }, () => value++ & 0xff));
}

function sequence(values) {
    let index = 0;
    return () => values[Math.min(index++, values.length - 1)];
}

// Golden vector obtained by executing the original Qre programs 0/6/7.
const keyNow = 1700000000000;
const ivNow = 1700000000001;
const expectedKey = 'v2170000000000000091T62-modnaesu';
const expectedIv = '93734a7fb72105df';

const highStorage = new MemoryStorage();
const highResult = generateKeyIv({
    storage: highStorage,
    now: sequence([keyNow, ivNow]),
    randomBytes: sequentialRandom(),
});
assert.deepStrictEqual(highResult, { key: expectedKey, iv: expectedIv });
assert.deepStrictEqual(highStorage.toJSON(), {
    rs_key: String(keyNow),
    rs_count: '001',
});

// Independent bytecode execution must produce the exact same output and state.
const oracleStorage = makeStorage();
const oracle = createOracle({
    storage: oracleStorage,
    now: sequence([keyNow, ivNow]),
    randomBytes: sequentialRandom(),
    rsaEncrypt: value => value,
});
const oracleResult = oracle.encryptKeyAndIv();
assert.strictEqual(oracleResult.rawKey, expectedKey);
assert.strictEqual(oracleResult.rawIV, expectedIv);
assert.strictEqual(oracleResult.encryptedData, expectedIv + expectedKey);
assert.notStrictEqual(oracleResult.encryptedData, expectedKey + expectedIv);
assert.strictEqual(oracleStorage.getItem('rs_key'), String(keyNow));
assert.strictEqual(oracleStorage.getItem('rs_count'), '001');

// Existing state changes the key's five-character timestamp tail and counter.
const existingHigh = new MemoryStorage({ rs_key: '1699999999123', rs_count: '041' });
const existingOracle = makeStorage({ rs_key: '1699999999123', rs_count: '041' });
const highExistingKey = generateAESKey({
    storage: existingHigh,
    now: keyNow,
    randomBytes: sequentialRandom(64),
});
const oracleExistingKey = createOracle({
    storage: existingOracle,
    now: keyNow,
    randomBytes: sequentialRandom(64),
}).generateAESKey();
assert.strictEqual(highExistingKey, oracleExistingKey);
assert.strictEqual(existingHigh.getItem('rs_count'), '042');
assert.strictEqual(existingOracle.getItem('rs_count'), '042');

// Counter rolls from 999 to 000 after using 999 in the current key.
const rollover = new MemoryStorage({ rs_key: '1699999999999', rs_count: '999' });
const rolloverKey = generateAESKey({
    storage: rollover,
    now: keyNow,
    randomBytes: sequentialRandom(128),
});
assert.ok(rolloverKey.includes('999'));
assert.strictEqual(rollover.getItem('rs_count'), '000');

// Confirm encryptToken passes iv + key to RSA, not key + iv.
const originalPublicEncrypt = crypto.publicEncrypt;
let rsaPlaintext;
try {
    crypto.publicEncrypt = (_options, plaintext) => {
        rsaPlaintext = Buffer.from(plaintext);
        return Buffer.alloc(256, 0x5a);
    };
    delete require.cache[require.resolve('./encryptToken')];
    const { getcsr_risk_token } = require('./encryptToken');
    const token = getcsr_risk_token({
        storage: new MemoryStorage(),
        now: sequence([keyNow, ivNow]),
        randomBytes: sequentialRandom(),
    });
    assert.strictEqual(rsaPlaintext.toString('utf8'), token.iv + token.key);
    assert.strictEqual(token.encryptedData.length, 344);
} finally {
    crypto.publicEncrypt = originalPublicEncrypt;
    delete require.cache[require.resolve('./encryptToken')];
}

// Direct IV formula check.
assert.strictEqual(
    generateIV({ now: ivNow }),
    crypto.createHash('sha256').update(String(ivNow) + 'iv').digest('hex').slice(0, 16)
);

console.log('Qre key/IV golden vector: PASS');
console.log('Qre bytecode differential: PASS');
console.log('RSA plaintext order (iv + key): PASS');
