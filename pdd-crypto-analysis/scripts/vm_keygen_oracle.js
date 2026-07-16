'use strict';

/**
 * Small executor for the tracked Qre bytecode fixture.
 *
 * This is deliberately separate from keygen.js: tests compare the readable
 * implementation against the original programs 2-7 instead of comparing two
 * copies of the same pseudocode.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BYTECODE = Buffer.from(
    fs.readFileSync(path.join(__dirname, '..', 'raw', 'bytecodes_b64.txt'), 'utf8').trim(),
    'base64'
);

const PROGRAMS = [
    { id: 0, name: 'encryptKeyAndIv', offset: 0, length: 59, locals: 4, params: 0 },
    { id: 1, name: 'decryptString', offset: 59, length: 174, locals: 12, params: 3 },
    { id: 2, name: 'getCount', offset: 233, length: 92, locals: 2, params: 0 },
    { id: 3, name: 'setCount', offset: 325, length: 126, locals: 5, params: 1 },
    { id: 4, name: 'getPreKey', offset: 451, length: 75, locals: 2, params: 0 },
    { id: 5, name: 'setPreKey', offset: 526, length: 67, locals: 2, params: 1 },
    { id: 6, name: 'generateAESKey', offset: 593, length: 166, locals: 10, params: 0 },
    { id: 7, name: 'generateIV', offset: 759, length: 40, locals: 1, params: 0 },
    { id: 8, name: 'rsaEncrypt', offset: 799, length: 65, locals: 3, params: 1 },
    { id: 9, name: 'aesDecrypt', offset: 864, length: 96, locals: 4, params: 3 },
];

const CONSTANTS = [
    'encryptedData', 'rawKey', 'rawIV', -1, '1', 0, 'utf-8', '', undefined, null,
    '000', 'rs_count', 3, '0', 1, 999, 'rs_key', 'v', '2', -5, 32, 'iv', 16,
    'ciphertext', 'mode', 'padding'
];

const GLOBAL_NAMES = [
    'generateAESKey', 'generateIV', 'rsaEncrypt', 'Object', '_sliceInstanceProperty',
    'call', 'decodeBase64Url', 'u8ToWordArray', 'aesDecrypt', 'wordArrayToUint8Array',
    'decompress', 'TextDecoder', 'decode', '_JSON$stringify', 'Error', '_globalThis',
    'localStorage', 'getItem', '_padStartInstanceProperty', '_parseInt', 'toString',
    'setItem', '_Date$now', 'getCount', 'getPreKey', 'Math', 'length', 'max', 'nanoid',
    'setPreKey', 'setCount', 'CryptoJS', 'SHA256', 'substring', 'encryptor', 'encrypt',
    'AES', 'enc', 'Utf8', 'parse', 'mode', 'CBC', 'pad', 'Pkcs7', 'decrypt'
];

const OPCODES = Object.freeze({
    POP: 1,
    OR: 16,
    SET_PROP: 17,
    EQ: 24,
    JUMP_TRUE: 25,
    GET_PROP_DYNAMIC: 29,
    RETURN_VOID: 32,
    GTE: 33,
    LEAVE_TRY: 34,
    THROW: 35,
    ADD: 36,
    NOT: 48,
    BIT_NOT: 49,
    MAKE_ARRAY: 50,
    BIT_OR: 51,
    OBJECT_KEYS: 52,
    NOP_35: 53,
    BIT_AND: 54,
    LT: 80,
    PUSH_THIS: 81,
    NOP_52: 82,
    BIT_XOR: 83,
    PUSH_CONST: 84,
    NEGATE: 85,
    GET_PROP: 96,
    AND: 97,
    STRICT_EQ: 98,
    TO_NUMBER: 99,
    CALL_METHOD: 100,
    JUMP: 101,
    NEW_GLOBAL: 102,
    GT: 103,
    GET_PROP_ALT: 104,
    SET_GLOBAL: 105,
    STORE_LOCAL: 112,
    DUP: 114,
    SHIFT_RIGHT: 115,
    DIV: 116,
    SHIFT_RIGHT_UNSIGNED: 130,
    ENTER_TRY: 131,
    JUMP_FALSE: 132,
    NEW_METHOD: 133,
    NOP_90: 144,
    SUB: 145,
    PUSH_GLOBAL: 146,
    PUSH_LOCAL: 147,
    NOP_94: 148,
    RETURN: 149,
    MOD: 150,
    TYPEOF: 151,
    SHIFT_LEFT: 152,
    LTE: 153,
    MUL: 254,
    CALL_GLOBAL: 255,
});

function makeStorage(initial = {}) {
    const values = new Map(Object.entries(initial).map(([k, v]) => [String(k), String(v)]));
    return {
        values,
        getItem(key) { return values.has(String(key)) ? values.get(String(key)) : null; },
        setItem(key, value) { values.set(String(key), String(value)); },
    };
}

function createOracle(options = {}) {
    const storage = options.storage === undefined ? makeStorage() : options.storage;
    const nowSource = options.now === undefined ? Date.now : options.now;
    const randomBytes = options.randomBytes || crypto.randomBytes;
    const alphabet =
        'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';

    function now() {
        return typeof nowSource === 'function' ? nowSource() : nowSource;
    }

    function nanoid(size = 21) {
        const bytes = randomBytes(size |= 0);
        let out = '';
        while (size--) out += alphabet[bytes[size] & 63];
        return out;
    }

    const cryptoJs = {
        SHA256(value) {
            const digest = crypto.createHash('sha256').update(String(value)).digest('hex');
            return { toString() { return digest; } };
        },
    };

    let globals;

    function resolve(name) {
        if (Object.prototype.hasOwnProperty.call(globals, name)) return globals[name];
        throw new Error(`VM oracle global not implemented: ${name}`);
    }

    function execute(programId, args = [], thisContext = undefined) {
        const program = PROGRAMS[programId];
        if (!program) throw new Error(`Invalid VM program: ${programId}`);

        const end = program.offset + program.length;
        const locals = new Array(program.locals);
        for (let i = 0; i < program.params && i < args.length; i++) locals[i] = args[i];
        const stack = [];
        let pc = program.offset;

        const u8 = () => BYTECODE[pc++];
        const u16 = () => {
            const value = BYTECODE[pc] | (BYTECODE[pc + 1] << 8);
            pc += 2;
            return value;
        };
        const i16 = () => {
            let value = u16();
            if (value & 0x8000) value -= 0x10000;
            return value;
        };
        const pop = () => {
            if (!stack.length) throw new Error(`VM stack underflow at ${pc - 1}`);
            return stack.pop();
        };
        const popArgs = count => {
            const values = [];
            while (count--) values.unshift(pop());
            return values;
        };

        while (pc < end) {
            const opcodeAddress = pc;
            const opcode = u8();

            switch (opcode) {
                case OPCODES.POP:
                    pop();
                    break;
                case OPCODES.SET_PROP: {
                    const value = pop();
                    const key = pop();
                    pop()[key] = value;
                    break;
                }
                case OPCODES.ADD: {
                    const right = pop();
                    stack.push(pop() + right);
                    break;
                }
                case OPCODES.NOT:
                    stack.push(!pop());
                    break;
                case OPCODES.STRICT_EQ: {
                    const right = pop();
                    stack.push(pop() === right);
                    break;
                }
                case OPCODES.GT: {
                    const right = pop();
                    stack.push(pop() > right);
                    break;
                }
                case OPCODES.SUB: {
                    const right = pop();
                    stack.push(Number(pop()) - Number(right));
                    break;
                }
                case OPCODES.PUSH_CONST:
                    stack.push(CONSTANTS[u16()]);
                    break;
                case OPCODES.PUSH_GLOBAL:
                    stack.push(resolve(GLOBAL_NAMES[u16()]));
                    break;
                case OPCODES.PUSH_LOCAL:
                    stack.push(locals[u16()]);
                    break;
                case OPCODES.STORE_LOCAL:
                    locals[u16()] = pop();
                    break;
                case OPCODES.DUP:
                    if (!stack.length) throw new Error(`VM dup on empty stack at ${opcodeAddress}`);
                    stack.push(stack[stack.length - 1]);
                    break;
                case OPCODES.GET_PROP:
                case OPCODES.GET_PROP_ALT: {
                    const object = pop();
                    const name = GLOBAL_NAMES[u16()];
                    stack.push(object[name]);
                    break;
                }
                case OPCODES.CALL_METHOD: {
                    const count = u8();
                    const name = GLOBAL_NAMES[u16()];
                    const callArgs = popArgs(count);
                    const receiver = pop();
                    stack.push(receiver[name].apply(receiver, callArgs));
                    break;
                }
                case OPCODES.CALL_GLOBAL: {
                    const count = u8();
                    const name = GLOBAL_NAMES[u16()];
                    stack.push(resolve(name).apply(undefined, popArgs(count)));
                    break;
                }
                case OPCODES.NEW_GLOBAL: {
                    const count = u8();
                    const name = GLOBAL_NAMES[u16()];
                    stack.push(Reflect.construct(resolve(name), popArgs(count)));
                    break;
                }
                case OPCODES.JUMP:
                    {
                        const offset = i16();
                        pc += offset;
                    }
                    break;
                case OPCODES.JUMP_FALSE: {
                    const offset = i16();
                    if (!pop()) pc += offset;
                    break;
                }
                case OPCODES.JUMP_TRUE: {
                    const offset = i16();
                    if (pop()) pc += offset;
                    break;
                }
                case OPCODES.RETURN:
                    return pop();
                case OPCODES.RETURN_VOID:
                    return undefined;
                default:
                    throw new Error(
                        `VM oracle opcode 0x${opcode.toString(16)} not implemented at ${opcodeAddress}`
                    );
            }
        }
        return undefined;
    }

    globals = {
        Object,
        Math,
        Error,
        _globalThis: storage === null ? { localStorage: null } : { localStorage: storage },
        _sliceInstanceProperty: value => value.slice,
        _padStartInstanceProperty: value => value.padStart,
        _parseInt: parseInt,
        _Date$now: now,
        CryptoJS: cryptoJs,
        nanoid,
        getCount: () => execute(2),
        setCount: value => execute(3, [value]),
        getPreKey: () => execute(4),
        setPreKey: value => execute(5, [value]),
        generateAESKey: () => execute(6),
        generateIV: () => execute(7),
        rsaEncrypt: options.rsaEncrypt || (value => value),
    };

    return {
        storage,
        execute,
        getCount: globals.getCount,
        setCount: globals.setCount,
        getPreKey: globals.getPreKey,
        setPreKey: globals.setPreKey,
        generateAESKey: globals.generateAESKey,
        generateIV: globals.generateIV,
        encryptKeyAndIv: () => execute(0),
    };
}

module.exports = {
    BYTECODE,
    PROGRAMS,
    CONSTANTS,
    GLOBAL_NAMES,
    OPCODES,
    makeStorage,
    createOracle,
};

if (require.main === module) {
    const oracle = createOracle();
    console.log('VM key:', oracle.generateAESKey());
    console.log('VM IV: ', oracle.generateIV());
}
