'use strict';

/**
 * Rre VM bytecode disassembler.
 * Decodes the 960-byte bytecode of PDD's custom VM and prints program 0 (generateAESKey).
 */
const fs = require('fs');
const path = require('path');

const b64 = fs.readFileSync(path.join(__dirname, '..', 'raw', 'bytecodes_b64.txt'), 'utf8').trim();
const code = Buffer.from(b64, 'base64');
console.log(`Total bytecode: ${code.length} bytes\n`);

// Program metadata (from Qre function analysis)
const programs = [
    { id: 0, name: 'generateAESKey', offset: 0, length: 59, locals: 4, params: 0 },
    { id: 1, name: 'decryptString', offset: 59, length: 174, locals: 12, params: 3 },
    { id: 2, name: 'getPreKey', offset: 233, length: 92, locals: 2, params: 0 },
    { id: 3, name: 'setPreKey', offset: 325, length: 126, locals: 5, params: 1 },
    { id: 4, name: 'getCount', offset: 451, length: 75, locals: 2, params: 0 },
    { id: 5, name: 'setCount', offset: 526, length: 67, locals: 2, params: 1 },
    { id: 6, name: 'generateAESKey', offset: 593, length: 166, locals: 10, params: 0 },
    { id: 7, name: 'generateIV', offset: 759, length: 40, locals: 1, params: 0 },
    { id: 8, name: 'rsaEncrypt', offset: 799, length: 65, locals: 3, params: 1 },
    { id: 9, name: 'aesDecrypt', offset: 864, length: 96, locals: 4, params: 3 },
];

// Constant table 'n' (25 entries)
const constants = [
    'o(439)', 'o(857)', 'rawIV', -1, '1', 0, 'o(785)', '', undefined, null,
    'o(914)', 'o(1506)', 3, '0', 1, 999, 'o(567)', 'v', '2', -5,
    32, 'iv', 16, 'o(688)', 'o(423)', 'o(616)'
];

// External function name table 'r' (42 entries)
const funcNames = [
    'o(761)', 'o(1481)', 'o(1006)', 'o(582)', 'o(1204)', 'o(774)', 'o(963)',
    'u8ToWordArray', 'o(866)', 'o(664)', 'o(922)', 'o(569)', 'o(1617)',
    'o(788)', 'Error', 'o(991)', 'o(888)', 'getItem', 'o(1448)', '_parseInt',
    'o(878)', 'setItem', 'o(1565)', 'o(1373)', 'o(1463)', 'o(784)', 'length',
    'o(1239)', 'o(1591)', 'o(1179)', 'o(1027)', 'o(1194)', 'SHA256',
    'substring', 'o(1079)', 'encrypt', 'o(824)', 'o(1207)', 'o(877)', 'o(847)',
    'o(423)', 'o(1225)', 'pad', 'o(1061)', 'o(1131)'
];

// Ordered dependency list 'a' (21 entries)
const deps = [
    'generateAESKey', 'rsaEncrypt', 'aesDecrypt', 'decodeBase64Url',
    'u8ToWordArray', 'aesDecrypt', 'encrypt', 'decompress',
    '_JSON$stringify', '_padStartInstanceProperty', '_parseInt',
    '_padStart', 'setItem', 'getPreKey', 'getCount', 'nanoid',
    'setPreKey', 'setPreKey(dup)', 'SHA256', 'encryptor', '?'
];

// Opcode names (decimal → name)
const opNames = {
    0: 'noop0?',
    1: 'push_undef',
    16: 'pop_or_byte',
    17: 'set_prop',
    24: 'cmp_eq_byte',
    25: 'jump_if',
    29: 'read_prop_pop',
    32: 'return',
    33: 'gte',
    35: 'push_dep',  // push external dependency by index
    36: 'add',
    48: 'not',
    49: 'bit_not',
    50: 'new_array',
    51: 'bit_or',
    52: 'obj_keys',
    54: 'bit_and',
    80: 'lt',
    81: 'push_this',
    83: 'xor',
    84: 'push_const',  // load constant from n by index
    85: 'negate',
    96: 'read_named',  // read property from r by U16 index
    97: 'and',
    98: 'strict_eq',
    99: 'to_number',
    100: 'call_method',  // arg count + U16 name index
    101: 'jump',
    102: 'call_ctor',    // arg count + U16 name index
    103: 'gt',
    104: 'read_prop_u16',
    105: 'set_global',
    112: 'store_local',  // byte: local index
    114: 'dup',
    115: 'rshift',
    116: 'div',
    130: 'urshift',
    131: 'try_enter',
    132: 'jump_if_false',
    133: 'call_ctor_on_obj',
    144: 'nop',
    145: 'sub',
    146: 'push_ext_by_name',  // get external dep by name from r
    147: 'push_local',   // byte: local index
    149: 'ret_val',
    150: 'mod',
    151: 'typeof_',
    152: 'lshift',
    153: 'lte',
    254: 'mul',
    255: 'call_static',  // static method call (no this): arg count + U16
};

// --- Disassembler ---
function disasm(prog) {
    const start = prog.offset;
    const end = start + prog.length;
    let pc = start;
    const lines = [];

    console.log(`┌─ Program ${prog.id}: ${prog.name} ───────────────────────────────┐`);
    console.log(`│  offset: ${start}  length: ${prog.length}  locals: ${prog.locals}  params: ${prog.params}`);

    while (pc < end) {
        const addr = pc;
        const op = code[pc++];
        const name = opNames[op] || `UNKNOWN_${op}`;

        let operand = '';
        let detail = '';

        switch (op) {
            case 255: { // call_static: arg count (byte) + U16 name index
                const argc = code[pc++];
                const idx = code[pc] | (code[pc + 1] << 8);
                pc += 2;
                operand = `argc=${argc}`;
                detail = `deps[${idx}]="${deps[idx] || '?'}"(${argc} args)`;
                break;
            }
            case 100: { // call_method: arg count (byte) + U16 name index (from r)
                const argc = code[pc++];
                const idx = code[pc] | (code[pc + 1] << 8);
                pc += 2;
                operand = `argc=${argc}`;
                detail = `r[${idx}]="${funcNames[idx] || '?'}"(${argc} args)`;
                break;
            }
            case 102: { // call_ctor: arg count + U16 name index
                const argc = code[pc++];
                const idx = code[pc] | (code[pc + 1] << 8);
                pc += 2;
                operand = `argc=${argc}`;
                detail = `new r[${idx}]="${funcNames[idx] || '?'}"(${argc} args)`;
                break;
            }
            case 96: // read_named: U16 name index from r
            case 104: { // read_prop_u16
                const idx = code[pc] | (code[pc + 1] << 8);
                pc += 2;
                operand = `r[${idx}]`;
                detail = `"${funcNames[idx] || '?'}"`;
                break;
            }
            case 35: { // push_dep: byte index
                const idx = code[pc++];
                operand = `deps[${idx}]`;
                detail = `"${deps[idx] || '?'}"`;
                break;
            }
            case 84: { // push_const: byte index into n
                const idx = code[pc++];
                operand = `n[${idx}]`;
                detail = JSON.stringify(constants[idx]);
                break;
            }
            case 112: { // store_local: byte index
                const idx = code[pc++];
                operand = `loc[${idx}]`;
                break;
            }
            case 147: { // push_local: byte index
                const idx = code[pc++];
                operand = `loc[${idx}]`;
                break;
            }
            case 25: // jump_if
            case 101: { // jump: signed offset (2 bytes?)
                // Read signed 16-bit offset
                const off = code[pc] | (code[pc + 1] << 8);
                const signed = off > 32767 ? off - 65536 : off;
                pc += 2;
                const target = start + (addr - start) + 3 + signed;
                operand = `${signed >= 0 ? '+' : ''}${signed}`;
                detail = `→ ${target}`;
                break;
            }
            case 132: { // jump_if_false
                const off = code[pc] | (code[pc + 1] << 8);
                const signed = off > 32767 ? off - 65536 : off;
                pc += 2;
                const target = start + (addr - start) + 3 + signed;
                operand = `${signed >= 0 ? '+' : ''}${signed}`;
                detail = `→ ${target}`;
                break;
            }
            case 24: { // cmp_eq_byte: 2 bytes
                const a = code[pc++];
                const b = code[pc++];
                operand = `#${a} #${b}`;
                break;
            }
            case 16: { // pop_or_byte
                const b = code[pc++];
                operand = `#${b}`;
                break;
            }
            default:
                // opcodes with no operands
                break;
        }

        const bytes = Array.from(code.slice(addr, pc)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
        const line = `  ${String(addr).padStart(4)}: ${bytes.padEnd(18)}  ${name.padEnd(16)} ${operand.padEnd(14)} ${detail}`;
        lines.push(line);
        console.log(line);
    }
    console.log(`└${'─'.repeat(60)}┘\n`);
    return lines;
}

// Disassemble all programs
console.log('PROGRAM 0: generateAESKey (the key generator)');
disasm(programs[0]);

console.log('PROGRAM 1: decryptString');
disasm(programs[1]);

console.log('PROGRAM 6: generateAESKey (extended)');
disasm(programs[6]);

console.log('PROGRAM 7: generateIV');
disasm(programs[7]);

console.log('PROGRAM 8: rsaEncrypt');
disasm(programs[8]);
