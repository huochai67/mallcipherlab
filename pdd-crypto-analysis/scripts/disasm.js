'use strict';

/** Exact disassembler for the 960-byte Qre VM fixture. */

const {
    BYTECODE,
    PROGRAMS,
    CONSTANTS,
    GLOBAL_NAMES,
    OPCODES,
} = require('./vm_keygen_oracle');

const opcodeNames = Object.fromEntries(
    Object.entries(OPCODES).map(([name, value]) => [value, name.toLowerCase()])
);

const callOpcodes = new Set([
    OPCODES.CALL_METHOD,
    OPCODES.NEW_GLOBAL,
    OPCODES.NEW_METHOD,
    OPCODES.CALL_GLOBAL,
]);
const globalU16Opcodes = new Set([
    OPCODES.GET_PROP,
    OPCODES.GET_PROP_ALT,
    OPCODES.SET_GLOBAL,
    OPCODES.PUSH_GLOBAL,
]);
const localU16Opcodes = new Set([
    OPCODES.STORE_LOCAL,
    OPCODES.PUSH_LOCAL,
]);
const jumpOpcodes = new Set([
    OPCODES.JUMP_TRUE,
    OPCODES.JUMP,
    OPCODES.JUMP_FALSE,
]);
const u8Opcodes = new Set([
    OPCODES.MAKE_ARRAY,
    OPCODES.ENTER_TRY,
]);

function readU16(pc) {
    return BYTECODE[pc] | (BYTECODE[pc + 1] << 8);
}

function signed16(value) {
    return value & 0x8000 ? value - 0x10000 : value;
}

function printable(value) {
    if (value === undefined) return 'undefined';
    return JSON.stringify(value);
}

function disassemble(program) {
    const end = program.offset + program.length;
    const lines = [];
    let pc = program.offset;

    while (pc < end) {
        const address = pc;
        const opcode = BYTECODE[pc++];
        const name = opcodeNames[opcode] || `unknown_0x${opcode.toString(16)}`;
        let operand = '';
        let detail = '';

        if (callOpcodes.has(opcode)) {
            const argc = BYTECODE[pc++];
            const index = readU16(pc);
            pc += 2;
            operand = `argc=${argc}, name=${index}`;
            detail = GLOBAL_NAMES[index] || '<out-of-range>';
        } else if (opcode === OPCODES.PUSH_CONST) {
            const index = readU16(pc);
            pc += 2;
            operand = `const=${index}`;
            detail = printable(CONSTANTS[index]);
        } else if (globalU16Opcodes.has(opcode)) {
            const index = readU16(pc);
            pc += 2;
            operand = `name=${index}`;
            detail = GLOBAL_NAMES[index] || '<out-of-range>';
        } else if (localU16Opcodes.has(opcode)) {
            const index = readU16(pc);
            pc += 2;
            operand = `local=${index}`;
        } else if (jumpOpcodes.has(opcode)) {
            const offset = signed16(readU16(pc));
            pc += 2;
            operand = `${offset >= 0 ? '+' : ''}${offset}`;
            detail = `-> ${pc + offset}`;
        } else if (u8Opcodes.has(opcode)) {
            operand = String(BYTECODE[pc++]);
        }

        const bytes = Array.from(BYTECODE.subarray(address, pc))
            .map(value => value.toString(16).padStart(2, '0'))
            .join(' ');
        lines.push(
            `${String(address).padStart(3)}  ${bytes.padEnd(12)}  ` +
            `${name.padEnd(18)} ${operand.padEnd(20)} ${detail}`.trimEnd()
        );
    }

    return lines;
}

function printProgram(program) {
    console.log(
        `\nProgram ${program.id}: ${program.name} ` +
        `(offset=${program.offset}, length=${program.length}, ` +
        `locals=${program.locals}, params=${program.params})`
    );
    console.log('-'.repeat(94));
    for (const line of disassemble(program)) console.log(line);
}

if (require.main === module) {
    console.log(`Total bytecode: ${BYTECODE.length} bytes`);
    const requested = process.argv.slice(2).map(Number).filter(Number.isInteger);
    const selected = requested.length
        ? PROGRAMS.filter(program => requested.includes(program.id))
        : PROGRAMS;
    for (const program of selected) printProgram(program);
}

module.exports = { disassemble, printProgram };
