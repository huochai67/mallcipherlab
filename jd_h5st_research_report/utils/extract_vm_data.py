import re, json

data = open('D:\\Desktop\\tmp\\jd\\js_security_v3_0.1.4.js', 'r', encoding='utf-8').read()

# === String decoder ===
def d43(s):
    o = ''
    i = 0
    while i < len(s):
        c = ord(s[i])
        i += 1
        if c > 63:
            o += chr(c ^ 43)
        elif c == '#':
            o += s[i]
            i += 1
        else:
            o += chr(c)
    return o

# === Extract _1hbrh string table ===
def extract_1hbrh():
    match = re.search(r'var _1hbrh=\[([^\]]+)\]', data, re.DOTALL)
    if not match:
        return []
    
    raw = match.group(1)
    items = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch in ' \n\r\t,':
            i += 1
        elif raw[i:i+8] == '_4uxrh("':
            end = raw.index('")', i+8)
            encoded = raw[i+8:end]
            items.append(d43(encoded))
            i = end + 2
        elif ch == '"':
            end = raw.index('"', i+1)
            items.append(raw[i+1:end])
            i = end + 1
        elif ch == '-' or ch.isdigit():
            j = i
            while j < len(raw) and (raw[j].isdigit() or raw[j] in '-x'):
                j += 1
            items.append(int(raw[i:j]))
            i = j
        else:
            i += 1
        if len(items) > 1000:  # safety
            break
    return items

table = extract_1hbrh()
print(f"Decoded string table: {len(table)} entries")
# Save
with open('D:\\Desktop\\tmp\\jd\\h5st_string_table.json', 'w', encoding='utf-8') as f:
    json.dump(table, f, ensure_ascii=False)

# Print ALL decoded strings with indices
for idx, val in enumerate(table):
    if isinstance(val, str):
        print(f"  [{idx}] = {repr(val)}")

# === Extract _2xnrh bytecode ===
for pat in ['_2xnrh=[', 'var _2xnrh=[']:
    idx = data.find(pat)
    if idx >= 0:
        arr_start = data.index('[', idx)
        # Find matching close bracket
        depth = 1
        i = arr_start + 1
        while depth > 0 and i < len(data):
            if data[i] == '[':
                depth += 1
            elif data[i] == ']':
                depth -= 1
            i += 1
        raw = data[arr_start+1:i-1]
        bytecode = [int(x.strip()) for x in raw.split(',') if x.strip()]
        print(f"\nBytecode: {len(bytecode)} entries")
        with open('D:\\Desktop\\tmp\\jd\\h5st_bytecode.json', 'w') as f:
            json.dump(bytecode, f)
        
        # Analyze unique opcodes (use first bytecode at index 5134 for _$sdnmd)
        # The VM in _$sdnmd starts at p=5134
        opcodes_start = 5134
        ops = set()
        for i in range(opcodes_start, min(opcodes_start + 200, len(bytecode))):
            ops.add(bytecode[i])
        print(f"Opcodes used (near start): {sorted(ops)}")
        print(f"First 50 bytecodes: {bytecode[opcodes_start:opcodes_start+50]}")
        break

# === Extract _3a8rh (Function.prototype.call alias) ===
print("\n=== _3a8rh ===")
for m in re.finditer(r'var\s+_3a8rh\s*=\s*([^;]+)', data):
    print(f"  _3a8rh = {m.group(1)}")

# === Extract key = fingerprint and version ===
print("\n=== Finding _version and _fingerprint ===")
for m in re.finditer(r'this\._version\s*=\s*(\w+)', data):
    print(f"  this._version = {m.group(1)}")

for m in re.finditer(r'this\._fingerprint\s*=\s*(\w+)', data):
    print(f"  this._fingerprint = {m.group(1)}")

# === Find the start of _$sdnmd VM ===
print("\n=== _$sdnmd VM ===")
idx = data.find('_$sdnmd=function')
if idx > 0:
    # Find the bytecode array reference
    snippet = data[idx:idx+1500]
    print(snippet[:1000])
