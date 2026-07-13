import re, json, sys

sys.path.insert(0, 'D:\\Desktop\\tmp\\jd')
data = open('D:\\Desktop\\tmp\\jd\\js_security_v3_0.1.4.js', 'r', encoding='utf-8').read()

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

OUT = 'D:\\Desktop\\tmp\\jd\\jd_h5st_research_report\\archives'

# Extract string table - use simpler regex to find all _4uxrh("...") calls and strings
match = re.search(r'var _1hbrh=\[([^\]]+)\]', data, re.DOTALL)
if match:
    raw = match.group(1)
    
    # Find all _4uxrh("...") patterns
    items = []
    pos = 0
    while pos < len(raw):
        # Try match _4uxrh("...")
        m = re.match(r'_4uxrh\("([^"]*)"\)', raw[pos:])
        if m:
            items.append(d43(m.group(1)))
            pos += m.end()
            continue
        # Try match simple string "..."
        m = re.match(r'"([^"]*)"', raw[pos:])
        if m:
            items.append(m.group(1))
            pos += m.end()
            continue
        # Try match number
        m = re.match(r'-?\d+', raw[pos:])
        if m:
            items.append(int(m.group()))
            pos += m.end()
            continue
        # Skip other chars
        pos += 1
    
    with open(f'{OUT}/h5st_string_table.json', 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False)
    print(f'Saved {len(items)} string table entries')
    # Print first 30
    for i, v in enumerate(items[:30]):
        print(f'  [{i}] {repr(v)}')

# Extract bytecode
for pat in ['_2xnrh=[', 'var _2xnrh=[']:
    idx = data.find(pat)
    if idx >= 0:
        start = data.index('[', idx)
        depth = 1
        i = start + 1
        while depth > 0 and i < len(data):
            if data[i] == '[':
                depth += 1
            elif data[i] == ']':
                depth -= 1
            i += 1
        raw = data[start+1:i-1]
        bc = [int(x.strip()) for x in raw.split(',') if x.strip()]
        with open(f'{OUT}/h5st_bytecode.json', 'w') as f:
            json.dump(bc, f)
        print(f'Saved {len(bc)} bytecode entries')
        break
