import re
data = open('D:\\Desktop\\tmp\\jd\\js_security_v3_0.1.4.js', 'r', encoding='utf-8').read()

def d(s):
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

# Find the _1hbrh array
match = re.search(r'var _1hbrh=\[([^\]]+)\]', data)
if match:
    arr_content = match.group(1)
    items = re.findall(r'_4uxrh\("([^"]+)"\)|"([^"]*)"|(-?\d+)', arr_content)
    
    decoded = []
    for item in items:
        if item[0]:
            decoded.append(d(item[0]))
        elif item[1]:
            decoded.append(item[1])
        elif item[2]:
            decoded.append(int(item[2]))
    
    print(f'Decoded {len(decoded)} entries')
    
    # Print all decoded strings sorted
    strings = [(idx, val) for idx, val in enumerate(decoded) if isinstance(val, str)]
    for idx, val in strings:
        print(f'  [{idx}] = {repr(val)}')
