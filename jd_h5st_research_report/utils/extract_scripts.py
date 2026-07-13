import re
data = open('D:\\Desktop\\tmp\\jd\\search_page.html', 'r', encoding='utf-8').read()
# Find all script tags with src
for m in re.finditer(r'<script[^>]*src="([^"]+)"', data):
    print(m.group(1))
