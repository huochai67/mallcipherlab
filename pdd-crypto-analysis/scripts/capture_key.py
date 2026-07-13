"""
PDD key/iv capture — minimal implementation.
"""
import json, os, sys
from invisible_playwright import InvisiblePlaywright

GOODS_ID = sys.argv[1] if len(sys.argv) > 1 else "976963702683"
COOKIES_STR = os.environ.get("PDD_COOKIES", "")
OAK_RCTO = os.environ.get("OAK_RCTO", "")

if not OAK_RCTO:
    raise SystemExit("请通过环境变量 OAK_RCTO 提供当前会话参数；仓库不保存该值。")

cookies = []
if COOKIES_STR:
    for c in COOKIES_STR.split(";"):
        if "=" in (c := c.strip()):
            k, _, v = c.partition("=")
            cookies.append({"name": k.strip(), "value": v.strip(), "domain": ".pinduoduo.com", "path": "/"})

with InvisiblePlaywright() as browser:
    ctx = browser.new_context(viewport={"width": 1920, "height": 1080}, locale="zh-CN")
    if cookies:
        ctx.add_cookies(cookies)
    page = ctx.new_page()

    page.add_init_script("""
        Object.defineProperty(Object.prototype, '_encryptionKeys', {
            set: function(val) {
                if (val && val.key) window.__pdd_keys = { key: val.key, iv: val.iv };
                Object.defineProperty(this, '_encryptionKeys',
                    { value: val, writable: true, enumerable: true, configurable: true });
            },
            get: function() { return undefined; },
            configurable: true, enumerable: false
        });
    """)

    page.goto(
        f"https://mobile.pinduoduo.com/goods.html?goods_id={GOODS_ID}"
        f"&_oak_rcto={OAK_RCTO}"
        f"&page_from=401&refer_page_name=goods_detail&refer_page_sn=10014",
        wait_until="domcontentloaded", timeout=30000
    )
    page.wait_for_timeout(10000)

    keys = page.evaluate("() => window.__pdd_keys || null")
    if keys:
        print(json.dumps(keys))
    else:
        print("null")
        sys.exit(1)
