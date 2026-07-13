# Taobao MTOP H5 Sign 逆向分析报告

## 目录

1. [概述](#1-概述)
2. [Sign 结构](#2-sign-结构)
3. [创建流程](#3-创建流程)
4. [流程细节](#4-流程细节)
5. [可行的逆向方案](#5-可行的逆向方案)
6. [当前研究现状](#6-当前研究现状)
7. [附录](#7-附录)

---

## 1. 概述

### 1.1 背景

MTOP (Mobile Taobao Open Platform) 是阿里巴巴旗下的移动开放平台 API 网关,淘宝 H5 页面及移动端 App 的所有 API 请求均通过 MTOP 网关转发。为保障接口安全,MTOP 对每个请求都要求携带 `sign` 签名参数,用于验证请求的合法性。

本次逆向分析的目标是淘宝 H5 推荐流接口:

```
https://h5api.m.taobao.com/h5/mtop.relationrecommend.wirelessrecommend.recommend/2.0/
```

### 1.2 样本来源

样本来源于 Chrome 浏览器 DevTools 导出的 cURL 命令(sample.txt),包含完整的请求 URL、请求头、Cookies 等信息。

### 1.3 核心结论

- 签名算法:**MD5**
- 签名公式:`sign = MD5(token + "&" + t + "&" + appKey + "&" + data)`
- Token 来源: Cookie `_m_h5_tk`,按 `_` 分割后取第一部分
- 算法已通过**真实请求验证**(HTTP 200,返回正常业务数据)

---

## 2. Sign 结构

### 2.1 请求 URL 构成

```
https://h5api.m.taobao.com/h5/{api}/{version}/
  ? jsv=2.7.4
  & appKey=12574478
  & t=<TIMESTAMP_MS>
  & sign=<SIGN_HEX>
  & api=mtop.relationrecommend.wirelessrecommend.recommend
  & v=2.0
  & type=jsonp
  & dataType=jsonp
  & callback=mtopjsonp6
  & data={...URL编码的JSON...}
  & ua=
```

### 2.2 参数说明

| 参数 | 示例值 | 说明 |
|------|--------|------|
| `jsv` | `2.7.4` | MTOP JavaScript SDK 版本号,固定值 |
| `appKey` | `12574478` | 应用标识,生产环境默认值;waptest 环境为 `4272` |
| `t` | `<TIMESTAMP_MS>` | 13位 Unix 时间戳(毫秒),每次请求动态生成 |
| `sign` | `<SIGN_HEX>` | **32位 MD5 签名**,本报告核心分析对象 |
| `api` | `mtop.relationrecommend...` | API 接口名 |
| `v` | `2.0` | API 版本号 |
| `data` | `{"appId":"34385",...}` | URL 编码后的**JSON 字符串**(请求体数据) |
| `callback` | `mtopjsonp6` | JSONP 回调函数名,自动递增编号 |

### 2.3 Sign 内容结构

Sign 是由 5 个要素通过 `&` 拼接后计算 MD5 得到的 32 位十六进制字符串:

```
sign = MD5(
  token           -- 从 _m_h5_tk cookie 提取
  + "&"
  + t             -- 时间戳(毫秒)
  + "&"
  + appKey        -- 应用标识
  + "&"
  + data          -- JSON.stringify(请求数据对象),非URL编码
)
```

---

## 3. 创建流程

### 3.1 完整流程图

```
┌─────────────────────────────────────────────────────────────────┐
│  浏览器端(H5) 发起 MTOP 请求                                      │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. 构造请求参数对象                                             │
│     { api, v, data, type, timeout, ... }                        │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. 序列化 data                                                │
│     data = JSON.stringify(dataObject)                           │
│     (若 data 已经是字符串则跳过)                                  │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. 获取 Token                                                 │
│     cookie = document.cookie.match(/_m_h5_tk=([^;]+)/)         │
│     token = cookie.split('_')[0]                                │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. 生成时间戳 & 签名                                           │
│     t = Date.now()                                              │
│     appKey = options.appKey || "12574478"                       │
│     signStr = token + "&" + t + "&" + appKey + "&" + data      │
│     sign = MD5(signStr)                                         │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. 拼装请求 URL                                               │
│     qs = { jsv, appKey, t, sign, api, v, ... }                 │
│     postdata = { data: c.data, ua: c.ua }                      │
│     url = path + "?" + encodeURI(qs) + "&" + encodeURI(data)   │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. 发起请求(JSONP / XHR / WindVane)                           │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 关键代码(源码反编译)

以下代码来自 `lib-mtop/2.7.4` (CDN: `g.alicdn.com/mtb/lib-mtop/2.7.4/mtop.js`):

```javascript
// ============ 步骤 3: 获取 Token ============
var B = "_m_h5_c";    // CDR 模式下的 token cookie
var C = "_m_h5_tk";   // 默认 token cookie

// CDR 模式下优先使用 _m_h5_c,否则使用 _m_h5_tk
a.CDR && l(B)
  ? a.token = l(B).split(";")[0]
  : a.token = a.token || l(C);

// 统一按'_'分割,取第一部分作为 token
a.token && (a.token = a.token.split("_")[0]);

// ============ 步骤 4: 生成签名 ============
// appKey: waptest 环境为 "4272",其他环境默认 "12574478"
var h = c.appKey || ("waptest" === d.subDomain ? "4272" : "12574478");
var j = (new Date).getTime();
var k = MD5(d.token + "&" + j + "&" + h + "&" + c.data);

// ============ 步骤 5: 拼装 URL ============
var l = {jsv: A, appKey: h, t: j, sign: k};

// 将 params 中未在 qs/data 中的参数加入 querystring
Object.keys(c).forEach(function(a) {
  "undefined" == typeof l[a]
  && "undefined" == typeof m[a]
  && "headers" !== a
  && "ext_headers" !== a
  && "ext_querys" !== a
  && (l[a] = c[a]);
});

// postdata= {data, ua}
var m = {data: c.data, ua: c.ua};

// 最终 URL: path + "?" + encodeURI(qs) + "&" + encodeURI(data)
d.querystring = l;
d.postdata = m;
d.path = g;
```

---

## 4. 流程细节

### 4.1 Token 提取

Token 来源于 Cookie `_m_h5_tk`,格式为:

```
_m_h5_tk={md5_token}_{timestamp}
```

例如样本中的值:

```
_m_h5_tk=<TOKEN_HEX>_<COOKIE_TIMESTAMP_MS>
```

提取规则:

1. 从 Cookie 中读取 `_m_h5_tk` 的值
2. 按 `_` 分割字符串
3. 取分割后的**第一个元素**作为 token

```
token = "<TOKEN_HEX>_<COOKIE_TIMESTAMP_MS>".split("_")[0]
      = "<TOKEN_HEX>"
```

Token 是一个 32 位十六进制字符串(即一个 MD5 值),在用户会话期间不变,但会在特定条件下刷新(如重新登录、跨域请求等)。

#### CDR 模式

当 `mainDomain !== pageDomain` 时(跨域请求),MTOP 会启用 CDR (Cross-Domain Request) 模式:

```javascript
c.mainDomain !== c.pageDomain && (c.maxRetryTimes = 4, c.CDR = !0);
```

在 CDR 模式下,Token 优先从 `_m_h5_c` Cookie 获取,兜底使用 `_m_h5_tk`:

```javascript
a.CDR && l(B)
  ? a.token = l(B).split(";")[0]
  : a.token = a.token || l(C);
```

如果请求出现 `TOKEN_EMPTY` 或 `ILLEGAL_ACCESS` 错误,MTOP 会自动清除 token cookie 并重试:

```javascript
if (d.indexOf("TOKEN_EMPTY") > -1 || ...
    d.indexOf("ILLEGAL_ACCESS") > -1 || ...) {
  // 清除 cookie 并重试
  m(B, c.pageDomain, "*");
  m(C, c.mainDomain, c.subDomain);
  m(D, c.mainDomain, c.subDomain);
}
```

### 4.2 时间戳 t

`t` 参数由 `Date.now()` 在**浏览器端**生成,表示请求发起的 Unix 时间戳(毫秒级)。

```javascript
var j = (new Date).getTime();
// 结果示例: <TIMESTAMP_MS>
```

- 精度: 13 位毫秒时间戳
- 生成时机: 在签名计算前瞬间生成
- 与服务端时间无关,完全由客户端决定
- `t` 同时参与签名运算且作为 URL 参数传输,服务端可用其进行**时间窗口校验**(防重放攻击)

抓包时，`_m_h5_tk` cookie 的 timestamp 部分可能与 URL 参数 `t` 不同，说明 cookie 在请求后被刷新。这在实际抓包中很常见——DevTools 导出的 cURL 命令携带的是**当前** cookie，而非请求时的原始 cookie。

### 4.3 appKey

`appKey` 是 MTOP 的应用标识:

- **生产环境** (h5api.m.taobao.com): `12574478`
- **waptest 环境** (acs.waptest.taobao.net): `4272`
- 可通过 `options.appKey` 或 URL 参数 `appKey` 覆盖

源码逻辑:

```javascript
var h = c.appKey || ("waptest" === d.subDomain ? "4272" : "12574478");
```

如果请求显式传入了 `appKey`,则使用传入值;否则根据 subDomain 自动选择默认值。

### 4.4 Data 序列化

`data` 参数是请求的业务数据,其生成过程:

#### 4.4.1 构造数据对象

在 JavaScript 中构造请求数据对象,例如样本请求:

```javascript
var innerParams = {
  device: "HMA-AL00",
  isBeta: "false",
  from: "nt_history",
  brand: "HUAWEI",
  q: "真空轮胎补胎液",
  page: 1,
  n: 48,
  // ... 其他参数
};

var dataObject = {
  appId: "34385",
  params: JSON.stringify(innerParams)
};
```

#### 4.4.2 JSON 序列化

```javascript
"object" == typeof this.params.data
  && (this.params.data = JSON.stringify(this.params.data));
```

如果 data 是对象,则调用 `JSON.stringify()` 序列化为字符串。序列化结果中,**键值对之间不包含空格**(`separators=(',', ':')` 等效效果)。

序列化结果示例:

```json
{"appId":"34385","params":"{\"device\":\"HMA-AL00\",...}"}
```

#### 4.4.3 URL 编码

序列化后的 JSON 字符串作为 `data` 参数的值,经过 `encodeURIComponent()` 编码后放入 URL:

```
data=%7B%22appId%22%3A%2234385%22%2C%22params%22%3A%22%7B%5C%22device%5C%22%3A%5C%22HMA-AL00%5C%22...
```

**关键:签名使用的是 JSON 序列化后的原始字符串(未 URL 编码)**:

```javascript
var sign = MD5(d.token + "&" + j + "&" + h + "&" + c.data);
//                                                                  ^^^^^^
//                                                    c.data 是原始 JSON 字符串,非 URL 编码后
```

而 URL 中的 `data` 参数值是对同一字符串进行 URL 编码后的结果:

```javascript
var postdata = {data: c.data, ua: c.ua};
// URL: path + "?" + encodeURI(qs) + "&" + encodeURI(postdata)
// 即 encodeURIComponent(c.data) 作为 data= 参数值
```

### 4.5 MD5 签名计算

使用标准 MD5 算法,对拼接字符串计算 32 位小写十六进制摘要:

```python
import hashlib

sign_str = token + "&" + t + "&" + appKey + "&" + data
sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
# 输出示例: <SIGN_HEX>
```

MD5 实现为标准 RSA MD5,源码中为纯 JavaScript 实现(约 200 行),验证与 Python `hashlib.md5`/Node.js `crypto.createHash('md5')` 输出一致。

### 4.6 URL 拼装

签名生成后,构建最终请求 URL:

```javascript
var l = {jsv: A, appKey: h, t: j, sign: k};   // querystring
var m = {data: c.data, ua: c.ua};              // postdata

// 将数据加入 querystring
Object.keys(c).forEach(function(a) {
  if ("undefined" == typeof l[a]
      && "undefined" == typeof m[a]
      && "headers" !== a
      && "ext_headers" !== a
      && "ext_querys" !== a) {
    l[a] = c[a];
  }
});

d.querystring = l;
d.postdata = m;
d.path = path;  // //h5api.m.taobao.com/h5/{api}/{v}/

// 最终 URL
url = path + "?" + g(querystring) + "&" + g(postdata);
// 其中 g(a) = Object.keys(a).map(k => k + "=" + encodeURIComponent(a[k])).join("&")
```

最终 URL 的参数顺序由 `Object.keys()` 遍历决定(ES6 规范下按插入顺序):

```
jsv → appKey → t → sign → api → v → timeout → type → dataType → callback → data → ua
```

> **注意**:虽然参数顺序不影响服务端验签(服务端用同样的参数重新计算 sign),但 URL 中参数顺序会随着代码运行时 `Object.keys` 的遍历顺序而定。

### 4.7 请求发送

MTOP 支持多种请求方式,按优先级自动选择:

| 优先级 | 方式 | 条件 |
|--------|------|------|
| 1 | WindVane (WV) | `window.WindVane` 存在且版本 ≥ 5.4 |
| 2 | Alipay JSBridge | 支付宝容器环境 |
| 3 | **JSONP** (H5 默认) | 纯浏览器环境,`type=jsonp` |
| 4 | XHR (JSON/OriginalJSON) | 同源请求或 CORS |

样本请求使用的是 **JSONP** 方式 (type=jsonp, callback=mtopjsonp6),即动态创建 `<script>` 标签发起跨域请求。

---

## 5. 可行的逆向方案

### 5.1 方案一:源码分析(当前采用)

**思路**:从 CDN 获取 MTOP SDK 源码,直接读取签名逻辑。

**步骤**:
1. 从 `g.alicdn.com/mtb/lib-mtop/{jsv}/mtop.js` 获取对应版本的 SDK
2. 定位 `__processRequestUrl` 方法
3. 读取 `d.token + "&" + j + "&" + h + "&" + c.data` 签名逻辑

**优点**:直接、准确,无需任何 hook
**缺点**:JS 代码经过混淆,需花时间阅读;各版本算法可能有差异

### 5.2 方案二:浏览器 Hook

**思路**:在浏览器中 Hook MTOP 关键函数,捕获签名前参数。

**步骤**:
1. 在页面加载前注入 Hook 脚本
2. Hook `__processRequestUrl` 或 MD5 函数
3. 捕获 `token`, `t`, `appKey`, `data` 参数及计算结果

**示例 Hook 代码**:

```javascript
// Hook MD5 函数
var originalMD5 = window.MD5 || MD5;
window.MD5 = function(str) {
  console.log('[SIGN INPUT]', str);
  var result = originalMD5(str);
  console.log('[SIGN OUTPUT]', result);
  return result;
};

// 或 Hook mtop 的 __processRequestUrl
var originalProcess = mtop.CLASS.prototype.__processRequestUrl;
mtop.CLASS.prototype.__processRequestUrl = function(callback) {
  console.log('[MTOP PARAMS]', this.params);
  console.log('[MTOP OPTIONS]', this.options);
  return originalProcess.call(this, callback);
};
```

**优点**:可捕获运行时真实数据
**缺点**:需要浏览器环境;需要绕过 SRI/ CSP 等安全策略

### 5.3 方案三:网络抓包 + 参数推导

**思路**:抓取多组请求,通过参数差异推导签名规则。

**步骤**:
1. 使用 Fiddler / Charles / Chrome DevTools 抓取多组请求
2. 对比不同请求中 `sign` 与 `t`, `data`, `appKey` 的关系
3. 通过已知明文攻击(已知 sign、data、t、appKey)反推 token

**优点**:无需接触 JavaScript 代码
**缺点**:需要多组样本;token 未知时无法直接验证

### 5.4 方案四:Node.js 重放验证

**思路**:用获取到的 token 和算法构造请求,发送到服务端验证。

**步骤**:
1. 从有效 Cookie 中提取 `_m_h5_tk`
2. 构造与样本相同的数据对象
3. 生成新的时间戳 `t` 和签名 `sign`
4. 发送请求,观察服务端响应

**优点**:可确认算法是否正确
**缺点**:需要有效的 Cookie(过期后需重新获取)

### 5.5 各方案对比

| 方案 | 难度 | 准确性 | 可持续性 | 环境要求 |
|------|------|--------|----------|----------|
| 源码分析 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 无 |
| 浏览器 Hook | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | 浏览器 |
| 网络抓包 | ⭐ | ⭐⭐⭐ | ⭐⭐ | 无 |
| 重放验证 | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 有效 Cookie |

---

## 6. 当前研究现状

### 6.1 已知信息

- MTOP 签名算法在安全社区中有较多讨论,核心算法 `MD5(token + "&" + t + "&" + appKey + "&" + data)` 已被公开
- Token 来源为 `_m_h5_tk` 或 `_m_h5_c` Cookie
- appKey 的默认值(12574478 / 4272)是公开的
- MTOP SDK 源码可通过 CDN 直接获取,版本可追溯

### 6.2 仍存在的问题

- **Token 刷新机制**:`_m_h5_tk` 的刷新条件尚不完全明确(已知与登录态、跨域、会话过期有关)
- **Token 生成算法**:token 本身（如 `<TOKEN_HEX>`）的生成方式未知——可能为 `MD5(secret + timestamp + 随机数)` 或服务端下发的随机值
- **防重放机制**:服务端可能对 `t` 有时间窗口校验(如 ±5 分钟),过期的 `t` 即使签名正确也会被拒绝
- **JSV 版本差异**:不同版本的 `jsv` 可能对应不同的 SDK 版本,签名算法可能存在差异
- **App 端签名**:Native App 的 MTOP 签名使用 `wua` (WindVane UA) 等额外参数,H5 端 API 不同

### 6.3 可深入的方向

1. **Token 生成逆向**:分析 `setCookie` 逻辑,确定 `_m_h5_tk` 的生成时机和算法
2. **服务端验签逻辑**:通过构造异常参数,探测服务端签名校验的时间窗口和容错机制
3. **版本差异对比**:对比不同 `jsv` 版本的 SDK 源码,追踪签名算法演进
4. **自动化工具**:基于已知算法开发自动化的签名生成和请求工具

---

## 7. 附录

### 7.1 Python 签名实现

```python
import hashlib
import json
import time

def mtop_sign(token: str, data: str, app_key: str = "12574478"):
    """
    生成 MTOP H5 签名

    Args:
        token: 从 _m_h5_tk cookie 提取的 token (按'_'分割取[0])
        data:  JSON.stringify(请求数据对象) 的结果
        app_key: appKey, 默认 "12574478"

    Returns:
        (sign, t): 签名和时间戳
    """
    t = str(int(time.time() * 1000))
    sign_str = token + "&" + t + "&" + app_key + "&" + data
    sign = hashlib.md5(sign_str.encode("utf-8")).hexdigest()
    return sign, t


def build_url(api: str, version: str, data_obj: dict, token: str,
              app_key: str = "12574478"):
    """
    构建完整的 MTOP 请求 URL

    Args:
        api: API 名称,如 "mtop.relationrecommend.wirelessrecommend.recommend"
        version: API 版本,如 "2.0"
        data_obj: 请求数据对象(dict)
        token: 签名 token
        app_key: appKey

    Returns:
        完整的请求 URL
    """
    import urllib.parse

    data_str = json.dumps(data_obj, separators=(",", ":"))
    sign, t = mtop_sign(token, data_str, app_key)

    params = {
        "jsv": "2.7.4",
        "appKey": app_key,
        "t": t,
        "sign": sign,
        "api": api,
        "v": version,
        "timeout": "10000",
        "type": "jsonp",
        "dataType": "jsonp",
        "callback": "mtopjsonp6",
        "data": data_str,
        "ua": "",
    }

    qs = "&".join(
        [f'{k}={urllib.parse.quote(str(v), safe="")}' for k, v in params.items()]
    )
    return f"https://h5api.m.taobao.com/h5/{api.lower()}/{version.lower()}/?{qs}"
```

### 7.2 验证请求示例

```python
import urllib.request
import json
import re

# 构造搜索请求
data_obj = {
    "appId": "34385",
    "params": json.dumps({
        "q": "手机",
        "page": 1,
        "n": 15,
    }, separators=(",", ":"))
}

token = cookie_val.split("_")[0]  # 从 _m_h5_tk 提取
url = build_url(
    "mtop.relationrecommend.wirelessrecommend.recommend",
    "2.0",
    data_obj,
    token
)

# 发送请求
headers = {
    "Cookie": cookie_str,
    "Referer": "https://s.taobao.com/",
    "User-Agent": "Mozilla/5.0 ...",
}

req = urllib.request.Request(url, headers=headers)
with urllib.request.urlopen(req) as resp:
    text = resp.read().decode("utf-8")
    # 解析 JSONP 响应
    json_str = re.sub(r"^mtopjsonp\d+\(", "", text).rstrip(")")
    result = json.loads(json_str)
    print(result.get("ret"))
```

### 7.3 样本脱敏说明

原始请求样本不保存在仓库中。后续如需创建离线 fixture，必须先移除以下敏感信息：

| 原始字段 | 脱敏处理 |
|----------|----------|
| `_m_h5_tk` | 替换为 `<M_H5_TK>_<TIMESTAMP>` |
| `_m_h5_tk_enc` | 替换为 `<M_H5_TK_ENC>` |
| `_tb_token_` | 替换为 `<TB_TOKEN>` |
| `cna` | 替换为 `<CNA>` |
| 用户昵称/ID | 替换为 `<USER>` |
| 其他 cookie token | 替换为 `<TOKEN>` 等占位符 |

### 7.4 参考资源

- MTOP SDK 源码 (v2.7.4): `https://g.alicdn.com/mtb/lib-mtop/2.7.4/mtop.js`
- MTOP 官方文档: `https://developer.taobao.com`
- 请求端点: `https://h5api.m.taobao.com/h5/{api}/{version}/`

---

> **报告日期**: 2026-07-07
> **分析对象**: mtop.relationrecommend.wirelessrecommend.recommend (v2.0)
> **SDK 版本**: lib-mtop v2.7.4
