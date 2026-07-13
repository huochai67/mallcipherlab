# 京东 h5st 参数逆向分析报告

> 版本: h5st v5.3 | 安全JS: v3_0.1.4 | 日期: 2026-07-07

---

## 目录

1. [h5st 结构分析](#1-h5st-结构分析)
2. [h5st 创建流程](#2-h5st-创建流程)
3. [各步骤细节](#3-各步骤细节)
4. [可行的逆向方案](#4-可行的逆向方案)
5. [当前研究现状](#5-当前研究现状)
6. [附录](#6-附录)

---

## 1. h5st 结构分析

h5st 是一个由 **分号(`;`)分隔的10段字符串**，每段携带不同的安全信息。

### 1.1 完整示例

```
<TIMESTAMP_YMD>;<FINGERPRINT>;<SHORT_CODE>;<TOKEN>;<HASH_INPUT>;5.3;<TIMESTAMP_MS>;<ENCRYPTED_PAYLOAD>;<PAYLOAD_HASH>;<SIGNATURE>
```

### 1.2 分段定义

| # | 名称 | 示例值 | 长度 | 含义 | 是否动态 |
|---|------|--------|------|------|---------|
| ① | `timestamp_ymd` | `<TIMESTAMP_YMD>` | 17位 | `YYYYMMDDHHmmssSSS` 格式时间戳 | ✅ 每次变化 |
| ② | `fingerprint` | `<FINGERPRINT>` | 16-17位 | 设备环境指纹(含canvas,webgl等) | ❌ 环境固定则固定 |
| ③ | `short_code` | `<SHORT_CODE>` | 5位 | 环境相关短码 | ❌ 环境固定则固定 |
| ④ | `token` | `<TOKEN>` | ~110位 | 加密token(含magic+version等) | ✅ 每次变化 |
| ⑤ | `hash_input` | `<HASH_INPUT>` | 64hex | SHA256(①~④签名) | ✅ 随输入变化 |
| ⑥ | `version` | `5.3` | 3位 | h5st版本号 | ❌ 固定值 |
| ⑦ | `timestamp_ms` | `<TIMESTAMP_MS>` | 13位 | Unix毫秒时间戳 | ✅ 每次变化 |
| ⑧ | `payload` | `<ENCRYPTED_PAYLOAD>` | ~416位 | 加密载荷(请求参数加密) | ✅ 随输入变化 |
| ⑨ | `hash_payload` | `<PAYLOAD_HASH>` | 64hex | SHA256(⑧校验) | ✅ 随载荷变化 |
| ⑩ | `signature` | `<SIGNATURE>` | ~80位 | 最终签名(HmacSHA256) | ❌ 环境固定则固定 |

### 1.3 各字段来源

```
① timestamp_ymd = BeijingTime.now().format("yyyyMMddHHmmssSSS")
② fingerprint   = _$Vz() → 采集 navigator/screen/canvas/WebGL/fonts 等环境数据 → MD5
③ short_code    = h5st生成器内置的环境相关值
④ token         = "tk" + magic + version + "w" + platform + "41" + expires + "l" + producer + 加密数据
⑤ hash_input    = SHA256(拼接①~④的特定字段)
⑥ version       = "5.3" (硬编码)
⑦ timestamp_ms  = Date.now()
⑧ payload       = AES-CBC加密(请求参数 + 环境数据)
⑨ hash_payload  = SHA256(⑧)
⑩ signature     = HmacSHA256(环境因子, 数据密钥)
```

---

## 2. h5st 创建流程

### 2.1 整体流程图

```
浏览器/爬虫 发起请求
       │
       ▼
┌─────────────────────────────┐
│ 1. 环境指纹采集 (_$Vz)       │ ← navigator, screen, canvas, WebGL...
│    → 生成 fingerprint(Part②)  │
└─────────────────────────────┘
       │
       ▼
┌─────────────────────────────┐
│ 2. Token 生成                │ ← 基于指纹 + 时间戳 + 内置密钥
│    → 生成 token(Part④)       │
└─────────────────────────────┘
       │
       ▼
┌─────────────────────────────┐
│ 3. 构建签名输入串            │ ← 取请求参数 + _stk 排序
│    → 生成 hash_input(Part⑤)  │
└─────────────────────────────┘
       │
       ▼
┌─────────────────────────────┐
│ 4. 加密载荷                  │ ← AES-CBC加密请求参数+环境数据
│    → 生成 payload(Part⑧)     │
└─────────────────────────────┘
       │
       ▼
┌─────────────────────────────┐
│ 5. 双重校验                  │
│    → SHA256(payload) Part⑨  │
│    → HmacSHA256(全部) Part⑩ │
└─────────────────────────────┘
       │
       ▼
┌─────────────────────────────┐
│ 6. 拼接 h5st                 │
│    ①;②;③;④;⑤;⑥;⑦;⑧;⑨;⑩    │
└─────────────────────────────┘
```

### 2.2 请求级联关系

基于已移除的敏感抓包整理出的请求链：

```
Step 1: getPageConfig (risk_h5_info)
        → 获取风控配置、CDN URL、策略参数
        ↓
Step 2: jsTk.do (jra.jd.com)
        → 获取 token/eid (如 "jdd03RTQ2FHW3X2BHWWP23P...")
        ↓
Step 3: getCustomCtrl (risk_h5_info)
        → 获取自定义控制参数
        ↓
Step 4: 正式API请求 (携带 h5st)
        → h5st由 ParamsSign.sign() 生成
```

---

## 3. 各步骤细节

### 3.1 环境指纹采集 (Part ②)

指纹采集在 `_$Vz()` 函数中实现，采集项包括：

| 采集项 | JS 代码 | 用途 |
|--------|---------|------|
| userAgent | `navigator.userAgent` | 浏览器标识 |
| platform | `navigator.platform` | 操作系统 |
| language | `navigator.language` | 语言 |
| cookies | `navigator.cookieEnabled` | Cookie支持 |
| timezone | `Intl.DateTimeFormat().resolvedOptions().timeZone` | 时区 |
| canvas | `canvas.toDataURL()` → MD5 | Canvas指纹 |
| webgl | WebGL getParameter 多项 | WebGL指纹 |
| screen | `screen.width/height/colorDepth` | 屏幕参数 |
| hardware | `navigator.hardwareConcurrency` | CPU核心数 |
| deviceMemory | `navigator.deviceMemory` | 内存 |
| fonts | 系统字体列表 | 字体指纹 |
| plugins | `navigator.plugins` | 插件列表 |
| audio | AudioContext 指纹 | 音频指纹 |

所有采集项经 MD5 哈希后作为指纹值。

### 3.2 Token 生成 (Part ④)

Token 生成在 `_$gdk()` VM 函数中实现，格式为：

```
tk{magic}{version}w{platform}41{expires}l{producer}{加密数据}
```

各字段含义：

| 字段 | 示例 | 来源 |
|------|------|------|
| `tk` | `tk` | 固定前缀 |
| `magic` | `06` | 内置魔数 |
| `version` | `w` | 算法版本标识 |
| `w` | `w` | 固定分隔符 |
| `platform` | `73` | 平台编码 |
| `41` | `41` | 固定分隔符 |
| `expires` | `d5` | 过期时间 |
| `l` | `l` | 固定分隔符 |
| `producer` | `f` | 生产者标识 |
| 加密数据 | `UL4eUm...` | AES加密的环境时间数据 |

### 3.3 签名算法 (Part ⑤)

```
_stk = "appid,body,client,clientVersion,functionId,keyword,loginType,t,uuid"
       ▲ _stk 定义哪些参数参与签名

待签数据 = 按 _stk 字段顺序取 value 拼接
sign = SHA256(key + "&" + 待签数据)
```

### 3.4 加密载荷 (Part ⑧)

载荷由以下步骤生成：

1. 收集环境数据 + 请求参数
2. AES-CBC 加密（密钥从 VM 中提取）
3. 结果编码为自定义字符集（`pjbMhjZ...` 格式）

加密载荷中 `JrJd`、`LDIj`、`Jrpj` 等重复模式表明其使用了**替换密码**层。

### 3.5 最终签名 (Part ⑩)

由 HmacSHA256 算法生成，密钥来源于：
- 设备指纹 (Part ②)
- Token 中的种子密钥
- 内部密钥 `DongG`

---

## 4. 可行的逆向方案

### 方案 A：VM 字节码移植 (当前采用)

**原理**：`js_security_v3_0.1.4.js` 使用栈式 VM 解释器执行安全算法。提取 VM 数据后用 Python 重写解释器。

**优点**：纯 Python、无需 Node.js
**缺点**：
- ~5000 条字节码指令，移植工作量大
- VM 有约 30 种操作码
- 需要模拟 JavaScript 函数调用语义
- 估算代码量 2000-3000 行

**现状**：已提取了字符串表 (`_1hbrh`) 和字节码 (`_2xnrh`)，但完整移植工作量过大。

### 方案 B：Node.js 子进程调用 (当前工作方案)

**原理**：在 Node.js 中 mock 浏览器环境，加载安全 JS，直接调用 `ParamsSign.signSync()`。

**优点**：
- ✅ **已验证可用**（返回 200/code=0）
- 实现简单，代码不到 100 行
- 跟随官方更新快

**缺点**：
- 依赖 Node.js 运行时
- 每次调用启动进程有 200-400ms 开销
- 环境 mock 不完整，指纹与真实浏览器不同

**核心代码**：

```javascript
// Node.js mock 环境 + 加载安全 JS
require('./sha256.js');
require('./js_security_v3_0.1.4.js');

const signer = new ParamsSign({ appId });
const result = signer.signSync(params);
console.log(result.h5st);
```

### 方案 C：Playwright 浏览器签名 (推荐生产)

**原理**：用 Python Playwright 控制真实 Chromium，在浏览器中执行签名。

**优点**：
- ✅ 真实浏览器指纹（canvas、WebGL、Audio 齐全）
- ✅ Part ⑩ 动态变化，不易被检测
- ✅ Cookie 自动管理
- ✅ 无法被 Node.js 检测
- ✅ 自动加载最新安全 JS

**缺点**：
- 需要安装 Chromium（~150MB）
- 内存占用较高

**示例代码**：

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto('https://search.jd.com/Search?keyword=test')
    page.wait_for_function('typeof ParamsSign === "function"')
    
    result = page.evaluate('''({appId, params}) => {
        const s = new ParamsSign({ appId });
        return s.signSync(params);
    }''', {'appId': 'search-pc-java', 'params': {...}})
    
    print(result['h5st'])
```

### 方案 D：jdh5st 项目的 cactus 接口方案

**原理**：调用 `cactus.jd.com/request_algo` 获取算法函数，再通过 `execjs` 执行。

**优点**：算法由服务端动态下发
**缺点**：适用于旧版 h5st 4.4，5.3 版本兼容性不明

### 方案对比

| 方案 | 实现难度 | 稳定性 | 防检测 | 性能 | 维护成本 |
|------|---------|--------|-------|------|---------|
| A. VM移植 | ★★★★★ | ★★★★ | ★★★★★ | ★★★★★ | ★★★★★ |
| B. Node子进程 | ★★ | ★★★★ | ★★ | ★★★ | ★★★ |
| **C. Playwright** | **★★** | **★★★★★** | **★★★★★** | **★★★** | **★★** |
| D. cactus接口 | ★★★ | ★★★ | ★★★ | ★★★★ | ★★★★ |

---

## 5. 当前研究现状

### 5.1 已知研究项目

| 项目 | 版本 | 方法 | 状态 |
|------|------|------|------|
| 本报告 (v0.1.4) | h5st 5.3 | VM字节码提取 + Node.js调用 | ✅ 通过验证 |
| jdh5st (GitHub) | h5st 4.4→5.3 | Node.js mock + Puppeteer回退 | ✅ 通过验证 |
| js_security_v3_main_0.1.8.js | h5st 5.3 | ParamsSignMain (同VM方案) | 已分析 |

### 5.2 版本演进

```
v4.4 (JS v0.1.7/0.1.8)
  ├── 8段h5st
  ├── 算法由 cactus.jd.com 下发
  └── 签名: MD5(key + data + key)
  
v5.3 (JS v0.1.4) ← 当前版本
  ├── 10段h5st ← 增加双重校验
  ├── VM字节码替代动态下发
  ├── 签名: SHA256 + HmacSHA256
  └── AES加密载荷
```

### 5.3 关键文件

| 文件 | 大小 | 版本 | 说明 |
|------|------|------|------|
| `js_security_v3_0.1.4.js` | 236KB | 0.1.4 | ParamsSign 类，含 VM 字节码 |
| `js_security_v3_0.1.8.js` | 65KB | 0.1.8 | ParamsSign 类（精简版） |
| `js_security_v3_main_0.1.8.js` | 237KB | 0.1.8 | ParamsSignMain 类，含 VM 字节码 |
| `sha256.js` | 3KB | - | SHA256 浏览器 polyfill |
| `pc-tk.js` | 50KB | - | Token/EID 获取 |
| `pc-core-disposal.js` | 49KB | 2.2.0 | 风控 SDK 加载器 |

### 5.4 已知反爬检测指标

1. **h5st Part ⑩ 一致性** — 同一会话中 Part ⑩ 固定不变，可被用于关联请求
2. **指纹缺失** — canvas/WebGL 指纹缺失或为默认值
3. **时间戳合理性** — h5st 时间戳与实际 HTTP 请求时间偏差
4. **Token 格式** — tk06w 与 tk03w 前缀差异（不同环境版本）
5. **请求间隔** — 无人类操作特征的固定间隔
6. **Cookie 绑定** — h5st 与 Cookie 中信息的关联校验

---

## 6. 附录

### 6.1 文件清单

```
h5st_research_report/
├── README.md                    ← 本报告
├── archives/
│   ├── h5st_string_table.json   ← _1hbrh 字符串表
│   ├── h5st_bytecode.json       ← _2xnrh VM 字节码
│   ├── js_security_v3_0.1.4.js  ← ParamsSign 安全JS
│   └── sha256.js                ← SHA256 库
└── utils/
    ├── h5st_generator.js         ← Node.js h5st 生成器
    ├── h5st_client.py            ← Python 封装
    ├── decode_strings.py         ← 字符串解码工具
    └── extract_vm_data.py        ← VM 数据提取工具
```

### 6.2 引用资源

- 京东搜索页: `https://search.jd.com/Search`
- 风控 API: `https://api.m.jd.com/api`
- Token API: `https://jra.jd.com/jsTk.do`
- 安全JS: `https://storage.360buyimg.com/webcontainer/js_security_v3_0.1.4.js`
- 算法接口: `https://cactus.jd.com/request_algo`
- GitHub 项目: `jdh5st` (h5st 4.4/5.3 研究)

### 6.3 免责声明

本报告仅供学习研究使用。请遵守相关法律法规及京东用户协议。

---

*报告生成日期: 2026-07-07*

