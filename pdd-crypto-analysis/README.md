# PDD 拼多多移动端商品 API 加密逆向分析

> 分析目标：逆向 PDD 移动端商品详情页 API (`/proxy/api/api/oak/integration/render`) 的加密机制。
>
> 分析时间：2026-07
> 最终状态：解密管线已完全攻克，支持自动化 key 捕获 + 离线解密。

---

## 目录

1. [架构概览](#1-架构概览)
2. [加密机制详解](#2-加密机制详解)
3. [解密管线](#3-解密管线)
4. [工具与使用](#4-工具与使用)
5. [关键发现与限制](#5-关键发现与限制)
6. [文件清单](#6-文件清单)

---

## 1. 架构概览

PDD 移动端商品 API 使用三层防护：

```
请求层                   响应层
┌──────────────┐        ┌──────────────────────┐
│ anti_content │        │ encrypt_info          │
│ (行为指纹)    │        │ (AES-256-CBC + zlib) │
├──────────────┤        │ encrypt_status: 3     │
│ csr_risk_token│       └──────────────────────┘
│ (RSA 加密的密钥)│
└──────────────┘
```

**数据流**：

```
客户端生成 key/iv → RSA 加密为 csr_risk_token → POST 请求
    → 服务端验证 anti_content，解密 csr_risk_token
    → JSON 响应 → zlib deflate → AES-256-CBC 加密 → base64url + transport 包装
    → 客户端检测 encrypt_status=3 → 逆向解密 → 商品数据
```

---

## 2. 加密机制详解

### 2.1 encrypt_info（响应加密）

**Transport 格式**：

```
encrypt_info = <prefix> + <base64url_ciphertext> + <suffix>
```

prefix/suffix 长度可变（常见 6+2 或 0+1），保证 ciphertext base64url 长度 % 4 == 0。

**完整解密管线**：

```
encrypt_info
  → 剥 transport prefix+suffix
  → base64url decode → AES-256-CBC ciphertext
  → AES-256-CBC 解密 (key: 32B UTF-8, iv: 16B UTF-8, PKCS7)
  → zlib.inflate 解压 (头字节 0x78 0x9C)
  → JSON.parse → 商品数据
```

### 2.2 csr_risk_token（密钥交换）

- 算法：RSA-2048 PKCS#1 v1.5
- 明文：32 字符 key + 16 字符 iv = 48 字节 UTF-8
- 公钥：硬编码在主 bundle `Hk()[41]` 中
- 服务端 RSA 解密后使用独立密钥派生，**不使用客户端发送的 key/IV 直接加密**

### 2.3 anti_content（行为指纹）

- 由 `react_anti_co_*.js` chunk 中的 Rre VM 字节码生成
- 格式：`"0as"` 开头的 base64url 字符串（~310 字符）
- Node.js 可独立生成（见 `scripts/anti_content.js`）

### 2.4 Rre VM（字节码虚拟机）

- 960 字节 bytecode，50+ opcodes，10 个程序
- 程序 6 (generateAESKey)：构建 32 字符 key = `"v2" + Date.now() + counter + random`
- 程序 7 (generateIV)：构建 16 字符 iv = `SHA256(random + "iv")[0:16]`
- 已完整反编译（见 `scripts/disasm.js`）

---

## 3. 复现指南

### 3.0 前置准备

**环境依赖**：

```bash
# Node.js 工具
npm install

# Python 自动化捕获（方法 B 需要）
pip install git+https://github.com/feder-cr/invisible_playwright.git
python -m invisible_playwright fetch
```

**获取 JS bundle 文件**（anti_content 生成需要）：

打开 Chrome → F12 → Sources → 搜索 `react_anti_co` → 右键 Save as → 放入 `raw/` 目录。同时获取 `react_goods_*.js`（可选，仅供分析）。

**获取 Cookie**：

打开 `https://mobile.pinduoduo.com` 并登录。F12 → Application → Cookies → 至少需要这三条：
- `api_uid`
- `PDDAccessToken`
- `pdd_user_id`

**获取 `_oak_rcto`**：

从搜索结果页点击商品进入详情页，浏览器地址栏 URL 中包含 `_oak_rcto=...` 参数。此值可长期复用。

---

### 3.1 方法 A：浏览器油猴脚本（最简单）

1. 安装 Tampermonkey 浏览器扩展
2. 导入 `tools/pdd_crypto_hook.user.js`
3. 打开 PDD 商品页（URL 中需带 `_oak_rcto`），或从搜索结果点击进入
4. F12 Console 查看结果：

```javascript
// 获取 key/iv
window.__pdd.keys
// → { key: "v2178...", iv: "..." }

// 获取加密响应
window.__pdd.encrypted.encrypt_info

// 直接读解密数据（无需手动解密）
window.__pdd.decrypted.goods.goods_name
```

**跨商品复用**：同页面会话内 key/iv 不变。改 URL 中的 `goods_id` 后刷新页面，用同一对 key/iv 解密新响应。

**离线解密**——将捕获的 key/iv 和 encrypt_info 保存后用 Node.js 解密：

```powershell
node scripts/aes_response.js '<encrypt_info>' '<key>' '<iv>'
```

---

### 3.2 方法 B：invisible_playwright 全自动

```powershell
$env:PDD_COOKIES = "api_uid=...; PDDAccessToken=...; pdd_user_id=..."

# 捕获 key/iv（10-15 秒）
& python scripts/capture_key.py 976963702683
# 输出 JSON: {"key": "v2178...", "iv": "..."}
```

---

### 3.3 发送请求 + 解密响应

有了 key/iv 后，可独立发起请求：

```powershell
$env:PDD_COOKIES = "..."
$env:OAK_RCTO = "..."        # 从浏览器 URL 获取

# anti_content 由 Node.js 自动生成
# key/iv 从步骤 3.1 或 3.2 获取
node scripts/generate_request.js 624625371461 '<key>' '<iv>'
```

Node.js 程序化调用：

```javascript
const { generateAntiContent } = require('./scripts/anti_content');
const { getcsr_risk_token, decryptResponse } = require('./scripts/encryptToken');
const { decrypt } = require('./scripts/aes_response');

// 生成 anti_content
const anti = generateAntiContent();  // → "0as..."

// 用已知 key/iv 构建 csr_risk_token
const crypto = require('crypto');
const { RSA_PUBLIC_KEY } = require('./scripts/encryptToken');
const csr = crypto.publicEncrypt(
    { key: RSA_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(key + iv, 'utf8')
).toString('base64');

// 发送请求（需自行处理 HTTP，参考 generate_request.js）
// ...

// 解密响应
const data = decrypt(encrypt_info, key, iv).data;
// data.goods.goods_name → 商品名称
// data.price.min_group_price → 拼团价
```

---

### 3.4 端到端验证

```powershell
# 1. 确认 anti_content 生成正常
node scripts/anti_content.js
# 输出：0asWfxU...（~310 字符）

# 2. 确认加解密 round-trip
node scripts/test_aes_tools.js
# 输出：Round-trip: PASS

# 3. 确认线格式解析
node scripts/verify_aes_fixture.js
# 输出：wire-format fixture: PASS

# 4. 用真实数据完整验证
# 按 3.1 获取 key + iv + encrypt_info 后：
node scripts/aes_response.js '<encrypt_info>' '<key>' '<iv>'
# 输出：goods_name: ..., price: ...
```

---

## 4. 工具与使用

### 核心工具

| 工具 | 用途 | 运行方式 |
|---|---|---|
| `scripts/aes_response.js` | AES 解密 + zlib + transport | `node scripts/aes_response.js <ei> <key> <iv>` |
| `scripts/anti_content.js` | Node.js 生成 anti_content | `node scripts/anti_content.js` |
| `scripts/capture_key.py` | 自动化捕获 key/iv | `python scripts/capture_key.py <goods_id>` |
| `scripts/generate_request.js` | 一键请求管线 | `node scripts/generate_request.js <gid> <key> <iv>` |
| `scripts/key_discovery.js` | 18 种密钥策略测试 | `node scripts/key_discovery.js <ei> <key> <iv>` |

### 分析工具

| 工具 | 用途 |
|---|---|
| `scripts/disasm.js` | Rre VM 字节码反汇编器 |
| `scripts/keygen.js` | 密钥生成器（字节码反编译实现） |
| `scripts/analyze_encrypt_info.js` | encrypt_info 格式分析 |
| `scripts/verify_aes_fixture.js` | 线格式验证 |
| `scripts/encryptToken.js` | RSA 加密 + 解密 wrapper |
| `tools/pdd_crypto_hook.user.js` | 油猴脚本（fetch + JSON.parse hook） |

---

## 5. 关键发现与限制

### 已解决

- **解密管线**：transport → AES-256-CBC → zlib → JSON（完整实现）
- **anti_content 生成**：Node.js 独立运行，无需浏览器
- **key/IV 捕获**：通过 `Object.prototype` setter trap 或油猴脚本
- **字节码反编译**：Rre VM 960 字节完整反汇编，key/iv 格式已确认
- **key/IV 跨商品复用**：同页面会话内共用

### 限制

- **独立密钥生成**：服务端不使用 csr_risk_token 中的 key/IV 直接加密，有独立派生逻辑。无法从客户端静态分析。
- **主 bundle 无法独立运行**：`react_goods_*.js` 依赖 webpack runtime（HTML 内联脚本）
- **需要真实浏览器**：bare Chromium headless 被 PDD 检测，需要 `invisible_playwright`（C++ 级修补的 Firefox）
- **需要 `_oak_rcto`**：URL 参数，来自搜索结果页跳转，不在 cookie 中

---

## 6. 文件清单

```
pdd-crypto-analysis/
├── README.md                       # 本文档
├── AES_REVERSE_NOTES.md            # AES 逆向最终结论
├── INVESTIGATION_STATUS.md         # 调查历程与状态
├── scripts/
│   ├── aes_response.js             # ★ AES 解密 + zlib + transport 核心
│   ├── anti_content.js             # ★ anti_content Node.js 生成
│   ├── capture_key.py              # ★ invisible_playwright 自动捕获 key
│   ├── generate_request.js         # ★ 一键请求管线
│   ├── encryptToken.js             # RSA 加密 + 解密 wrapper
│   ├── key_discovery.js            # 18 种密钥策略测试
│   ├── keygen.js                   # 密钥生成器（反编译实现）
│   ├── disasm.js                   # Rre VM 字节码反汇编器
│   ├── analyze_encrypt_info.js     # encrypt_info 格式分析
│   ├── verify_aes_fixture.js       # 线格式验证
│   └── test_aes_tools.js           # AES 工具集成测试
├── tools/
│   └── pdd_crypto_hook.user.js     # 油猴脚本（方法 A 核心）
└── raw/                            # JS bundle 文件（需自行获取）
    └── react_anti_co_*.js          # anti_content chunk（~100KB）
```
