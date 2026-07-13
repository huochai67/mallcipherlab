# AES 逆向最终报告

## 解密管线结论

**完整解密管线**（已完全攻克）：
```
encrypt_info → 剥 transport_prefix+suffix → base64url decode
    → AES-256-CBC 解密 (key: 32B UTF-8, iv: 16B UTF-8, PKCS7)
    → zlib.inflate 解压 → JSON.parse → 商品数据
```

**encrypt_info 传输格式**：
```
encrypt_info = <prefix> + <base64url_ciphertext> + <suffix>
```
prefix+suffix 保证 core base64url 长度 % 4 == 0。常见 (6,2) 或 (0,1)。部分响应 core 尾部含 `==` 填充。

---

## 密钥研究

### key/iv 格式

通过 Rre VM 字节码反编译（960 bytes, 50+ opcodes, 10 个程序）确认：

- **key** (程序 6)：`"v2" + Date.now() + counter + random_base64url` = 32 chars
- **iv** (程序 7)：`SHA256(nanoid() + "iv").toString()[0:16]` = 16 chars

浏览器捕获样本验证过格式：
```
key: <REDACTED_32_CHAR_KEY>  (32 chars)
iv:  <REDACTED_16_CHAR_IV>   (16 chars)
```

### 独立密钥生成 — 不可行

| 尝试 | 方法 | 结果 |
|---|---|---|
| 1 | 模拟 Xre() → alphanumeric randomString | encrypt_status:3，bad decrypt |
| 2 | key = base64url(random bytes) | 同上 |
| 3 | key = v2 + Date.now() + random | 同上 |
| 4 | key = v2 + Date.now() + counter + random | 同上 |
| 5 | 18 种密钥推导策略（MD5/SHA/HMAC/PBKDF2 等） | 全部 bad decrypt |
| 6 | PKCS1 v1.5 + 浏览器真实 key 发送 | encrypt_status:3，bad decrypt |
| 7 | OAEP-SHA256 + 浏览器真实 key 发送 | no encrypt_info（拒绝） |
| 8 | 遍历 node_modules 找 PDD 的 nanoid 实现 | 使用不同 alphabet，无帮助 |

**结论**：RSA 加密正确（PKCS1 v1.5），服务端接受 token 返回 encrypt_status:3，但使用独立密钥派生逻辑，不直接使用 csr_risk_token 中的 key/IV。无法从客户端静态分析。

### key/iv 捕获方案

成功方案：`Object.prototype` setter trap 拦截 `_encryptionKeys` 赋值：

```javascript
Object.defineProperty(Object.prototype, '_encryptionKeys', {
    set: function(val) {
        if (val && val.key) window.__pdd_keys = { key: val.key, iv: val.iv };
        Object.defineProperty(this, '_encryptionKeys',
            { value: val, writable: true, enumerable: true, configurable: true });
    },
    get: function() { return undefined; },
    configurable: true, enumerable: false
});
```

### key/iv 复用

同一页面会话内，`_encryptionKeys` 设置一次后所有 render 请求共用。已验证跨商品复用。

---

## 浏览器自动化研究

| 方案 | 结果 | 原因 |
|---|---|---|
| Playwright Chromium headless + bare URL | JS bundle 加载但 React 不挂载 | PDD 检测 headless |
| Playwright + stealth.min.js 注入 | 同上 | stealth 仅 JS 层面，不够 |
| Playwright + `navigator.webdriver=false` | 同上 | PDD 检测更底层 |
| Playwright Chromium + 完整 URL (`_oak_rcto`) | 同上 | 非 URL 问题，是浏览器指纹 |
| **invisible_playwright** (C++ 修补 Firefox) + bare URL | React 加载但不触发 API | 缺少 `_oak_rcto` |
| **invisible_playwright + `_oak_rcto`** | **✅ 成功** | 真实浏览器指纹 + 正确 URL |
| `Object.prototype` trap 在 invisible_playwright | **✅ 捕获 key/iv** | |
| `JSON.stringify` hook | ❌ 失败 | 时序问题：webpack 捕获了原始引用 |
| `fetch init._encryptionKeys` hook | ❌ 失败 | key 在 body 对象上，不在 init 上 |
| `page.route` 拦截网络层 | ✅ 捕获 csr_token + encrypt_info | |
| 内存深度搜索 _encryptionKeys | ❌ 失败 | key 仅在闭包局部变量中 |

---

## RSA 加密验证

| 测试 | padding | plaintext | 结果 |
|---|---|---|---|
| PKCS1 v1.5 | RSA_PKCS1_PADDING | key + iv (48B UTF-8) | encrypt_status:3, bad decrypt |
| OAEP-SHA256 | RSA_PKCS1_OAEP_PADDING | key + iv | no encrypt_info |
| PKCS1 key only | RSA_PKCS1_PADDING | key (32B) | no encrypt_info |
| PKCS1 空 iv | RSA_PKCS1_PADDING | key + "" | no encrypt_info |

服务端严格验证 token 格式：需要 PKCS1 v1.5 加密的 48 字节明文。

---

## 工具链

| 工具 | 功能 | 状态 |
|---|---|---|
| `scripts/aes_response.js` | 完整解密管线 | ✅ |
| `scripts/anti_content.js` | Node.js 独立生成 anti_content | ✅ |
| `scripts/capture_key.py` | invisible_playwright 自动捕获 | ✅ |
| `scripts/generate_request.js` | 独立发送请求 | ✅ (需外部 key/iv) |
| `scripts/key_discovery.js` | 18 种策略测试 | ✅ (全部失败，确认为不可行路径) |
| `scripts/disasm.js` | Rre VM 反汇编 | ✅ 分析用 |
| `scripts/keygen.js` | 密钥生成器 | ⚠️ 格式正确但不匹配服务端 |
| `tools/pdd_crypto_hook.user.js` | 油猴脚本 | ✅ |
