# 调查历程与状态

## 时间线

### 阶段 1：基础分析

- 从浏览器抓取 `encrypt_info` 样本和对应 key/iv（`data/captured.json`）
- 发现 encrypt_info 无法直接 base64url decode → AES 解密
- 定位 transport 格式：`<prefix> + <base64url_ciphertext> + <suffix>`
- 定位 zlib 压缩：AES 解密后数据头 `0x78 0x9C`，需要 `zlib.inflate`

### 阶段 2：解密管线打通

- 实现 `aes_response.js`：自动检测 prefix/suffix + AES-256-CBC + zlib
- 用浏览器捕获的 key/iv 成功解密 `captured.json`
- 确认：蓝悦蓝牙耳机 (goods_id=963182786620, ¥25.49)

### 阶段 3：尝试独立密钥生成

尝试顺序：

1. **模拟 Xre() alphanumeric randomString** → bad decrypt
2. **base64url 编码随机字节** → bad decrypt（但发现浏览器 key 含 `-` 字符）
3. **v2 + Date.now() 格式** → bad decrypt
4. **v2 + timestamp + counter + random** → bad decrypt
5. **18 种推导策略**（MD5/SHA/HMAC/PBKDF2/XOR）→ 全部失败
6. **使用浏览器真实 key 通过我们的 RSA 加密发送** → encrypt_status:3 但 bad decrypt
7. **换 OAEP padding** → no encrypt_info
8. **对比测试**：浏览器 key 可解密 captured.json，但同一 key 通过我们的 RSA 发给服务端后无法解密新响应

**结论**：服务端有独立密钥派生逻辑，客户端 key 仅用于 token 验证，不用于响应加密。

### 阶段 4：Rre VM 字节码反编译

- 提取 960 字节 bytecode（base64 编码，1280 字符）
- 还原 55 个 opcode 的处理逻辑
- 反汇编 10 个程序的完整指令序列
- 确认 key 格式：`"v2" + Date.now() + counter + random`
- 确认 iv 格式：`SHA256(nanoid() + "iv")[0:16]`

### 阶段 5：anti_content 独立生成

- 加载 `react_anti_co_*.js` chunk 到 Node.js VM 沙箱
- 解决了 `navigator` getter-only 问题（改用 `vm.createContext`）
- 成功输出 `0as...` 格式的 anti_content（~310 字符）
- 发送请求验证：encrypt_status:3（服务端接受）

### 阶段 6：浏览器自动化

| 尝试 | 结果 |
|---|---|
| Playwright Chromium headless | JS 加载，React 不挂载 |
| Playwright + stealth.min.js | 同上 |
| Playwright + `navigator.webdriver=false` + `window.chrome` | 同上 |
| Playwright + 完整 URL（带 `_oak_rcto`）| 同上，确认不是 URL 问题 |

**发现**：JS bundle 全部加载成功（在 Network 日志中可见），但 React app 不 mount，`render` API 不触发。PDD 的检测在 C++ 引擎层面。

- **invisible_playwright**（C++ 补丁 Firefox）成功让 React 挂载
- 但 bare URL（仅 goods_id）仍不触发 API
- 加上 `_oak_rcto` 后 API 触发，render 成功

### 阶段 7：捕获 _encryptionKeys

尝试的方法：

| 方法 | 原理 | 结果 |
|---|---|---|
| `fetch(url, init)` hook 检查 `init._encryptionKeys` | key 在 fetch init 上 | ❌ key 在 body 对象上，不在 init |
| `JSON.stringify` hook | 序列化 body 前捕获 | ❌ webpack 捕获原始引用，hook 不触发 |
| `page.route` 网络拦截 | Playwright 路由层 | ✅ 捕获 csr_token + encrypt_info |
| 内存深度搜索 `_encryptionKeys` | 遍历所有全局对象 | ❌ key 仅在闭包局部变量 |
| **`Object.prototype` setter trap** | 拦截任意对象的 `_encryptionKeys` 赋值 | **✅ 成功捕获 key/iv** |

---

## 最终状态

| 组件 | 状态 | 备注 |
|---|---|---|
| encrypt_info 解密 | ✅ | transport + AES + zlib 完整管线 |
| anti_content 生成 | ✅ | Node.js 独立运行 |
| key/iv 捕获 | ✅ | 油猴脚本或 invisible_playwright |
| 独立密钥生成 | ❌ | 服务端不使用客户端 key |
| key/iv 跨商品复用 | ✅ | 同页面会话内共用 |
| 浏览器自动化 | ✅ | invisible_playwright + `_oak_rcto` |
| 独立请求管线 | ✅ | 需外部提供 key/iv |
| Rre VM 反编译 | ✅ | 960 字节完整反汇编 |

### 推荐工作流

**方法 A**（最简单）：油猴脚本 → 打开商品页 → `window.__pdd.keys` → 离线解密

**方法 B**（全自动）：
```powershell
$env:PDD_COOKIES = "..."
python scripts/capture_key.py <goods_id>
node scripts/aes_response.js '<encrypt_info>' '<key>' '<iv>'
```
