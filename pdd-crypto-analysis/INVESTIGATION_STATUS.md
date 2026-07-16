# 调查历程与修订状态

> 最近修订：2026-07-16

## 1. 时间线

### 阶段 1：浏览器样本解密

- 捕获 `encrypt_info` 与一组 key/IV。
- 确认 AES-256-CBC、UTF-8 key/IV、PKCS7、zlib 和 JSON 主链。
- 当时通过边界枚举找到可解样本组合，误把样本解释为可变 transport prefix/suffix。

### 阶段 2：独立请求失败

历史尝试包括：

1. 多种随机 key 格式。
2. 时间戳、计数器和随机串组合。
3. MD5、SHA、HMAC、PBKDF2 等派生策略。
4. PKCS#1 v1.5 与 OAEP。
5. 浏览器捕获 key/IV 的重新 RSA 包装。

请求能返回 `encrypt_status:3`，但本地 key/IV 解密失败。当时据此推测存在额外服务端派生。

### 阶段 3：Qre VM 重新反编译

重新对主 bundle module 96361 和 960 字节程序做精确分析后发现：

- VM 名为 `Qre`，不是此前记录的 `Rre`。
- 所有常量、局部变量和名称索引均为 U16 little-endian。
- 旧反汇编把索引高字节 `00` 识别成独立 opcode，导致程序名、依赖和语义错位。
- Program 0/2/3/4/5/6/7/8/9 的功能已重新标定。

### 阶段 4：key/IV 精确恢复

最终语义：

```text
key = "v2"
    + 当前毫秒时间戳
    + 上一时间戳末 5 位（首次为空）
    + 三位滚动计数器
    + 定制 nanoid 补足到 32 字符

iv = SHA256(另一次 Date.now().toString() + "iv").hex[0:16]
```

状态保存到 `localStorage.rs_key` 和 `localStorage.rs_count`。nanoid 使用 Web Crypto、定制 64 字符表、倒序字节和 `byte & 63`。

### 阶段 5：RSA 顺序纠错

Program 0 的栈行为明确给出：

```text
RSA plaintext = iv + key
```

旧实现使用 `key + iv`。两者同为 48 字节，所以服务端仍能按固定长度读取；但读取结果与本地保存的 key/IV不同。这解释了“token 有响应、AES bad decrypt”，不需要额外密钥派生假设。

### 阶段 6：响应 wire format 纠错

本轮一次性动态探针直接运行原 Qre Program 1，确认：

```text
compressionFlag = encrypt_info.slice(-1) === "1"
cipherCore = encrypt_info.slice(0, -1)
```

Base64URL padding 可省略。旧解析器要求 core 长度 `% 4 === 0` 并搜索多字符前后缀，会排除合法密文。

### 阶段 7：原字节码差分验证

新增 `vm_keygen_oracle.js`，直接执行仓库提交的 `bytecodes_b64.txt`。它与 `keygen.js` 在以下场景逐字一致：

- 首次空状态。
- 已有前序时间戳和计数器。
- 短前序值。
- 空 storage 分支。
- 999 → 000 回卷。
- Program 0 的 `iv + key` 拼接。

同时新增压缩和未压缩响应 marker 的 AES round-trip。

## 2. 旧结论修订表

| 旧结论 | 修订结论 |
|---|---|
| VM 名为 Rre | VM 名为 Qre；Rre 是无关 RegExp helper |
| key 仅为时间戳 + 随机近似格式 | key 还绑定 `rs_key` 末 5 位和三位滚动计数器 |
| IV 来源于 nanoid | IV 为 `SHA256(Date.now()+"iv").hex[0:16]` |
| RSA 明文为 key + iv | RSA 明文为 `iv + key` |
| 服务端另行派生响应密钥 | 响应拦截器直接使用同一 request config 的 key/IV |
| encrypt_info 有可变前缀/后缀 | 仅有末尾 1 字符压缩标志 |
| 同页面会话复用同一 key/IV | 每个符合条件的加密 POST 都重新生成 |
| 全局最后一组 key 可配任意响应 | key/IV 必须与具体请求和响应配对 |

## 3. 当前状态

| 组件 | 状态 | 备注 |
|---|---|---|
| Qre 程序元数据 | ✅ | 10 programs 已重新标定 |
| opcode/操作数宽度 | ✅ | U16/U8/S16 已修正 |
| key 生成 | ✅ | 高层实现与原字节码差分通过 |
| IV 生成 | ✅ | 固定向量与原字节码一致 |
| RSA padding | ✅ | PKCS#1 v1.5 |
| RSA 明文顺序 | ✅ | `iv + key` |
| 响应 key/IV 来源 | ✅ | 当前 request config `_encryptionKeys` |
| encrypt_info 线格式 | ✅ | 一次性原 P1 探针；自动回归使用合成 fixture |
| AES/zlib/JSON | ✅ | 压缩与未压缩离线测试通过 |
| anti_content CLI | ✅ | 单次生成，`0as` 前缀 |
| 脱敏真实响应 fixture | ⏳ | 仓库内尚未提交 |
| 当前线上端到端 | ⏳ | 需同版本请求上下文复核 |

## 4. 本地核验

```powershell
npm test
```

预期关键输出：

```text
Qre key/IV golden vector: PASS
Qre bytecode differential: PASS
RSA plaintext order (iv + key): PASS
Round-trip: PASS
Uncompressed marker: PASS
wire-format fixture: PASS
```

真实 `data/payload.json` 和历史 `decrypt_test.js` 未入库，因此相关兼容分支仍显示 `SKIP`。

## 5. 当前请求工作流

独立生成与请求：

```powershell
$env:PDD_COOKIES = "COOKIE_HEADER"
$env:OAK_RCTO = "OAK_RCTO"
node scripts/generate_request.js TARGET_GOODS_ID
```

离线解密：

```powershell
node scripts/aes_response.js "ENCRYPT_INFO" "KEY_32_CHARS" "IV_16_CHARS"
```

## 6. 后续核验重点

1. 使用当前 bundle 与请求上下文复核实时 `RSA(iv + key)` 闭环。
2. 提交不含账号、Cookie、商品私有数据的真实 response fixture。
3. 分别保留 marker `1` 和未压缩响应 fixture。
4. 将浏览器捕获器升级为逐请求队列，记录 URL、csr token、key/IV 和对应 response。
5. bundle 变化时重新检查 Qre 程序表、公钥、alphabet 与拦截器条件。
