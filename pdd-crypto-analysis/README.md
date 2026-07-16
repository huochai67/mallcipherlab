# PDD 商品详情加密链分析

> 样本版本：`react_goods_c6c457883e861343f681_1026.js`
> 最近核验：2026-07-16
> 当前结论：Qre VM 的 key/IV、RSA 包装和响应解密协议均已还原，并有字节码差分测试。

## 1. 最终结论

商品详情请求的加密拦截器执行以下流程：

```text
Qre P6 生成 32 字符 key
        ↓
Qre P7 生成 16 字符 IV
        ↓
Qre P8：RSA PKCS#1 v1.5 加密 (IV + key)
        ↓
csr_risk_token 写入 POST body
        ↓
同一请求的 {key, iv} 保存到 config._encryptionKeys
        ↓
响应 encrypt_info 使用该请求对应的 key/iv 解密
```

三个关键纠错：

1. 真正的字节码 VM 名为 **Qre**；bundle 中的 `Rre` 是无关的 RegExp helper。
2. RSA 明文顺序为 **`iv + key`（16 + 32 字节）**，不是 `key + iv`。
3. `encrypt_info` 是 **Base64URL 密文 + 1 字符压缩标志**，没有可变 transport 前缀。

旧实现把 `key + iv` 封装进 RSA。该明文仍为 48 字节，服务端可以按“前 16 字节 IV、后 32 字节 key”解析，但解析出的材料与本地保存值不同，因而出现“`encrypt_status:3` 但本地 bad decrypt”。

## 2. key/IV 精确算法

### 2.1 key：Qre Program 6

```javascript
function generateAESKey() {
  const timestamp = Date.now().toString();
  const count = (localStorage.getItem('rs_count') || '000')
    .padStart(3, '0');
  const previous = localStorage.getItem('rs_key') || '';
  const previousTail = previous ? previous.slice(-5) : '';

  const base = 'v2' + timestamp + previousTail + count;
  const key = base + nanoid(Math.max(0, 32 - base.length));

  localStorage.setItem('rs_key', timestamp);
  const next = parseInt(count) + 1;
  localStorage.setItem(
    'rs_count',
    String(next > 999 ? 0 : next).padStart(3, '0')
  );
  return key;
}
```

首次状态的固定部分为 `v2 + 13位时间戳 + 000`，再补 14 个随机字符。已有 `rs_key` 时会加入上一时间戳末 5 位，通常再补 9 个随机字符。

### 2.2 nanoid

```javascript
const alphabet =
  'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';

function nanoid(size) {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  let result = '';
  while (size--) result += alphabet[bytes[size] & 63];
  return result;
}
```

原实现使用 Web Crypto、倒序读取随机字节，并以 `byte & 63` 选择字符。

### 2.3 IV：Qre Program 7

```javascript
const iv = SHA256(Date.now().toString() + 'iv')
  .toString()
  .substring(0, 16);
```

IV 是 SHA-256 十六进制字符串的前 16 字符。Program 0 先生成 key，再单独调用一次 `Date.now()` 生成 IV，因此两次时间戳可能相差 1 ms。

### 2.4 RSA：Qre Programs 0/8

```javascript
const rawKey = generateAESKey();
const rawIV = generateIV();
const encryptedData = rsaPkcs1v15(rawIV + rawKey);

return { encryptedData, rawKey, rawIV };
```

- 公钥：主 bundle 内置 RSA-2048 公钥。
- Padding：PKCS#1 v1.5。
- 明文：`iv + key`，共 48 字节 UTF-8。
- 输出：标准 Base64，约 344 字符，写入 `csr_risk_token`。

## 3. 响应解密协议

Qre Program 1 的线格式：

```text
encrypt_info = base64url(AES_ciphertext) + compression_marker
```

- 最后 1 字符是压缩标志。
- 标志为 `"1"`：AES 明文还需 `zlib.inflate`。
- 其他标志：AES 明文直接按 UTF-8 解码。
- Base64URL 的 `=` padding 可以省略，解码前补齐即可。

完整流程：

```text
marker = encrypt_info.slice(-1)
core   = encrypt_info.slice(0, -1)
    ↓
Base64URL decode（补齐 padding）
    ↓
AES-256-CBC / PKCS7
key = 32 字节 UTF-8，IV = 16 字节 UTF-8
    ↓
marker === "1" ? zlib.inflate : 原文
    ↓
UTF-8 → JSON.parse
```

响应拦截器直接读取当前 Axios request config 中的 `_encryptionKeys`，没有第二套响应密钥派生。

## 4. Qre VM 程序表

| ID | 名称 | 作用 |
|---:|---|---|
| 0 | `encryptKeyAndIv` | 生成 key/IV、按 `iv + key` 做 RSA 包装 |
| 1 | `decryptString` | 解析标志、AES 解密、可选 zlib、UTF-8 |
| 2 | `getCount` | 读取并补齐 `rs_count` |
| 3 | `setCount` | 递增计数，999 后回到 000 |
| 4 | `getPreKey` | 读取 `rs_key` |
| 5 | `setPreKey` | 保存本次时间戳 |
| 6 | `generateAESKey` | 生成 32 字符 key |
| 7 | `generateIV` | 生成 16 字符 IV |
| 8 | `rsaEncrypt` | JSEncrypt / PKCS#1 v1.5 |
| 9 | `aesDecrypt` | CryptoJS AES-CBC / PKCS7 |

字节码总长 960 字节，存于 `raw/bytecodes_b64.txt`。`scripts/disasm.js` 已按真实 U16 little-endian 操作数宽度修正；旧版反汇编把高位 `00` 误识别为 opcode。

## 5. anti_content 的位置

`anti_content` 与 Qre 加密拦截器是两条独立链：

- `react_anti_co_*.js` 的 module 47927/32455 负责 `anti_content`。
- 输出以 `0as` 开头，当前样本通常约 310 字符。
- `react_goods_*.js` 的 module 96361 包含 Qre、RSA、AES 与请求/响应拦截器。

本地调用：

```powershell
node scripts/anti_content.js
```

主程序现在只生成一次 token；模块调用和 CLI 输出一致。

## 6. 本地复现与测试

### 6.1 全部离线测试

```powershell
npm test
```

覆盖内容：

- 固定时间、固定随机源的 Qre key/IV golden vector。
- 可读实现与 960 字节 fixture 中 P0/P2-P7 key/IV 相关程序的差分执行。
- `rs_key`、三位计数器及 999 → 000 回卷。
- RSA 输入顺序断言：`iv + key`。
- 压缩与未压缩两种 `encrypt_info` marker。
- AES-256-CBC、PKCS7、Base64URL 与 JSON round-trip。

### 6.2 生成 key/IV

```powershell
node scripts/keygen.js
```

程序化调用：

```javascript
const { generateKeyIv, MemoryStorage } = require('./scripts/keygen');

const storage = new MemoryStorage();
const { key, iv } = generateKeyIv({ storage });
```

### 6.3 生成 csr_risk_token

```javascript
const { getcsr_risk_token } = require('./scripts/encryptToken');

const token = getcsr_risk_token();
console.log(token.key, token.iv, token.encryptedData);
```

### 6.4 离线解密

```powershell
node scripts/aes_response.js "ENCRYPT_INFO" "KEY_32_CHARS" "IV_16_CHARS"
```

### 6.5 请求脚本

```powershell
$env:PDD_COOKIES = "COOKIE_HEADER"
$env:OAK_RCTO = "OAK_RCTO"
node scripts/generate_request.js TARGET_GOODS_ID
```

当前请求脚本默认使用已修正的 Qre key/IV 和 `iv + key` RSA 顺序。外部传入 key/IV 时也使用同样顺序。

## 7. 验证状态

| 项目 | 状态 | 证据 |
|---|---|---|
| key 生成语义 | 通过 | 高层实现与原 Qre P6 固定向量逐字一致 |
| IV 生成语义 | 通过 | 高层实现与原 Qre P7 固定向量逐字一致 |
| 状态与计数器 | 通过 | 空状态、已有状态、回卷差分测试 |
| RSA 拼接顺序 | 通过 | Qre P0 oracle 与 `publicEncrypt` 输入断言均为 `iv + key` |
| 响应线格式 | 通过 | 本轮一次性原 Qre P1 动态探针；自动回归为合成 marker fixture |
| AES/zlib/JSON | 通过 | 压缩和未压缩 round-trip |
| anti_content CLI | 通过 | 本机 bundle 单次输出且为 `0as` 前缀；clean checkout 需补 `react_anti_co` chunk |
| 脱敏真实响应 fixture | 待补 | 当前仓库未提交真实 payload/key/IV fixture |
| 当前线上端到端请求 | 待复核 | 需要与当前 bundle、Cookie、`_oak_rcto` 同步核验 |

## 8. 浏览器捕获边界

加密拦截器对每个符合条件的 POST 单独生成 key/IV，并不是页面会话只生成一次。因此捕获时必须把 key/IV 与具体请求及响应配对。

现有 `capture_key.py` 的 setter 可以观察 `_encryptionKeys`，但只保存最后一次赋值；页面存在并发加密请求时可能取到另一请求的材料。更稳妥的采集记录应同时保存：

```text
request URL / request sequence
csr_risk_token
该 request config 的 key/iv
对应 response 的 encrypt_info
```

## 9. 文件导航

```text
pdd-crypto-analysis/
├── README.md
├── AES_REVERSE_NOTES.md
├── INVESTIGATION_STATUS.md
├── raw/
│   └── bytecodes_b64.txt
├── scripts/
│   ├── keygen.js                 # Qre P2-P7 可读实现
│   ├── vm_keygen_oracle.js       # 直接执行原字节码的差分 oracle
│   ├── test_keygen.js            # golden vector / RSA 顺序测试
│   ├── disasm.js                 # 修正后的 Qre 反汇编器
│   ├── encryptToken.js           # iv + key RSA 包装
│   ├── aes_response.js           # marker + AES + optional zlib
│   ├── verify_aes_fixture.js
│   ├── test_aes_tools.js
│   ├── anti_content.js
│   ├── generate_request.js
│   └── capture_key.py
└── tools/
    └── pdd_crypto_hook.user.js
```

`react_goods_*.js` 和 `react_anti_co_*.js` 体积较大并被 Git 忽略；提交的 `bytecodes_b64.txt`、oracle 和 golden vector 足以离线复核 key/IV 算法。
