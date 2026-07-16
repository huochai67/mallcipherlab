# Qre 加密与响应解密最终记录

> 样本：`react_goods_c6c457883e861343f681_1026.js`
> 修订日期：2026-07-16

## 1. 协议摘要

```text
key = Qre P6，32 字符 UTF-8
iv  = Qre P7，16 字符 UTF-8

csr_risk_token = RSA-2048 PKCS#1 v1.5 (iv + key)

encrypt_info = base64url(AES-256-CBC ciphertext) + compression_marker
```

响应解密：

```text
encrypt_info.slice(0, -1)
    → Base64URL decode（padding 可省略）
    → AES-256-CBC / PKCS7
    → marker === "1" 时 zlib.inflate
    → UTF-8
    → JSON.parse
```

## 2. key 生成

Qre Program 6：

```javascript
timestamp = Date.now().toString();
count = (localStorage.getItem('rs_count') || '000').padStart(3, '0');
previous = localStorage.getItem('rs_key') || '';
previousTail = previous ? previous.slice(-5) : '';

base = 'v2' + timestamp + previousTail + count;
key = base + nanoid(Math.max(0, 32 - base.length));

localStorage.setItem('rs_key', timestamp);
next = parseInt(count) + 1;
localStorage.setItem('rs_count', String(next > 999 ? 0 : next).padStart(3, '0'));
```

### nanoid 细节

```javascript
alphabet = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';
bytes = crypto.getRandomValues(new Uint8Array(size));

while (size--) {
  output += alphabet[bytes[size] & 63];
}
```

- 随机字节倒序消费。
- 使用 `byte & 63`。
- 首次空状态通常补 14 字符；已有 `rs_key` 时通常补 9 字符。
- `rs_count` 当前值先进入 key，之后才递增；`999` 使用后回卷到 `000`。

## 3. IV 生成

Qre Program 7：

```javascript
iv = SHA256(Date.now().toString() + 'iv')
  .toString()
  .substring(0, 16);
```

这里的 `toString()` 是 CryptoJS WordArray 的十六进制输出。IV 与 nanoid 无关。

## 4. RSA 包装顺序

Qre Program 0 的关键栈序列：

```text
generateAESKey → store key
generateIV     → DUP → store iv      # 栈上仍保留 iv
load key
ADD                                 # iv + key
rsaEncrypt
```

因此：

```javascript
plaintext = iv + key; // 16 + 32 = 48 bytes
```

Qre Program 8 使用 bundle 内 JSEncrypt 公钥和 PKCS#1 v1.5 padding，输出标准 Base64。

## 5. 响应 wire format

Qre Program 1 的开头等价于：

```javascript
const compressed = encryptInfo.slice(-1) === '1';
const core = encryptInfo.slice(0, -1);
```

随后：

```javascript
const ciphertext = base64urlDecode(core);
const plaintext = AES.decrypt(
  { ciphertext },
  CryptoJS.enc.Utf8.parse(key),
  {
    iv: CryptoJS.enc.Utf8.parse(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  }
);
```

`compressed` 为真时才调用 inflate。当前 VM 中没有可变前缀扫描，也没有 `(6,2)` transport 边界。

## 6. 旧实验为何产生 bad decrypt

| 旧现象 | 根因 |
|---|---|
| 自生成 token 返回 `encrypt_status:3`，本地解密失败 | 旧脚本使用 `key + iv`；服务端按前 16 字节 IV、后 32 字节 key 读取，得到另一组材料 |
| 浏览器 key/IV 重新包装后仍失败 | 重新包装继续沿用错误顺序 |
| 合法无 padding Base64URL 被解析器排除 | 旧解析器枚举 prefix/suffix，并要求 core 长度 `% 4 === 0` |
| 捕获值似乎跨请求复用 | 捕获器只保存最后一次赋值，存在请求与 key/IV 错配窗口 |
| 近似 keygen 只匹配格式 | 时间戳前序状态、三位计数器、nanoid 与 IV 来源均有误 |

这些旧结果不再支持“服务端另行派生响应密钥”的推断。静态 Axios 调用链显示响应拦截器使用同一请求的 `config._encryptionKeys.key/iv`；一次性原 Program 1 动态探针另行确认了 marker/AES 解码语义。

## 7. 差分验证

`scripts/test_keygen.js` 使用固定时间和固定随机字节，分别执行：

1. `scripts/keygen.js` 的可读实现。
2. `scripts/vm_keygen_oracle.js` 对提交 fixture 中的 P0/P2-P7 相关程序直接解释执行。

固定向量：

```text
key timestamp = 1700000000000
iv timestamp  = 1700000000001
random bytes  = 00 01 02 ...

key = v2170000000000000091T62-modnaesu
iv  = 93734a7fb72105df
RSA oracle plaintext = 93734a7fb72105dfv2170000000000000091T62-modnaesu
```

`npm test` 合并覆盖：

- 空 localStorage。
- 已有 `rs_key` / `rs_count`。
- `999 → 000` 回卷。
- `iv + key` RSA 顺序。
- 压缩 marker `1`。
- 未压缩 marker `0`。
- 无 Base64 padding 的 ciphertext。

执行：

```powershell
npm test
```

## 8. 当前工具状态

| 工具 | 当前用途 |
|---|---|
| `scripts/keygen.js` | Qre P2-P7 的可读实现 |
| `scripts/vm_keygen_oracle.js` | 直接执行原始 key/IV 字节码 |
| `scripts/test_keygen.js` | golden vector、状态和 RSA 顺序测试 |
| `scripts/disasm.js` | 精确 U16 操作数反汇编 |
| `scripts/encryptToken.js` | `iv + key` RSA 包装 |
| `scripts/aes_response.js` | marker、Base64URL、AES、可选 zlib |
| `scripts/generate_request.js` | 生成请求并尝试解密响应 |
| `scripts/key_discovery.js` | 保留的历史排查工具，不再代表当前主结论 |

## 9. 版本边界

- 结论对应文件名所示 bundle 样本；bundle 更新后应重新检查 Qre 元数据、公钥和拦截器。
- 仓库尚缺一个脱敏真实响应 fixture，当前真实样本分支仍显示 SKIP。
- 当前修改已完成 bundle/字节码级验证；实时请求还需用同版本上下文复核。
- 每个加密 POST 都生成新 key/IV，采集时必须按请求配对，不能取全局最后值代替。
