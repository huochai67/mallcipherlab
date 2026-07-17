# 京东 h5st 5.3 VM 研究与离线运行

> 验收日期：2026-07-16（A4 跟踪/纯算切片续写于同日会话）  
> 样本：`js_security_v3_0.1.4.js` 的 2026-05-27 官方历史构建  
> 资产身份以 SHA256 为准；URL 中的 `0.1.4` 版本号不足以区分多态构建。

## 1. 当前状态

方案 A 拆成四个可独立验收的层次：

| 层次 | 状态 | 实现与边界 |
|---|---|---|
| A1：构建绑定与静态移植 | 完成 | 词法安全提取 374 项字符串、5209 个整数编码单元、34 个 dispatcher、1124 个 case handler；恢复全部 CFG，共 3841 条可达指令。 |
| A2：完整离线签名运行 | 完成 | `h5st_runtime.py` 通过 Python `quickjs==1.19.4` 扩展在进程内执行固定官方 VM；无需 Node 子进程，浏览器宿主由确定性 shim 提供，全流程零网络。 |
| A3：原生 Python dispatcher | 完成首个执行切片 | `h5st_vm.py` 原生执行最终入口 5134 的真实 75-cell 尾段和全部 33 个 handler；`_$cps/_$rds/_$clt/_$ms` 由宿主注入。其余 dispatcher 由 A2 的嵌入式官方 VM 执行。 |
| A4：脱离厂商 JS 的纯算路径 | **完成（本构建 + shim）** | 已纯算：seData/eData、MD5/SHA256、HMAC/`local_key_3`、genKey、part5/9、part10、encode、fingerprint、defaultToken、**part8（`_$clt` env JSON + encode）**。`generate_h5st(app_id, params, now_ms=, seed=)` 可无注入材料逐字对齐 golden 十段。 |

**自动端到端十段签名**：A2（QuickJS 嵌官方源）仍是完整 VM 路径；**A4 纯 Python**在固定 seed/时钟/shim 环境下可独立复现 h5st（见 `h5st_native.generate_h5st`）。换浏览器指纹或真实 canvas 时 part8 静态字段（如 `bu14`）需按宿主覆盖。

详细过程见 [反编译与解密过程](DECOMPILATION_AND_DECRYPTION.md)。

## 2. 样本身份与构建绑定

| 资产 | 用途 | 大小 / 数量 | SHA256 |
|---|---|---:|---|
| 官方历史快照 `js_security_v3_0.1.4_20260527205706.js` | 逐字 golden 与完整运行 | 236,108 B（LF） | `78ff71158c7dc6284a0ab381370be33bc8fb8fd7f25571745330848eb766c331` |
| 可读样本 `js_security_v3_0.1.4_cc4cf49.js` | dispatcher 提取、调用链阅读 | 460,392 B | `bbe0f7569bc1823dcc90d7f41d9e28e7f5cc839704afb6ea1576a297ce1a3c78` |
| `_1hbrh` 解码表 | 字符串操作数 | 374 项 | canonical JSON `6cc5c66c97b2b6e48be64f46abfd0528a2c5dfbf735fb72fb56e1e3676f8da1c` |
| `_2xnrh` | VM 整数编码单元 | 5209 项 | canonical JSON `38e5fef28ac880e1d3b6203f354c5ff26d625b8f90737eb25895201fa83633d0` |
| dispatcher 元数据 | 入口、handler、跳转与字符串基址 | 34 个入口 / 1124 handlers | 由 manifest 绑定 |

来源：

- [官方 CDN 的 Wayback 快照](https://web.archive.org/web/20260527205706id_/https://storage.360buyimg.com/webcontainer/js_security_v3_0.1.4.js)
- [可读样本仓库与固定 commit](https://github.com/kb-ywl/h5st-/commit/cc4cf495fe1047f31ac621d5bb9345853b403f98)

两份源码的字符串表、字节码和 dispatcher 结构逐项相同。可读样本与官方快照在固定环境下生成的 h5st 仅第 8 段有一个字符差异，所以运行金标固定使用官方历史快照。

**换行警告：** Windows 上若 Git 将官方快照转成 CRLF，原始字节哈希会变成例如 `9395aeaa…`、体积约 236,112 B。manifest 与 `verify_assets()` 以 **LF 历史金标** `78ff7115…` 为准；检出后应用 `git config core.autocrlf false` 或 `git restore --source=HEAD -- archives/js_security_v3_0.1.4_20260527205706.js` 恢复后再跑 A2 测试。

2026-07-16 采集的同名 CDN URL 已是另一构建：SHA256 `3a067e38c463d75c3e6aae32fac9049d01e9e245966a5e09d13ad675c768a23f`、数组 5133 项、最终入口 4998。`h5st_vm_manifest.json` 与提取器会在混用构建时立即报错。

## 3. 快速运行

### 3.1 安装 Python 运行时

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r jd_h5st_research_report\requirements.txt
```

### 3.2 生成固定离线 h5st（A2 · QuickJS）

```powershell
.\.venv\Scripts\python jd_h5st_research_report\utils\h5st_runtime.py `
  --app-id 586ae `
  --params '{"functionId":"unionSearchGoods","appid":"unionpc","body":"4320c719309c0b8916765224c312f9e6e78e34f86dc87ef56aa75ca902a6665e"}' `
  --now-ms 1784168130123 `
  --seed 305419896 `
  --pretty
```

固定时钟、PRNG、UTC+8 视图和浏览器属性来自 `browser_shim.js`。网络对象是本地桩，延迟远程算法分支保持休眠。

### 3.3 Python API（A2）

```python
from h5st_runtime import generate_h5st

result = generate_h5st(
    "586ae",
    {
        "functionId": "unionSearchGoods",
        "appid": "unionpc",
        "body": "4320c719309c0b8916765224c312f9e6e78e34f86dc87ef56aa75ca902a6665e",
    },
    now_ms=1784168130123,
    seed=305419896,
)
assert len(result["h5st"].split(";")) == 10
```

从仓库外导入时，把 `jd_h5st_research_report/utils` 加到 `PYTHONPATH`，或直接复用 `h5st_client.py`。

## 4. 脱离厂商 JS：Node 跟踪 → 纯 Python（A4）

完整十段签名当前仍依赖 A2。A4 路线是先用 Node 把算法中间态钉死，再切片移植到纯 Python。

### 4.1 导出 golden 中间态

仓库已提交 `tests/fixtures/golden_trace.json`。需要重生成时：

```powershell
node jd_h5st_research_report\utils\h5st_trace.js --golden `
  > jd_h5st_research_report\tests\fixtures\golden_trace.json
```

固定输入下记录方法序、`_$atm`/`_$gdk`/`_$gs`/`_$gsd` 参数与返回值、十段拆分。典型方法序：

```text
_$cps → _$pam → _$rds → _$clt → _$atm → _$atm → _$gdk → _$gs → _$gsd → _$gsp → _$ms → _$sdnmd
```

### 4.2 已还原的魔改哈希（纯 Python）

```powershell
.\.venv\Scripts\python jd_h5st_research_report\utils\h5st_native.py `
  --app-id 586ae `
  --params '{"functionId":"unionSearchGoods","appid":"unionpc","body":"4320c719309c0b8916765224c312f9e6e78e34f86dc87ef56aa75ca902a6665e"}' `
  --now-ms 1784168130123 `
  --seed 305419896 `
  --analyze-only --pretty
```

`jd_crypto.py` 已对齐本构建：

| 步骤 | 规则（本构建） | 状态 |
|---|---|---|
| seData 分段 | 6 段、`×28 % 64`、字符表见下 | E3 纯算 |
| eData 盐 | 追加 `RvI<7|` | E3 纯算 |
| MD5 / SHA256（单次） | `sha256(prepare1(msg))`，`prepare1=seData+salt` | E3 纯算 |
| HmacSHA256 / `local_key_3` | message=`seData²+salt`；key=`eKey`（仅变换前 2 字符，可打印仿射 `((c-32)*7+8)%95+32`，逆序 pop）；长度>64 先标准 SHA256 key | E3 纯算 |
| genKey 双轮 | `mid=HMAC(material,token)`，`key=HMAC(mid,token)` | E3 纯算 |
| part5 `_$gs` | `SHA256(prepare1(key + body + key))`，`body=k:v&…` | E3 纯算 |
| part9 `_$gsd` | `SHA256(prepare1(key + "appid:appid&functionid:functionId" + key))` | E3 纯算 |
| part10 / `encode` | 自定义 Base64 表 `rqpo…zyxwvuts`；`len%3≠0` 时 PKCS 风格填充（填充字节值=填充长度）；4 字符分组反转后再整体反转；`len%3==0` 时前缀 `of7r`。`part10=encode(stk)` | E3 纯算 |
| part8 | `encode(JSON.stringify(env,null,2))`；`extend.random`=`Y8(11)`、`random`=`Y8(10)`；`bu14`=默认 pLabel `VRAEjxVEtV` | E3 纯算（空 storage） |
| part1 | `_$Y6`：`now_ms + 5000` → `yyyyMMddhhmmssSSS`（UTC+8 getters） | E3 纯算 |

字符表：

```text
nmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA-_9876543210zyxwvutsrqpo
```

纯算端到端（仅 seed / 时钟，无需注入 part8/token）：

```powershell
.\.venv\Scripts\python jd_h5st_research_report\utils\h5st_native.py `
  --app-id 586ae `
  --params '{"functionId":"unionSearchGoods","appid":"unionpc","body":"4320c719309c0b8916765224c312f9e6e78e34f86dc87ef56aa75ca902a6665e"}' `
  --now-ms 1784168130123 `
  --seed 305419896 `
  --time-str 20260716101535123 `
  --pretty
```

共享 PRNG 顺序：`warmup(1) → fingerprint(24) → clt Y8(11)+Y8(10) → token Y8(32)+4floor+Y8(12)`。

### 4.3 从跟踪得到的主流程

```text
_$cps(params)            → 按 key 排序的 [{key,value}, ...]
_$rds()                  → fingerprint（及 token/algo，若有缓存）
_$clt(now_ms)            → 第 8 段环境载荷
_$gdk → 两次 _$atm       → local_key_3 双轮派生业务 key   ✅ 纯算
_$gs(key, sortedParams)  → 第 5 段                           ✅ 纯算
_$gsd(key, …)            → 第 9 段（固定串，与 params 无关） ✅ 纯算
_$gsp(...)               → 十段拼接（第 10 段在 _$ms 内先算好再传入）
```

默认 local-token 路径上，首轮 `_$atm` 明文材料为：

```text
token + fingerprint + timeStr + "54" + appId + "jid+hR"
```

### 4.4 A4 验收清单

| 项 | 说明 |
|---|---|
| fingerprint | ✅ `_$YX`（入口 1068）：`generate_fingerprint` |
| defaultToken | ✅ `_$YE`（入口 1553）：`generate_default_token`；`tk06w`+adler8+expr+cipher；expr body=`Y8(32)[:5]` |
| 第 8 段 | ✅ `_$clt`：`generate_part8` / `build_env_json`；pretty indent-2 JSON + `encode` |
| 共享流 | ✅ `generate_fingerprint_part8_and_token`；fp → clt → token |
| 端到端 | ✅ `generate_h5st(...)` 无注入对齐 golden 十段 |
| part1 时间 | ✅ 厂商 `_$Y6` **固定** `ts += 5000` 再格式化为 `yyyyMMddhhmmssSSS`；part7 仍是原始 `Date.now()`。常量 `PART1_MS_OFFSET` |
| bu14 / pLabel | ✅ 字段 `bu14` ← `pLabel`；`WQ_dy1_pFlag` 无效时默认 `VRAEjxVEtV`。`resolve_plabel` / `bu14=` 可覆盖 |
| canvas | ✅ `canvas_fingerprint_from_data_url` = **标准 MD5** hex（`toDataURL()`）。shim 无 `getContext` → 无键（golden） |
| webglFp | ✅ **本构建只读** storage `WQ_gather_wgl1`（不写）。`pack_env_storage` / `webgl_fp_from_storage` / `webgl_fp=`。绘制生成不在本 JS 内（rac 为密文） |
| extend 检测位 | ✅ golden 钉 `bu4=0,bu5=0`；`infer_extend_statics(webdriver/phantom/cypress/…)` 覆盖宿主差分 |

## 5. 提取、反编译与原生入口（A1 / A3）

重新提取固定构建：

```powershell
python jd_h5st_research_report\utils\vm_bundle.py `
  jd_h5st_research_report\archives\js_security_v3_0.1.4_20260527205706.js `
  --output-dir "$env:TEMP\jd-vm-bundle"
```

验证 34 个 CFG：

```powershell
python jd_h5st_research_report\utils\vm_decompiler.py --validate-all
```

查看最终入口及 handler：

```powershell
python jd_h5st_research_report\utils\vm_decompiler.py 5134 --handlers
python jd_h5st_research_report\utils\h5st_vm.py
```

34 个 dispatcher 入口为：

```text
0, 131, 181, 199, 381, 433, 473, 741, 902, 1068, 1304,
1447, 1553, 1720, 1909, 2161, 2189, 2199, 2209, 2422,
2428, 2574, 2647, 4004, 4180, 4312, 4367, 4476, 4548,
4560, 4719, 5037, 5042, 5134
```

各 dispatcher 的 opcode 数字经过独立随机化；相同数字在不同入口里可表达不同语义。反编译器按每个函数自身的 `switch` handler 解码，而不是套用一张全局 opcode 表。

与 A4 相关的入口提示：`131`=`_append`，`181`=`_eData`，`199`=`_seData1`，`433`=MD5 侧 `_seData`，`5042`=`_$clt`，`4719`=`_$ms`，`5134`=`_$sdnmd`。

## 6. h5st 十段：fixture 证据

QuickJS golden fixture 位于 `tests/fixtures/golden_h5st.json`。固定结果总长 975，十段长度如下：

```text
17, 16, 5, 92, 64, 3, 13, 660, 64, 32
```

| 段 | 固定 fixture 中的可观测含义 | 证据等级 |
|---:|---|---|
| 1 | UTC+8 格式化时间 `YYYYMMDDHHmmssSSS`（本 golden 为 `20260716101535123`） | 已测试；与 shim `Date` 本地读数存在约 +5s 观测差，归因为厂商格式化/偏移，非简单 `now_ms` 直转 |
| 2 | 本地环境指纹 | 已测试 |
| 3 | 短应用标识，本 fixture 为 `586ae` | 已测试 |
| 4 | `tk06w...` 本地 token | 已测试 |
| 5 | 64 位十六进制中间签名值 | 已测试其形态与确定性；由 `_$gs(key, sortedParams)` 产出（跟踪） |
| 6 | 版本 `5.3` | 已测试 |
| 7 | 13 位毫秒时间戳（本 golden 与 `now_ms` 一致） | 已测试 |
| 8 | 请求与环境扩展数据的编码载荷（`_$clt`） | 已测试其输入敏感性与构建/引擎差分 |
| 9 | 64 位十六进制校验值 | 已测试其形态与确定性；由 `_$gsd(key, sortedParams)` 产出（跟踪） |
| 10 | 32 字符最终尾签 | 已测试其形态与确定性；在 `_$gsp` 前已算好（跟踪） |

旧文档曾把第 8 段直接标为 AES-CBC、第 9 段标为 `SHA256(payload)`、第 10 段标为约 80 位 HMAC。这些描述缺少本构建的逐步数据流证据，现以实际 fixture、跟踪与反编译结果为准。项目中的“解密”主要指字符串表解码、控制流还原、魔改哈希预处理还原，以及编码载荷的数据流追踪；第 8 段的逆变换需要继续绑定中间态 fixture 才能命名每一层算法。

同一官方源码、同一仓库 shim 在 V8 与 QuickJS 下，十段中的 1–7、9–10 完全一致，第 8 段等长且仅一个字符不同；QuickJS fixture 是 Python API 的逐字金标，Node oracle / `h5st_trace.js` 用于 V8 差分与中间态。

## 7. 自动化验收

```powershell
.\.venv\Scripts\python -m unittest discover `
  -s jd_h5st_research_report\tests `
  -p "test_*.py" `
  -v
```

测试模块：

| 模块 | 内容 |
|---|---|
| `test_vm.py` | 构建绑定、提取一致性、34 个 CFG、入口 5134 原生差分 |
| `test_runtime.py` | QuickJS 十段 golden、确定性、Node/V8 单字符边界（需 `quickjs`；Node 测试可选） |
| `test_native_crypto.py` | seData / MD5 / SHA256 纯算向量、native 脚手架、`h5st_trace.js` 冒烟（Node 可选） |

`test_native_crypto` 单独运行时期望 40 项通过（含 part8 / canvas / webgl storage / 纯算端到端）。全量用例数随 skip（无 quickjs / 无 node / 源码 CRLF 哈希错配）变化；**官方快照必须为 LF 金标哈希**，否则 A1/A2 相关用例会失败。

覆盖要点：

- 官方快照与可读样本提取结果逐项相同；
- 未登记源码哈希快速拒绝；
- 字符串表、字节码、dispatcher 数量与 manifest 一致；
- 全 34 个 dispatcher 的 CFG 可达性验证；
- 原生 Python entry 5134 与官方 JS 差分一致；
- Python QuickJS 完整十段 golden fixture；
- 固定时间与固定 PRNG 的逐字确定性；
- Node/V8 与 Python/QuickJS 的已知单字符差异断言；
- 纯 Python seData / MD5 / SHA256 / HMAC(eKey) / genKey / part5 / part9 / part10 与 golden 一致；
- **fingerprint / token / part8 纯算**与 golden part2/4/8 逐字一致；
- **无注入材料**时 `generate_h5st(seed, now_ms)` 完整十段与 golden 逐字一致；
- `h5st_trace.js` golden 跟踪冒烟。

## 8. 文件布局

```text
jd_h5st_research_report/
├── README.md
├── DECOMPILATION_AND_DECRYPTION.md
├── requirements.txt
├── archives/
│   ├── js_security_v3_0.1.4_20260527205706.js
│   ├── js_security_v3_0.1.4_cc4cf49.js
│   ├── h5st_vm_manifest.json
│   ├── h5st_vm_dispatchers.json
│   ├── h5st_string_table.json
│   └── h5st_bytecode.json
├── tests/
│   ├── fixtures/
│   │   ├── golden_h5st.json      # QuickJS 十段逐字金标
│   │   ├── golden_trace.json     # Node 中间态跟踪金标
│   │   └── final_vm.json
│   ├── js/final_vm_reference.js
│   ├── test_runtime.py
│   ├── test_native_crypto.py
│   └── test_vm.py
└── utils/
    ├── browser_shim.js
    ├── h5st_runtime.py           # A2 完整离线签名
    ├── h5st_client.py
    ├── h5st_generator.js         # V8 差分 oracle
    ├── h5st_trace.js             # A4 中间态跟踪
    ├── h5st_native.py            # A4 纯算脚手架
    ├── jd_crypto.py              # A4 魔改哈希纯算
    ├── vm_bundle.py
    ├── vm_decompiler.py
    └── h5st_vm.py                # A3 入口 5134
```

## 9. 维护规则

1. 用源码 SHA256 标识构建，不以 URL 或 `0.1.4` 文本替代；检出官方快照时保持 LF。
2. 字符串表、整数流和 dispatcher handler 必须从同一源码一次性提取。
3. 每次构建变化先生成新 manifest 和 fixture（含 `golden_h5st.json` / `golden_trace.json`），再比较入口、字符串基址、中间态和十段输出。
4. 当前仓库未包含 HAR、Cookie、账号凭据或会话 token；fixture 为合成本地输入。
5. 结论统一标记为“已测试 / 静态推断 / 待绑定中间态”三类证据。
6. A4 纯算未齐备前不得用 `h5st_native.generate_h5st` 冒充可上线签名；完整离线签名统一走 `h5st_runtime.generate_h5st`。
