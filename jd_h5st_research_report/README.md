# 京东 h5st 5.3 VM 研究与离线运行

> 验收日期：2026-07-16<br>
> 样本：`js_security_v3_0.1.4.js` 的 2026-05-27 官方历史构建<br>
> 资产身份以 SHA256 为准；URL 中的 `0.1.4` 版本号不足以区分多态构建。

## 1. 当前状态

方案 A 已拆成三个可独立验收的层次：

| 层次 | 状态 | 实现与边界 |
|---|---|---|
| A1：构建绑定与静态移植 | 完成 | 词法安全提取 374 项字符串、5209 个整数编码单元、34 个 dispatcher、1124 个 case handler；恢复全部 CFG，共 3841 条可达指令。 |
| A2：完整离线签名运行 | 完成 | `h5st_runtime.py` 通过 Python `quickjs==1.19.4` 扩展在进程内执行固定官方 VM；无需 Node 子进程，浏览器宿主由确定性 shim 提供，全流程零网络。 |
| A3：原生 Python dispatcher | 完成首个执行切片 | `h5st_vm.py` 原生执行最终入口 5134 的真实 75-cell 尾段和全部 33 个 handler；`_$cps/_$rds/_$clt/_$ms` 由宿主注入。其余 dispatcher 由 A2 的嵌入式官方 VM 执行。 |

因此，项目已经具备可调用的 Python 离线签名 API、构建错配检查、完整静态反编译覆盖、原生尾部 VM 和固定回归 fixture。Node 工具仅作为 V8 差分 oracle。

详细过程见 [反编译与解密过程](DECOMPILATION_AND_DECRYPTION.md)。

## 2. 样本身份与构建绑定

| 资产 | 用途 | 大小 / 数量 | SHA256 |
|---|---|---:|---|
| 官方历史快照 `js_security_v3_0.1.4_20260527205706.js` | 逐字 golden 与完整运行 | 236,108 B | `78ff71158c7dc6284a0ab381370be33bc8fb8fd7f25571745330848eb766c331` |
| 可读样本 `js_security_v3_0.1.4_cc4cf49.js` | dispatcher 提取、调用链阅读 | 460,392 B | `bbe0f7569bc1823dcc90d7f41d9e28e7f5cc839704afb6ea1576a297ce1a3c78` |
| `_1hbrh` 解码表 | 字符串操作数 | 374 项 | canonical JSON `6cc5c66c97b2b6e48be64f46abfd0528a2c5dfbf735fb72fb56e1e3676f8da1c` |
| `_2xnrh` | VM 整数编码单元 | 5209 项 | canonical JSON `38e5fef28ac880e1d3b6203f354c5ff26d625b8f90737eb25895201fa83633d0` |
| dispatcher 元数据 | 入口、handler、跳转与字符串基址 | 34 个入口 / 1124 handlers | 由 manifest 绑定 |

来源：

- [官方 CDN 的 Wayback 快照](https://web.archive.org/web/20260527205706id_/https://storage.360buyimg.com/webcontainer/js_security_v3_0.1.4.js)
- [可读样本仓库与固定 commit](https://github.com/kb-ywl/h5st-/commit/cc4cf495fe1047f31ac621d5bb9345853b403f98)

两份源码的字符串表、字节码和 dispatcher 结构逐项相同。可读样本与官方快照在固定环境下生成的 h5st 仅第 8 段有一个字符差异，所以运行金标固定使用官方历史快照。

2026-07-16 采集的同名 CDN URL 已是另一构建：SHA256 `3a067e38c463d75c3e6aae32fac9049d01e9e245966a5e09d13ad675c768a23f`、数组 5133 项、最终入口 4998。`h5st_vm_manifest.json` 与提取器会在混用构建时立即报错。

## 3. 快速运行

### 3.1 安装 Python 运行时

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r jd_h5st_research_report\requirements.txt
```

### 3.2 生成固定离线 h5st

```powershell
.\.venv\Scripts\python jd_h5st_research_report\utils\h5st_runtime.py `
  --app-id 586ae `
  --params '{"functionId":"unionSearchGoods","appid":"unionpc","body":"4320c719309c0b8916765224c312f9e6e78e34f86dc87ef56aa75ca902a6665e"}' `
  --now-ms 1784168130123 `
  --seed 305419896 `
  --pretty
```

固定时钟、PRNG、UTC+8 视图和浏览器属性来自 `browser_shim.js`。网络对象是本地桩，延迟远程算法分支保持休眠。

### 3.3 Python API

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

## 4. 提取、反编译与原生入口

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

## 5. h5st 十段：fixture 证据

QuickJS golden fixture 位于 `tests/fixtures/golden_h5st.json`。固定结果总长 975，十段长度如下：

```text
17, 16, 5, 92, 64, 3, 13, 660, 64, 32
```

| 段 | 固定 fixture 中的可观测含义 | 证据等级 |
|---:|---|---|
| 1 | UTC+8 格式化时间 `YYYYMMDDHHmmssSSS` | 已测试 |
| 2 | 本地环境指纹 | 已测试 |
| 3 | 短应用标识，本 fixture 为 `586ae` | 已测试 |
| 4 | `tk06w...` 本地 token | 已测试 |
| 5 | 64 位十六进制中间签名值 | 已测试其形态与确定性 |
| 6 | 版本 `5.3` | 已测试 |
| 7 | 13 位毫秒时间戳 | 已测试 |
| 8 | 请求与环境扩展数据的编码载荷 | 已测试其输入敏感性与构建差分 |
| 9 | 64 位十六进制校验值 | 已测试其形态与确定性 |
| 10 | 32 字符最终尾签 | 已测试其形态与确定性 |

旧文档曾把第 8 段直接标为 AES-CBC、第 9 段标为 `SHA256(payload)`、第 10 段标为约 80 位 HMAC。这些描述缺少本构建的逐步数据流证据，现以实际 fixture 与反编译结果为准。项目中的“解密”主要指字符串表解码、控制流还原和编码载荷的数据流追踪；第 8 段的逆变换需要继续绑定中间态 fixture 才能命名每一层算法。

同一官方源码、同一仓库 shim 在 V8 与 QuickJS 下，十段中的 1–7、9–10 完全一致，第 8 段等长且仅一个字符不同；QuickJS fixture 是 Python API 的逐字金标，Node oracle 测试显式记录该引擎差异。

## 6. 自动化验收

```powershell
.\.venv\Scripts\python -m unittest discover `
  -s jd_h5st_research_report\tests `
  -p "test_*.py" `
  -v
```

当前结果：`Ran 12 tests ... OK`。覆盖内容：

- 官方快照与可读样本提取结果逐项相同；
- 未登记源码哈希快速拒绝；
- 字符串表、字节码、dispatcher 数量与 manifest 一致；
- 全 34 个 dispatcher 的 CFG 可达性验证；
- 原生 Python entry 5134 与官方 JS 差分一致；
- Python QuickJS 完整十段 golden fixture；
- 固定时间与固定 PRNG 的逐字确定性；
- Node/V8 与 Python/QuickJS 的已知单字符差异断言。

## 7. 文件布局

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
│   ├── fixtures/golden_h5st.json
│   ├── test_runtime.py
│   └── test_vm.py
└── utils/
    ├── browser_shim.js
    ├── h5st_runtime.py
    ├── h5st_client.py
    ├── h5st_generator.js
    ├── vm_bundle.py
    ├── vm_decompiler.py
    └── h5st_vm.py
```

## 8. 维护规则

1. 用源码 SHA256 标识构建，不以 URL 或 `0.1.4` 文本替代。
2. 字符串表、整数流和 dispatcher handler 必须从同一源码一次性提取。
3. 每次构建变化先生成新 manifest 和 fixture，再比较入口、字符串基址和十段输出。
4. 当前仓库未包含 HAR、Cookie、账号凭据或会话 token；fixture 为合成本地输入。
5. 结论统一标记为“已测试 / 静态推断 / 待绑定中间态”三类证据。
