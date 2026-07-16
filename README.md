# 国内电商 H5 / 移动端 API 加密研究

> 最后盘点：2026-07-16
> 范围：淘宝 MTOP、京东 h5st、拼多多商品详情响应加密。仅限已获授权的安全研究、互操作性验证与本地样本分析；不要使用真实用户凭据、绕过访问控制或对平台服务施加压力。

## 总览

| 平台 | 目录 | 当前结论 | 可复现状态 | 下一里程碑 |
|---|---|---|---|---|
| 淘宝 | `taobao-sign-report/` | 已定位 H5 MTOP 的 MD5 签名输入：token、毫秒时间戳、appKey 和未 URL 编码的 data。 | 公式可由本地脚本生成；随附样本因 Cookie 已刷新，现有结果与原请求签名不再一致。 | 用脱敏且时间一致的固定 fixture 做离线回归测试，并记录 token 刷新/失败响应边界。 |
| 京东 | `jd_h5st_research_report/` | 已锁定 SHA256 为 `78ff…c331` 的官方 h5st 5.3 历史构建，恢复 374 项字符串、5209 个整数编码单元、34 个 dispatcher 及全部 CFG。 | Python 进程内 QuickJS 完整离线签名、原生 Python 最终 dispatcher、构建错配检测和 golden fixture 均通过；Node 仅作差分 oracle。 | 扩充中间态 fixture，继续提高核心 worker 的原生 Python 语义覆盖，并建立多态构建差分。 |
| 拼多多 | `pdd-crypto-analysis/` | 已精确还原 Qre key/IV、`RSA(iv + key)`、逐请求密钥绑定，以及 `Base64URL ciphertext + 1字符压缩标志 → AES-256-CBC → optional zlib → JSON`。 | key/IV 原字节码差分、RSA 顺序、压缩/未压缩 AES fixture 均通过；真实响应 fixture 尚未入库。 | 使用当前 bundle 上下文复核实时请求，并提交完全脱敏的压缩与未压缩响应 fixture。 |

## 已完成资产

- `taobao-sign-report/`：签名说明、脱敏请求样本、Python 签名生成器和样本验证脚本。
- `jd_h5st_research_report/`：官方/可读双源码、构建 manifest、完整 VM 资产、CFG 反编译器、Python 进程内离线运行时、原生最终 dispatcher、Node 差分 oracle 和合成 golden fixture；当前仓库未包含 HAR 或会话材料。
- `pdd-crypto-analysis/`：Qre VM 反汇编与字节码 oracle、精确 key/IV 生成、`iv + key` RSA token、响应 marker/AES/zlib、anti_content 和测试脚本。

## 本次本地核验

| 检查项 | 结果 | 说明 |
|---|---|---|
| 拼多多 Qre key/IV 差分 | 通过 | `node pdd-crypto-analysis/scripts/test_keygen.js`；固定向量、状态、计数回卷和 `iv + key` RSA 顺序均通过。 |
| 拼多多 AES round-trip | 通过 | `node pdd-crypto-analysis/scripts/test_aes_tools.js`；压缩与未压缩 marker 均通过，真实 payload 分支为 SKIP。 |
| 拼多多响应 wire fixture | 通过 | `node pdd-crypto-analysis/scripts/verify_aes_fixture.js`；格式为无 padding Base64URL 密文加末尾 1 字符标志。 |
| 淘宝签名公式 smoke test | 通过 | `verify_algorithm.py` 仅使用合成输入验证 MD5 拼接公式，不包含任何请求样本或会话材料。 |
| 京东 h5st VM 与离线运行 | 通过 | `python -m unittest discover -s jd_h5st_research_report/tests -p "test_*.py" -v`；完整环境运行 12 项测试，覆盖双源码同构提取、34 个 CFG、entry 5134 官方 JS 差分、十段 QuickJS golden 与 Node oracle。 |

## 下一步行动

1. 继续补齐可复现性：淘宝与拼多多各加入一个不含账号、Cookie、商品/用户标识的离线 golden fixture；京东现有 fixture 固定源码哈希、时钟、PRNG、时区和浏览器 shim。
2. 扩展京东原生覆盖：为 `_$cps/_$rds/_$clt/_$ms` 绑定中间态 fixture，逐步把 dispatcher 语义从嵌入式官方 VM 迁入原生 Python，并对同版本号的多态构建建立自动差分。
3. 完善淘宝验证：将 `t`、token 和原始（未 URL 编码）`data` 放入同一脱敏 fixture，断言 MD5 结果；将“算法确认”与“实时请求成功”分开记录。
4. 完善拼多多测试边界：提交经脱敏且逐请求配对的 `encrypt_info`、key/IV 和期望 JSON 摘要，覆盖压缩与未压缩 marker；不要把真实会话材料写入仓库。
5. 建立维护机制：记录每个样本的采集日期、客户端/JS 版本、源码 SHA256、适用页面和失效信号；JS bundle 或接口字段变更时先更新 fixture，再更新结论。
6. 统一工程卫生：补充各项目最小命令和测试状态表，保持 HAR、请求头、Cookie、token、用户数据与商品私有数据在版本库之外。

## 建议的研究节奏

```text
离线 fixture 与单元测试
        ↓
源码哈希 / 构建 manifest
        ↓
静态提取 / CFG / 运行时差分
        ↓
版本与样本元数据
        ↓
变更监控与报告更新
```

## 目录导航

- [淘宝 MTOP 报告](taobao-sign-report/README.md)
- [京东 h5st 报告](jd_h5st_research_report/README.md)
- [京东 VM 反编译与解密过程](jd_h5st_research_report/DECOMPILATION_AND_DECRYPTION.md)
- [拼多多加密分析](pdd-crypto-analysis/README.md)
- [拼多多调查记录](pdd-crypto-analysis/INVESTIGATION_STATUS.md)
