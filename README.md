# 国内电商 H5 / 移动端 API 加密研究

> 最后盘点：2026-07-13  
> 范围：淘宝 MTOP、京东 h5st、拼多多商品详情响应加密。仅限已获授权的安全研究、互操作性验证与本地样本分析；不要使用真实用户凭据、绕过访问控制或对平台服务施加压力。

## 总览

| 平台 | 目录 | 当前结论 | 可复现状态 | 下一里程碑 |
|---|---|---|---|---|
| 淘宝 | `taobao-sign-report/` | 已定位 H5 MTOP 的 MD5 签名输入：token、毫秒时间戳、appKey 和未 URL 编码的 data。 | 公式可由本地脚本生成；随附样本因 Cookie 已刷新，不能重新匹配原请求签名。 | 用脱敏且时间一致的固定 fixture 做离线回归测试，并记录 token 刷新/失败响应边界。 |
| 京东 | `jd_h5st_research_report/` | 报告已拆解 h5st 字段、环境指纹、token、载荷与最终签名，并保留字节码/字符串表。原始 HAR 已移除，避免保存请求与会话材料。 | 当前生成器不能直接运行：`utils/h5st_generator.js` 以相对路径加载的 `sha256.js` 与安全 JS 不在 `utils/` 下。 | 修复资源定位、加入离线 golden fixture，并明确当前 JS 版本与适用范围。 |
| 拼多多 | `pdd-crypto-analysis/` | 已实现并验证响应解密链：transport 拆包 → Base64URL → AES-256-CBC → zlib → JSON；也已完成 anti_content 分析与 key/IV 捕获研究。 | `test_aes_tools.js` 的 round-trip 通过，`verify_aes_fixture.js` 通过；真实 payload fixture 不在仓库，因此两项真实样本解析被跳过。 | 固化完全脱敏的真实响应 fixture、增加端到端离线回归，并把浏览器采集与解密能力清晰隔离。 |

## 已完成资产

- `taobao-sign-report/`：签名说明、脱敏请求样本、Python 签名生成器和样本验证脚本。
- `jd_h5st_research_report/`：h5st 结构报告、VM 字节码和字符串表，以及 Node/Python 调用封装与提取工具；原始 HAR 已移除。
- `pdd-crypto-analysis/`：AES 解密、加密响应格式解析、anti_content 分析、字节码反汇编、RSA token 包装、测试脚本和浏览器端观察脚本。

## 本次本地核验

| 检查项 | 结果 | 说明 |
|---|---|---|
| 拼多多 AES round-trip | 通过 | `node pdd-crypto-analysis/scripts/test_aes_tools.js`；真实 payload / 历史解密样本缺失，相关检查为 SKIP。 |
| 拼多多 transport fixture | 通过 | `node pdd-crypto-analysis/scripts/verify_aes_fixture.js`。 |
| 淘宝签名公式 smoke test | 通过 | `verify_algorithm.py` 仅使用合成输入验证 MD5 拼接公式，不包含任何请求样本或会话材料。 |
| 京东 h5st 生成器 | 阻塞 | 运行时找不到 `./sha256.js`；现有文件位于 `archives/sha256.js`，且安全 JS 文件未出现在目录清单中。 |

## 下一步行动

1. 先补齐可复现性：每个平台各加入一个不含账号、Cookie、商品/用户标识的离线 golden fixture，测试只验证序列化、签名或解密结果，不发网络请求。
2. 修复京东工具链：将依赖文件放入受控位置或改用基于 `__dirname` 的明确路径；启动后以固定输入输出写 Node 与 Python 双层 smoke test。
3. 完善淘宝验证：将 `t`、token 和原始（未 URL 编码）`data` 放入同一脱敏 fixture，断言 MD5 结果；将“算法确认”与“实时请求成功”分开记录。
4. 完善拼多多测试边界：提交经脱敏的 `encrypt_info`、key/IV 和期望 JSON 摘要，恢复当前被跳过的解析与解密验证；不要把真实会话材料写入仓库。
5. 建立维护机制：记录每个样本的采集日期、客户端/JS 版本、适用页面和失效信号；JS bundle 或接口字段变更时先更新 fixture，再更新结论。
6. 统一工程卫生：补充根目录的运行环境说明、各项目最小命令、测试状态徽记（或表格）和 `.gitignore`，明确禁止提交 HAR 中的敏感请求头、Cookie、token、用户数据或商品私有数据。

## 建议的研究节奏

```text
离线 fixture 与单元测试
        ↓
资源路径 / 脚本可启动性
        ↓
版本与样本元数据
        ↓
经授权的最小化集成验证
        ↓
变更监控与报告更新
```

## 目录导航

- [淘宝 MTOP 报告](taobao-sign-report/README.md)
- [京东 h5st 报告](jd_h5st_research_report/README.md)
- [拼多多加密分析](pdd-crypto-analysis/README.md)
- [拼多多调查记录](pdd-crypto-analysis/INVESTIGATION_STATUS.md)
