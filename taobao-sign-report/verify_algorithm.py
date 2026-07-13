"""本地、无网络的 MTOP 签名公式 smoke test。"""

import hashlib


def mtop_sign(token: str, timestamp_ms: str, app_key: str, data: str) -> str:
    payload = "&".join((token, timestamp_ms, app_key, data))
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    # 合成输入：不包含真实 Cookie、会话 token 或请求数据。
    result = mtop_sign(
        "0123456789abcdef0123456789abcdef",
        "1700000000000",
        "12574478",
        '{"appId":"demo","params":"{}"}',
    )
    assert result == "a2e1bb96827872b2a348b472a67385e9"
    print("MTOP sign formula: PASS")
