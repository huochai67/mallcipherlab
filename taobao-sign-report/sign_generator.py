"""
Taobao MTOP H5 Sign Generator
==============================
根据逆向分析结果实现的签名生成工具。

用法:
    python sign_generator.py --token <TOKEN> --data <JSON_STRING>
    python sign_generator.py --token <TOKEN> --data-file <data.json>
"""

import hashlib
import json
import time
import urllib.parse
import argparse
import re


def mtop_sign(token: str, data: str, app_key: str = "12574478"):
    """
    生成 MTOP H5 签名

    Args:
        token: 从 _m_h5_tk cookie 提取的 token (split('_')[0])
        data:  JSON.stringify(请求数据对象) 的结果
        app_key: appKey, 默认 "12574478"

    Returns:
        (sign, t): 32位小写十六进制签名, 13位毫秒时间戳
    """
    t = str(int(time.time() * 1000))
    sign_str = token + "&" + t + "&" + app_key + "&" + data
    sign = hashlib.md5(sign_str.encode("utf-8")).hexdigest()
    return sign, t


def extract_token_from_cookie(cookie_str: str) -> str:
    """从 Cookie 字符串中提取 _m_h5_tk 的 token 部分"""
    match = re.search(r'_m_h5_tk=([^;]+)', cookie_str)
    if not match:
        raise ValueError("Cookie 中未找到 _m_h5_tk")
    return match.group(1).split("_")[0]


def build_request_url(
    api: str,
    version: str,
    data_obj: dict,
    token: str,
    app_key: str = "12574478",
) -> str:
    """
    构建完整的 MTOP H5 请求 URL

    Args:
        api: API 名称, e.g. "mtop.relationrecommend.wirelessrecommend.recommend"
        version: API 版本, e.g. "2.0"
        data_obj: 请求数据对象 (dict, 将被 JSON 序列化)
        token: 签名 token
        app_key: appKey

    Returns:
        完整的请求 URL (包含所有 query 参数)
    """
    data_str = json.dumps(data_obj, separators=(",", ":"))
    sign, t = mtop_sign(token, data_str, app_key)

    params = {
        "jsv": "2.7.4",
        "appKey": app_key,
        "t": t,
        "sign": sign,
        "api": api,
        "v": version,
        "timeout": "10000",
        "type": "jsonp",
        "dataType": "jsonp",
        "callback": "mtopjsonp6",
        "data": data_str,
        "ua": "",
    }

    qs = "&".join(
        f'{k}={urllib.parse.quote(str(v), safe="")}'
        for k, v in params.items()
    )
    return (
        f"https://h5api.m.taobao.com/h5/{api.lower()}/{version.lower()}/?{qs}"
    )


def parse_jsonp_response(text: str) -> dict:
    """解析 MTOP JSONP 响应为 dict"""
    json_str = re.sub(r"^mtopjsonp\d+\(", "", text).rstrip(")")
    return json.loads(json_str)


def main():
    parser = argparse.ArgumentParser(description="MTOP H5 Sign Generator")
    parser.add_argument("--token", help="签名 token (从 _m_h5_tk cookie 提取)")
    parser.add_argument("--cookie", help="完整 Cookie 字符串 (自动提取 token)")
    parser.add_argument("--data", help="JSON 字符串 (将被序列化)")
    parser.add_argument("--data-file", help="JSON 文件路径")
    parser.add_argument("--api", default="mtop.relationrecommend.wirelessrecommend.recommend")
    parser.add_argument("--version", default="2.0")
    parser.add_argument("--app-key", default="12574478")
    args = parser.parse_args()

    # 获取 token
    if args.token:
        token = args.token
    elif args.cookie:
        token = extract_token_from_cookie(args.cookie)
    else:
        parser.error("请提供 --token 或 --cookie")

    # 获取 data
    if args.data:
        data_obj = json.loads(args.data)
    elif args.data_file:
        with open(args.data_file, encoding="utf-8") as f:
            data_obj = json.load(f)
    else:
        # 默认: 使用样本中的空请求
        data_obj = {"appId": "34385", "params": "{}"}

    url = build_request_url(args.api, args.version, data_obj, token, args.app_key)
    print(url)


if __name__ == "__main__":
    main()
