#!/usr/bin/env python3
"""
h5st 生成器 Python 客户端

依赖:
  - Node.js (v16+)
  - js_security_v3_0.1.4.js (已下载)
  - sha256.js (已下载)

用法:
  from h5st_client import generate_h5st
  
  params = {
      'appid': 'search-pc-java',
      'functionId': 'pc_search_searchWare',
      't': '1783410832775',
      'body': '{"enc":"utf-8","pvid":"...","page":2}',
      'client': 'pc',
      'clientVersion': '1.0.0',
      'uuid': '1783317821529844451249',
      'loginType': '3',
      'keyword': '%E6%B1%BD%E6%B2%B9%E9%99%A4%E6%B0%B4%E5%89%82',
  }
  result = generate_h5st('search-pc-java', params)
  print(result['h5st'])
"""

import json
import subprocess
import os
from typing import Optional

_NODE_SCRIPT = os.path.join(os.path.dirname(__file__), 'h5st_generator.js')

def generate_h5st(app_id: str, params: dict, token: str = '') -> dict:
    """
    生成 h5st 参数
    
    Args:
        app_id: 应用ID (如 'search-pc-java')
        params: 请求参数 (包含 appid, functionId, t, body 等)
        token: 可选的 token (从 jsTk.do 获取)
    
    Returns:
        dict: 包含 h5st 字段的完整参数
    """
    cmd = ['node', _NODE_SCRIPT, app_id, json.dumps(params, ensure_ascii=False)]
    if token:
        cmd.append(token)
    
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=os.path.dirname(_NODE_SCRIPT)
    )
    
    if proc.returncode != 0:
        raise RuntimeError(f'h5st generation failed: {proc.stderr}')
    
    result = json.loads(proc.stdout)
    
    if 'error' in result:
        raise RuntimeError(f'h5st generation error: {result["error"]}')
    
    return result


def generate_h5st_for_search(keyword: str, page: int = 1, **extra) -> dict:
    """生成京东搜索 API 的 h5st"""
    import time
    
    params = {
        'appid': 'search-pc-java',
        'functionId': 'pc_search_searchWare',
        't': str(int(time.time() * 1000)),
        'body': json.dumps({
            'enc': 'utf-8',
            'pvid': 'test-pvid-' + str(int(time.time())),
            'from': 'home',
            'area': '19_1601_50258_129167',
            'page': page,
            'mode': '',
            'concise': False,
            'hoverPictures': True,
            'newAdvRepeat': False,
            'mixerParam': False,
            'new_interval': True,
            's': 27,
        }, ensure_ascii=False),
        'client': 'pc',
        'clientVersion': '1.0.0',
        'uuid': 'test-uuid-' + str(int(time.time())),
        'loginType': '3',
        'keyword': keyword,
    }
    params.update(extra)
    return generate_h5st('search-pc-java', params)


if __name__ == '__main__':
    # 测试
    import time
    params = {
        'appid': 'search-pc-java',
        'functionId': 'pc_search_searchWare',
        't': str(int(time.time() * 1000)),
        'body': '{"enc":"utf-8","pvid":"test","from":"home","page":1}',
        'client': 'pc',
        'clientVersion': '1.0.0',
        'uuid': 'test-uuid',
        'loginType': '3',
        'keyword': 'test',
    }
    result = generate_h5st('search-pc-java', params)
    print('=== h5st 生成成功 ===')
    print(f"h5st: {result.get('h5st', 'N/A')}")
    print(f"_stk: {result.get('_stk', 'N/A')}")
    
    # 分解 h5st
    h5st = result.get('h5st', '')
    if h5st:
        parts = h5st.split(';')
        labels = ['时间戳', '设备指纹', '短码', 'Token', 'Hash1', '版本', '时间戳ms', '加密载荷', 'Hash2', '签名']
        print('\nh5st 分段:')
        for i, (label, part) in enumerate(zip(labels, parts)):
            print(f"  {i+1}. {label}: {part[:50]}{'...' if len(part) > 50 else ''}")
