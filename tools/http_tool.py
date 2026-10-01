# -*- coding: utf-8 -*-
# 设计说明：HTTP 探测工具，负责取目标响应，并按配额限速
# 为什么：限速卡在这一层。全系统所有出站 HTTP 请求都从这儿过，限速才不会漏
# 放弃了：不用 aiohttp 做异步并发。V1.0 并发上限就 3 路，同步加限速更好控节奏
#
# 2026-10-01 限速从技能里挪到这里。原先写在各技能自己身上，结果每个技能限各的，
# 三个技能一起跑照样把目标打满，等于没限
import threading
import time

import requests
import urllib3

from config import PAYLOAD_EXEC_TIMEOUT, SCAN_RATE_LIMIT_PER_SECOND
from tools.tool_registry import tool_register

# 自签名证书在测试环境太常见，一律不校验证书。这条警告每请求刷一次，会淹没日志
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 限速状态。时间戳用单元素列表存，免得为了改一个数字到处写 global
_rate_lock = threading.Lock()
_last_request_at = [0.0]

# 伪装成普通浏览器。python-requests 的默认 UA 太显眼，不少站点直接按 UA 拦
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


def probe_wait_rate_slot():
    # 设计说明：按配置的每秒请求数阻塞等待，直到可以发下一个请求
    # 为什么：多线程一起打，小站会被打挂，还容易被 WAF 直接封 IP
    # 放弃了：不做令牌桶。单机串行任务用"最小间隔"就够了，桶换不来更好的效果
    min_interval = 1.0 / max(SCAN_RATE_LIMIT_PER_SECOND, 1)
    with _rate_lock:
        idle_time = time.time() - _last_request_at[0]
        if idle_time < min_interval:
            time.sleep(min_interval - idle_time)
        _last_request_at[0] = time.time()


def probe_fetch_http_response(raw_url):
    # 设计说明：取目标首页的响应，返回状态码、响应头、正文片段
    # 为什么：正文只留前若干字符。整页动辄几百 KB，直接塞进上下文能把 token 吃光
    # 放弃了：不主动跟随跳转。第一跳的 Location 本身就是指纹，跟过去反而看不到了
    probe_wait_rate_slot()

    try:
        response = requests.get(
            raw_url,
            headers=DEFAULT_HEADERS,
            timeout=PAYLOAD_EXEC_TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
    except requests.RequestException as fetch_error:
        # 目标返回异常编码、连接被重置都会落进这里。早先没接住，整个任务直接崩了
        return {"ok": False, "reason": str(fetch_error)[:120]}

    return {
        "ok": True,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body_snippet": response.text[:4000],
        "location": response.headers.get("Location"),
    }


# 注册进工具表。任务管线按 "http_probe" 这个名字调
tool_register(
    "http_probe",
    "HTTP 探测：请求目标地址，返回状态码、响应头、正文片段和跳转目标",
    probe_fetch_http_response,
)
