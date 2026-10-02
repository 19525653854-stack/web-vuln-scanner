# -*- coding: utf-8 -*-
# 设计说明：HTTP 探测工具，负责取目标响应，并按配额限速
# 为什么：限速卡在这一层。全系统所有出站 HTTP 请求都从这儿过，限速才不会漏
# 放弃了：不用 aiohttp 做异步并发。V1.0 并发上限就 3 路，同步加限速更好控节奏
#
# 2026-10-01 限速从技能里挪到这里。原先写在各技能自己身上，结果每个技能限各的，
# 三个技能一起跑照样把目标打满，等于没限
import re
import threading
import time
from urllib.parse import parse_qsl, urlparse

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


def probe_collect_candidate_params(raw_url, raw_body_snippet=""):
    # 设计说明：从 URL 查询串和页面表单里收集候选参数名
    # 为什么：注入类测试得先知道有哪些参数可以下手。让使用者手填参数列表不现实，
    #         而 URL 的 query 和 <input name=...> 是最常见的两个入口
    # 放弃了：不解析 JS 里动态拼出来的参数。那得跑一遍页面，V1.0 不做浏览器
    #
    # 2026-10-02 提取出来放在这里，SQL 注入和 XSS 两个技能都要用，各写一遍迟早走岔
    candidate_params = []

    parsed_url = urlparse(raw_url)
    for param_name, _ in parse_qsl(parsed_url.query, keep_blank_values=True):
        if param_name and param_name not in candidate_params:
            candidate_params.append(param_name)

    for input_match in re.finditer(r"""<input[^>]*name\s*=\s*["']([^"']+)["']""", raw_body_snippet or "", re.I):
        input_name = input_match.group(1)
        if input_name and input_name not in candidate_params:
            candidate_params.append(input_name)

    return candidate_params


def probe_build_injected_url(raw_url, param_name, raw_payload):
    # 设计说明：把某个参数的值换成 payload，拼出一条注入用的 URL
    # 为什么：注入点的值必须被替换掉而不是追加，不然目标收到的还是原来那个正常值，测不出东西
    # 放弃了：不做 POST 表单提交。V1.0 只测 GET 参数，POST 的验证要连带处理表单，留后面做
    parsed_url = urlparse(raw_url)
    param_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
    injected_pairs = [
        (name, raw_payload if name == param_name else value)
        for name, value in param_pairs
    ]

    if not any(name == param_name for name, _ in param_pairs):
        # 参数在表单里不在 query 里，直接补一个上去
        injected_pairs.append((param_name, raw_payload))

    injected_query = "&".join("%s=%s" % (name, value) for name, value in injected_pairs)
    return "%s://%s%s?%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path, injected_query)


def probe_fetch_raw_text(raw_url):
    # 设计说明：取目标的完整响应正文，给注入类检测用
    # 为什么：http_probe 的返回里正文被截到 4000 字，而注入的数据库报错很可能落在截断之后，
    #         检测这一步必须看到全文，否则会把能报错的点判成没有注入
    # 放弃了：不设长度上限。真遇到巨型页面就慢一点，漏判的代价比慢一点大得多
    probe_wait_rate_slot()
    try:
        response = requests.get(
            raw_url,
            headers=DEFAULT_HEADERS,
            timeout=PAYLOAD_EXEC_TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
        return response.text
    except requests.RequestException:
        # 请求失败就回空串，让调用方按"没拿到响应"处理，不要在检测函数里到处判空
        return ""


# 注册进工具表。任务管线按 "http_probe" 这个名字调
tool_register(
    "http_probe",
    "HTTP 探测：请求目标地址，返回状态码、响应头、正文片段和跳转目标",
    probe_fetch_http_response,
)
