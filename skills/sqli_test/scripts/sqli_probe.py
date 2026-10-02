# -*- coding: utf-8 -*-
# 设计说明：SQL 注入检测脚本，做显错注入
# 为什么：显错注入是唯一能"看一眼响应就确定"的注入类型，误报率最低。盲注要靠响应时间或布尔
#         差异去推断，靶场上还行，真实站点上网络抖动一大就全是误报
# 放弃了：不做盲注、时间盲注、堆叠注入。V1.0 只回答"这个参数有没有被打出数据库报错"
#
# 2026-10-02 判定判据从"状态码有没有变"改成"有没有出现数据库报错特征词"。
# 状态码一变就报漏洞的写法，被 WAF 拦一下、被重定向一下都会误报，靶场演示时很难看
from tools.http_tool import (
    probe_build_injected_url,
    probe_collect_candidate_params,
    probe_fetch_raw_text,
    probe_wait_rate_slot,
)
from tools.tool_registry import tool_register

# 各数据库的报错特征。只认这几家的典型句式，宁可漏报，也不要把普通报错当成注入
SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate[",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider for sql server",
    "syntax error at or near",
    "sqlite error",
    "pg_query",
    "postgresql query failed",
)

# 显错注入的 payload。思路都是"闭合掉引号让语句断掉"，不构造子查询，动静最小
ERROR_PAYLOADS = ("'", '"', "')", "';", "' AND '1'='2")

# 证据片段截多长。太短看不出是哪个报错，太长会把上下文撑爆
EVIDENCE_SNIPPET_LIMIT = 200


def probe_match_sql_error(raw_text):
    # 设计说明：在响应正文里找数据库报错特征词
    # 为什么：注入成功的证据就是"数据库把自己的报错吐出来了"，这是最硬的判据，不需要再推断
    # 放弃了：不做模糊匹配和同义词扩展。特征表里已经是各家报错的原话，加模糊匹配只会引入误报
    lowered_text = (raw_text or "").lower()
    for error_signature in SQL_ERROR_SIGNATURES:
        if error_signature in lowered_text:
            return error_signature
    return ""


def probe_extract_error_evidence(raw_text, error_signature):
    # 设计说明：把报错那句话连同前后文抓出来，作为报告里的证据
    # 为什么：报告要能复现，只写"命中 SQL 报错"没人信；得把报错原文摆出来
    # 放弃了：不做 HTML 标签清理。这段是给人看的证据，保留原始形态反而更可信
    error_position = (raw_text or "").lower().find(error_signature)
    if error_position < 0:
        return ""

    snippet_start = max(0, error_position - 60)
    return raw_text[snippet_start:snippet_start + EVIDENCE_SNIPPET_LIMIT].replace("\n", " ").strip()


def probe_check_parameter_injection(raw_url, param_name, baseline_text):
    # 设计说明：对一个参数挨个试显错 payload，命中就返回证据
    # 为什么：同一个参数可能有 payload 被过滤、另一个没被过滤的情况，所以要多试几个；
    #         但只要有一个命中，这个参数就已经确认了，剩下的不用再打
    # 放弃了：不做 payload 变形绕过。绕 WAF 是另一个课题，混进检测逻辑会把代码搅浑
    for payload in ERROR_PAYLOADS:
        probe_wait_rate_slot()
        injected_url = probe_build_injected_url(raw_url, param_name, payload)
        injected_text = probe_fetch_raw_text(injected_url)

        error_signature = probe_match_sql_error(injected_text)
        # 基线响应里本来就有这个报错词，说明是目标自己一直带着的，不算注入打出来的
        if error_signature and error_signature not in (baseline_text or "").lower():
            return {
                "parameter": param_name,
                "payload": payload,
                "error_signature": error_signature,
                "evidence": probe_extract_error_evidence(injected_text, error_signature),
            }
    return None


def probe_fetch_sqli_result(raw_url, raw_body_snippet=""):
    # 设计说明：对目标的所有候选参数逐个做显错注入检测，返回结构化结果
    # 为什么：先取一次基线响应再比对——只有"基线里没有、注入后出现"的报错才算这个参数带来的，
    #         这一步是压掉误报的关键
    # 放弃了：不自动扩大 payload 集合。试到能报错就够，继续加只会提高被 WAF 盯上的概率
    candidate_params = probe_collect_candidate_params(raw_url, raw_body_snippet)
    baseline_text = probe_fetch_raw_text(raw_url)

    hit_list = []
    for param_name in candidate_params:
        hit_item = probe_check_parameter_injection(raw_url, param_name, baseline_text)
        if hit_item is not None:
            hit_list.append(hit_item)

    return {
        "tested_parameter_count": len(candidate_params),
        "candidate_parameters": candidate_params,
        "hit_list": hit_list,
    }


# 注册进工具表。import 这个模块就等于把 SQL 注入检测挂进系统
tool_register(
    "sqli_probe",
    "SQL注入检测：从目标 URL 参数和表单里找出注入点，用显错注入判定，返回命中的参数、payload 与报错证据",
    probe_fetch_sqli_result,
)
