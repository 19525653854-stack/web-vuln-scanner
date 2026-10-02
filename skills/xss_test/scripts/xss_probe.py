# -*- coding: utf-8 -*-
# 设计说明：反射型 XSS 检测脚本
# 为什么：XSS 的判定要看"参数回显时有没有被转义"。只看参数原样出现在响应里是不够的——
#         大部分模板引擎本来就会原样输出，要看的是尖括号有没有被吃掉
# 放弃了：不做存储型 XSS。存储型要先提交再等另一个页面读出来，验证链路长、清理麻烦，
#         而且很容易在别人系统里留下脏数据
#
# 2026-10-02 判定从"参数值出现在响应里"改成"注入的标签原样出现在响应里"。
# 前者在正常站点上随处可见，靶场演示时会被当成误报打脸
from tools.http_tool import (
    probe_build_injected_url,
    probe_fetch_raw_text,
    probe_wait_rate_slot,
)
from tools.tool_registry import tool_register

# 注入用的标记标签。用一段不可能跟页面里原有内容撞车的前缀命名标签，
# 免得目标页面本来就带 <b> 之类的东西被算成命中
XSS_MARKER_PREFIX = "xssmark"
# 响应里抓证据时前后各留一段上下文
EVIDENCE_CONTEXT_LEN = 80


def probe_build_xss_payload(marker_id):
    # 设计说明：拼一个自闭合的标记标签当 payload
    # 为什么：用 <xssmark1> 这种自定义标签，而不是 <script>alert(1)</script>。前者只验证
    #         "尖括号有没有被转义"，不会真的在目标浏览器里弹窗；脚本注入的行为留给报告说明
    # 放弃了：不注入完整可执行脚本。对授权的靶场也没必要真的执行，验证转义就够了
    return "<%s%s>" % (XSS_MARKER_PREFIX, marker_id)


def probe_check_parameter_reflection(raw_url, param_name, param_index):
    # 设计说明：对一个参数注入标记标签，看它有没有被原样吐回来
    # 为什么：判定用"标签原文整体出现"而不是"参数值出现"。转义之后响应里会出现
    #         `&lt;xssmark1&gt;`，那样整体匹配是匹配不上的，正好区分开
    # 放弃了：不做浏览器渲染验证。要真跑一遍 DOM 得引入无头浏览器，V1.0 扛不动那个依赖
    marker_payload = probe_build_xss_payload(param_index)

    probe_wait_rate_slot()
    injected_url = probe_build_injected_url(raw_url, param_name, marker_payload)
    injected_text = probe_fetch_raw_text(injected_url)

    marker_position = injected_text.find(marker_payload)
    if marker_position < 0:
        return None

    snippet_start = max(0, marker_position - EVIDENCE_CONTEXT_LEN)
    return {
        "parameter": param_name,
        "payload": marker_payload,
        "evidence": injected_text[snippet_start:marker_position + EVIDENCE_CONTEXT_LEN].replace("\n", " ").strip(),
        # 只有标签原文出现才算没转义；被打成实体了就到不了这里
        "reflected_raw": True,
    }


def probe_fetch_xss_result(raw_url, raw_body_snippet=""):
    # 设计说明：对目标的所有候选参数逐个做反射型 XSS 检测，返回结构化结果
    # 为什么：参数回显是 XSS 的前提，先把所有参数过一遍，再把命中的挑出来给验证器判断
    # 放弃了：不区分输出上下文（HTML 正文 / 属性 / 脚本块）。上下文不同危害不同，但判断
    #         上下文要解析 DOM，V1.0 只在报告里注明"未区分输出位置"
    from tools.http_tool import probe_collect_candidate_params as collect_candidates

    candidate_params = collect_candidates(raw_url, raw_body_snippet)
    hit_list = []

    for param_index, param_name in enumerate(candidate_params, start=1):
        hit_item = probe_check_parameter_reflection(raw_url, param_name, param_index)
        if hit_item is not None:
            hit_list.append(hit_item)

    return {
        "tested_parameter_count": len(candidate_params),
        "candidate_parameters": candidate_params,
        "hit_list": hit_list,
    }


# 注册进工具表。import 这个模块就等于把反射型 XSS 检测挂进系统
tool_register(
    "xss_probe",
    "反射型XSS检测：向目标参数注入标记标签，看尖括号有没有被转义，返回命中的参数与响应证据",
    probe_fetch_xss_result,
)
