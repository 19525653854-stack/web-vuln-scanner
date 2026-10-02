# -*- coding: utf-8 -*-
# 设计说明：总结器。把工具原始返回压成关键信息，避免上下文溢出
# 为什么：http_probe 一轮能带回几 KB 正文，循环十几轮下来上下文直接爆。压成十几个字段之后，
#         既留住了判断依据，又把 token 消耗压到可控范围
# 放弃了：不请模型来做摘要。压缩是纯机械动作，让模型来做白烧 token 还要多等好几秒；
#         真正需要判断力的那一步在验证器，不在这一层
import logging

logger = logging.getLogger("ai_scanner.summarizer")

# 数据库和远程管理端口直接对着外网，本身就是一条发现，不必等后续测试
SENSITIVE_PORT_SET = {21, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017}

# 摘要里正文最多留这么多字。留多了等于没压缩，留太少又看不出注入特征
BODY_SNIPPET_LIMIT = 300

# 命中列表最多留几条。命中太多说明参数全都不设防，报告里列前三条够说明问题了
MAX_SUMMARY_HITS = 3


def summarize_check_sensitive_ports(open_port_items):
    # 设计说明：从端口列表里挑出敏感端口
    # 为什么：3306、3389 这类端口暴露在外是实打实的风险，扫出来就该记一笔
    # 放弃了：不在这里定风险等级。等级统一由验证器判，避免两处标准打架
    return [
        item for item in (open_port_items or [])
        if item.get("port") in SENSITIVE_PORT_SET
    ]


def summarize_port_scan_result(raw_result):
    # 设计说明：压缩端口扫描结果
    # 为什么：原始结果是 21 个端口的完整清单，摘要里只需要"开了几个、哪几个、有没有敏感端口"
    # 放弃了：不保留每个端口的服务名。服务名在报告里再回查原始数据，这里省下的 token 更值钱
    open_port_items = raw_result or []
    return {
        "open_port_count": len(open_port_items),
        "open_port_list": [item.get("port") for item in open_port_items],
        "sensitive_port_list": summarize_check_sensitive_ports(open_port_items),
    }


def summarize_http_probe_result(raw_result):
    # 设计说明：压缩 HTTP 探测结果
    # 为什么：正文只留前若干字符。注入类特征的判断只需要看局部，整页正文对结论没有增量
    # 放弃了：不做正文的 HTML 清洗。清洗要引入解析依赖，而这里只是留给验证器瞄一眼
    if not raw_result or not raw_result.get("ok"):
        return {"reachable": False, "reason": (raw_result or {}).get("reason", "没有拿到响应")}

    response_headers = {
        str(header_name).lower(): str(header_value)
        for header_name, header_value in (raw_result.get("headers") or {}).items()
    }
    return {
        "reachable": True,
        "status_code": raw_result.get("status_code"),
        "server": response_headers.get("server", ""),
        "powered_by": response_headers.get("x-powered-by", ""),
        "content_type": response_headers.get("content-type", ""),
        "redirect_to": raw_result.get("location") or "",
        "body_length": len(raw_result.get("body_snippet") or ""),
        "body_snippet": (raw_result.get("body_snippet") or "")[:BODY_SNIPPET_LIMIT],
    }


def summarize_fingerprint_result(raw_result):
    # 设计说明：压缩指纹识别结果
    # 为什么：指纹结果本身就已经是摘要形态，这里只做字段裁剪，去掉报告才用的细节
    fingerprint_block = raw_result or {}
    return {
        "reachable": fingerprint_block.get("reachable"),
        "status_code": fingerprint_block.get("status_code"),
        "technologies": fingerprint_block.get("technologies") or [],
        "page_title": fingerprint_block.get("page_title") or "",
        "missing_security_headers": fingerprint_block.get("missing_security_headers") or [],
        "waf_or_cdn": fingerprint_block.get("waf_or_cdn") or [],
    }


def summarize_injection_result(raw_result):
    # 设计说明：压缩注入类检测结果。SQL 注入、XSS、目录遍历三个工具的返回形状是一样的
    # 为什么：这三个工具都只回"测了几个参数、命中哪些"，共用一个压缩规则，加第四个同类工具时
    #         直接复用就行，不用再写一遍
    # 放弃了：不抹掉证据片段。验证器判断"算不算漏洞"全靠这些片段，压掉就等于让它瞎猜
    hit_list = (raw_result or {}).get("hit_list") or []
    return {
        "tested_parameter_count": (raw_result or {}).get("tested_parameter_count", 0),
        "hit_count": len(hit_list),
        "hit_list": hit_list[:MAX_SUMMARY_HITS],
    }


def summarize_leak_result(raw_result):
    # 设计说明：压缩敏感信息泄露的检测结果
    # 为什么：它的返回分三块（路径、调试信息、版本号），得分开压，混成一段验证器分不清是哪类泄露
    # 放弃了：不合并三类结论。三条渠道的严重程度不一样，合并会让验证器的置信度判断失准
    leak_block = raw_result or {}
    return {
        "checked_path_count": leak_block.get("checked_path_count", 0),
        "sensitive_path_count": len(leak_block.get("sensitive_path_hits") or []),
        "sensitive_path_hits": (leak_block.get("sensitive_path_hits") or [])[:MAX_SUMMARY_HITS],
        "debug_output": leak_block.get("debug_output"),
        "version_disclosure": leak_block.get("version_disclosure") or [],
    }


def summarize_round_result(tool_name, raw_result):
    # 设计说明：按工具名分发到各自的压缩规则
    # 为什么：每种工具返回的形状差得远，规则写在一起但按工具分开，加新工具照着补一个分支就行
    # 放弃了：不做通用压缩。通用规则压不出有用信息，反而会把关键字段压没
    if tool_name == "port_scan":
        return summarize_port_scan_result(raw_result)
    if tool_name == "http_probe":
        return summarize_http_probe_result(raw_result)
    if tool_name == "fingerprint":
        return summarize_fingerprint_result(raw_result)
    if tool_name in ("sqli_probe", "xss_probe", "traversal_probe"):
        return summarize_injection_result(raw_result)
    if tool_name == "leak_probe":
        return summarize_leak_result(raw_result)

    # 没有专门规则的工具就截断兜底，至少别让整轮因为少写一条压缩规则而中断
    logger.info("工具 %s 没有专门的压缩规则，按截断处理", tool_name)
    return {"raw_summary": str(raw_result)[:BODY_SNIPPET_LIMIT]}
