# -*- coding: utf-8 -*-
# 设计说明：敏感信息泄露检测脚本
# 为什么：这一类不需要注入，目标自己把不该露的东西摆出来了——版本号、报错栈、备份文件。
#         它在真实渗透里往往是最先出成果的一步，也最容易被忽略
# 放弃了：不做目录爆破。那要跑字典，请求量是另一个量级；V1.0 只用一份固定的高危路径清单
#
# 2026-10-02 判定改成"路径可访问 + 内容特征命中"双条件。第一版只看状态码 200，
# 结果目标站有个统一个 200 的兜底页，把所有不存在的路径都当成了泄露
import re
from urllib.parse import urlsplit

from tools.http_tool import probe_fetch_http_response, probe_wait_rate_slot
from tools.tool_registry import tool_register

# 高危路径清单。只挑高频且危害明确的几条，不做大字典
SENSITIVE_PATHS = (
    ("/.git/config", "[core]", "Git 仓库配置文件，可顺着还原出整个源码"),
    ("/.env", "app_key", "环境变量文件，通常含数据库口令和密钥"),
    ("/.svn/entries", "svn", "SVN 元数据目录，同样能还原源码"),
    ("/phpinfo.php", "phpinfo", "phpinfo 探针页，暴露环境与配置细节"),
    ("/config.php.bak", "<?php", "配置文件的编辑器备份，能直接读到连接串"),
    ("/db.sql", "insert into", "数据库导出文件，可直接下载"),
    ("/backup.zip", "PK", "站点备份压缩包，可直接下载"),
)

# 正文里出现这些说明目标把调试信息吐出来了
DEBUG_INFO_SIGNATURES = (
    ("traceback (most recent call last)", "Python 异常栈"),
    ("stack trace:", "Java 异常栈"),
    ("notice: undefined", "PHP 提示级报错"),
    ("warning: include(", "PHP 文件包含告警"),
    ("at java.", "Java 调用栈帧"),
    ("debug = true", "调试开关没关"),
)

# 版本号特征：Server 或 X-Powered-By 里带数字版本，等于告诉对方自己跑的是什么版本
VERSION_PATTERN = re.compile(r"\d+\.\d+")

EVIDENCE_SNIPPET_LIMIT = 200


def probe_build_site_root(raw_url):
    # 设计说明：从目标地址里取出站点根，用来拼敏感路径
    # 为什么：目标地址可能带很长一串路径和参数，直接往后面接 "/.env" 会拼到子路径上去
    parsed_url = urlsplit(raw_url)
    return "%s://%s" % (parsed_url.scheme, parsed_url.netloc)


def probe_check_sensitive_paths(raw_url):
    # 设计说明：逐个探敏感路径，返回可访问且内容特征命中的那些
    # 为什么：双条件判定。只看状态码会把"统一返回 200 的兜底页"全算成泄露，
    #         只看内容特征又会漏掉返回 200 但内容是空的情况
    # 放弃了：不区分 200 和 206。这两种都能拿到内容，没必要分
    site_root = probe_build_site_root(raw_url)
    hit_list = []

    for path_value, content_signature, path_description in SENSITIVE_PATHS:
        probe_wait_rate_slot()
        probe_result = probe_fetch_http_response(site_root + path_value)
        if not probe_result.get("ok") or probe_result.get("status_code") != 200:
            continue

        body_text = probe_result.get("body_snippet") or ""
        # 压缩包是二进制，正文里捞不到 PK 头，改用 content-type 判断
        if path_value.endswith(".zip"):
            content_type = str((probe_result.get("headers") or {}).get("Content-Type", "")).lower()
            if "zip" not in content_type and "octet-stream" not in content_type:
                continue
        elif content_signature.lower() not in body_text.lower():
            continue

        signature_position = body_text.lower().find(content_signature.lower())
        snippet_start = max(0, signature_position - 40)
        hit_list.append({
            "path": path_value,
            "description": path_description,
            "evidence": body_text[snippet_start:snippet_start + EVIDENCE_SNIPPET_LIMIT].replace("\n", " ").strip(),
        })

    return hit_list


def probe_check_debug_output(raw_body_snippet):
    # 设计说明：在页面正文里找调试信息泄露
    # 为什么：异常栈和绝对路径这类东西，正常运营的站点不该出现在返回页面上
    # 放弃了：不解析栈的调用链。报告里给出片段就够，分析栈不是这个技能的事
    body_text = raw_body_snippet or ""
    for debug_signature, debug_description in DEBUG_INFO_SIGNATURES:
        if debug_signature in body_text.lower():
            signature_position = body_text.lower().find(debug_signature)
            snippet_start = max(0, signature_position - 40)
            return {
                "description": debug_description,
                "evidence": body_text[snippet_start:snippet_start + EVIDENCE_SNIPPET_LIMIT].replace("\n", " ").strip(),
            }
    return None


def probe_check_version_disclosure(raw_headers):
    # 设计说明：看响应头有没有把服务端版本号报出来
    # 为什么：版本号本身不算漏洞，但它是下一步找对应版本漏洞的入口，属于典型的信息泄露
    # 放弃了：不比对 CVE 库。本地没有可靠的漏洞库，硬编一份很快就过期了
    header_lower = {str(h_name).lower(): str(h_value) for h_name, h_value in (raw_headers or {}).items()}
    disclosed_items = []

    for header_name in ("server", "x-powered-by"):
        header_value = header_lower.get(header_name, "")
        if header_value and VERSION_PATTERN.search(header_value):
            disclosed_items.append({"header": header_name, "value": header_value})

    return disclosed_items


def probe_fetch_leak_result(raw_url, raw_headers=None, raw_body_snippet=""):
    # 设计说明：敏感信息泄露检测总入口，三个角度一起看
    # 为什么：敏感路径、报错信息、版本号是三条独立的泄露渠道，任一条中招都该记一笔
    # 放弃了：不合并指纹技能已经报过的"安全响应头缺失"。那两个角度不一样，合并会变成重复计数
    sensitive_hits = probe_check_sensitive_paths(raw_url)

    return {
        "sensitive_path_hits": sensitive_hits,
        "debug_output": probe_check_debug_output(raw_body_snippet),
        "version_disclosure": probe_check_version_disclosure(raw_headers),
        "checked_path_count": len(SENSITIVE_PATHS),
    }


# 注册进工具表。import 这个模块就等于把敏感信息泄露检测挂进系统
tool_register(
    "leak_probe",
    "敏感信息泄露检测：探测高危路径、页面调试信息与响应头版本号泄露，返回命中的具体证据",
    probe_fetch_leak_result,
)
