# -*- coding: utf-8 -*-
# 设计说明：指纹识别技能脚本，从 HTTP 响应里推断目标用了什么技术栈
# 为什么：指纹决定后面测什么。WordPress 站点优先看插件问题、Java 站点优先看反序列化，
#         两眼一抹黑地全量测一遍既慢又容易被封
# 放弃了：不做主动探测（拼特定文件路径、发畸形请求）。侦察阶段就动手容易触发告警，
#         V1.0 只用被动特征，也就是"目标自己吐出来的东西"
import re

from tools.tool_registry import tool_register

# 特征写成数据表而不是 if-else 堆砌。以后加新指纹往表里加一行就行，不用动逻辑
HEADER_SIGNATURES = {
    "server": {
        "nginx": "nginx",
        "apache": "apache",
        "microsoft-iis": "iis",
        "tomcat": "tomcat",
        "jetty": "jetty",
        "openresty": "openresty",
    },
    "x-powered-by": {
        "php": "php",
        "asp.net": "asp.net",
        "express": "nodejs-express",
        "servlet": "java-servlet",
    },
}

COOKIE_SIGNATURES = {
    "phpsessid": "php",
    "jsessionid": "java",
    "asp.net_sessionid": "asp.net",
    "laravel_session": "laravel",
    "ci_session": "codeigniter",
    "thinkphp": "thinkphp",
}

BODY_SIGNATURES = (
    (re.compile(r"wp-content|wp-includes", re.I), "wordpress"),
    (re.compile(r"thinkphp", re.I), "thinkphp"),
    (re.compile(r"__next_data__", re.I), "nextjs"),
    (re.compile(r"laravel", re.I), "laravel"),
)

# 这几条响应头是基础的浏览器侧防护，缺了算配置问题，报告里会列出来
SECURITY_HEADERS = (
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
)

# CDN / WAF 的响应头特征。有 WAF 在前面挡着，后面的扫描策略要更保守
WAF_SIGNATURES = {
    "cf-ray": "cloudflare",
    "x-waf": "waf",
    "server-timing": "可能有 CDN",
    "x-cache": "可能有 CDN",
}


def probe_check_headers(response_headers):
    # 设计说明：从响应头推断服务端和开发语言
    # 为什么：Server 和 X-Powered-By 是目标主动报的家门，最省事也最准
    # 放弃了：不做版本号精确匹配。版本号常被改掉或抹掉，盯着它容易误判成没识别出来
    header_lower = {str(name).lower(): str(value) for name, value in (response_headers or {}).items()}
    matched_tech = set()

    for header_name, signature_map in HEADER_SIGNATURES.items():
        header_value = header_lower.get(header_name, "").lower()
        for keyword, tech_name in signature_map.items():
            if keyword in header_value:
                matched_tech.add(tech_name)

    return sorted(matched_tech)


def probe_check_cookies(response_headers):
    # 设计说明：从 Cookie 名推断后端技术
    # 为什么：语言可能被藏在响应头里看不到，但会话 Cookie 名改起来麻烦，基本会露馅
    # 放弃了：不看 Cookie 的值。值里可能是加密串或 base64，解它有越界嫌疑
    cookie_text = str((response_headers or {}).get("Set-Cookie", "")).lower()
    if not cookie_text:
        return []

    matched_tech = []
    for cookie_name, tech_name in COOKIE_SIGNATURES.items():
        if cookie_name in cookie_text:
            matched_tech.append(tech_name)
    return sorted(set(matched_tech))


def probe_check_body(body_snippet):
    # 设计说明：从正文片段里找框架和 CMS 的特征
    # 为什么：模板路径、注入的全局变量名这些藏不住，比响应头更实
    # 放弃了：不看 CSS / JS 文件名列表。误报率太高，静态资源重命名很常见
    body_text = body_snippet or ""
    matched_tech = []
    for body_pattern, tech_name in BODY_SIGNATURES:
        if body_pattern.search(body_text):
            matched_tech.append(tech_name)
    return sorted(set(matched_tech))


def probe_check_security_headers(response_headers):
    # 设计说明：列出目标缺失的基础安全响应头
    # 为什么：这几条缺失本身就算一处配置缺陷，报告里要能体现，不用等后续漏洞测试
    # 放弃了：只列出缺失项，不判定风险等级。等级交给反思器统一评，这里不越权
    header_lower = {str(name).lower() for name in (response_headers or {})}
    return [
        header_name for header_name in SECURITY_HEADERS
        if header_name.lower() not in header_lower
    ]


def probe_check_waf(response_headers):
    # 设计说明：判断目标前面有没有 CDN 或 WAF
    # 为什么：有 WAF 挡着的话，后面的 payload 测试要放慢、要更保守，否则整轮都被拦
    # 放弃了：不做 WAF 主动识别（发攻击特征看拦不拦）。那已经属于攻击行为了
    header_lower = {str(name).lower(): str(value) for name, value in (response_headers or {}).items()}
    matched_items = []
    for header_name, waf_name in WAF_SIGNATURES.items():
        if header_name in header_lower:
            matched_items.append(waf_name)
    return sorted(set(matched_items))


def probe_check_fingerprint(http_result):
    # 设计说明：指纹识别总入口，输入 HTTP 探测结果，输出技术栈画像
    # 为什么：三类特征（头、Cookie、正文）各测各的再汇总，任何一类缺失都不影响其他两类出结果
    # 放弃了：不给置信度打分。"像是 WordPress"和"确定是 WordPress"界限模糊，打分反而误导
    if not http_result or not http_result.get("ok"):
        # 探测都没成功，后面每一类特征都没得看，直接回一个空画像
        return {
            "reachable": False,
            "reason": (http_result or {}).get("reason", "没有拿到响应"),
            "technologies": [],
            "missing_security_headers": [],
        }

    response_headers = http_result.get("headers") or {}
    technologies = set()
    technologies.update(probe_check_headers(response_headers))
    technologies.update(probe_check_cookies(response_headers))
    technologies.update(probe_check_body(http_result.get("body_snippet")))

    title_match = re.search(r"<title[^>]*>(.*?)</title>", http_result.get("body_snippet") or "",
                            re.I | re.S)
    page_title = title_match.group(1).strip()[:80] if title_match else ""

    return {
        "reachable": True,
        "status_code": http_result.get("status_code"),
        "page_title": page_title,
        "technologies": sorted(technologies),
        "waf_or_cdn": probe_check_waf(response_headers),
        "missing_security_headers": probe_check_security_headers(response_headers),
        "redirect_to": http_result.get("location"),
    }


# 注册成工具。任务管线按 "fingerprint" 这个名字调，不直接 import 本模块
tool_register(
    "fingerprint",
    "指纹识别：从响应头、Cookie、正文推断服务端/语言/框架/CMS，并列出缺失的安全响应头与 CDN/WAF 迹象",
    probe_check_fingerprint,
)
