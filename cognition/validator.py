# -*- coding: utf-8 -*-
# 设计说明：验证器。判断一轮结果是否构成真实发现，并给出下一步动作
# 为什么：这是整个循环里唯一必须动用模型判断力的地方——端口开着不等于漏洞，响应里冒出一句
#         error 也不等于注入成功。"这些证据够不够"靠正则写不出来
# 放弃了：不用固定规则兜底判定。规则判定的误报率高得没法看，宁可回一个保守的"本轮无发现"
#
# 设计背景：验证器输出的四字段结构（is_vuln / confidence / reason / next_action）来自
#           AutoSec-Agent 的 PSV 循环，本系统照搬了这个输出契约
import json
import logging

from agent.prompt_templates import VALIDATOR_SYSTEM_PROMPT, VALIDATOR_USER_TEMPLATE
from llm.model_adapter import llm_invoke_json
from llm.model_config import llm_build_runtime_config

logger = logging.getLogger("ai_scanner.validator")

VALID_ACTIONS = ("continue", "stop")


def validate_parse_flag(raw_value):
    # 设计说明：把模型给的布尔值解析成真布尔
    # 为什么：模型经常把 is_vuln 写成字符串 "true"，或者写成中文"是"。直接 if 它会一直为真
    # 放弃了：不做多语言穷举。认得这几个常见写法就够了，其余按 False 处理
    if isinstance(raw_value, bool):
        return raw_value
    return str(raw_value).strip().lower().strip(".") in ("true", "1", "yes", "是")


def validate_parse_confidence(raw_value):
    # 设计说明：把置信度规整到 0 到 1
    # 为什么：模型时不时写成百分数 85，或者写超一点变成 1.5。不规整的话报告里会出现"置信度 8500%"
    # 放弃了：不报错。超出范围的直接折算或夹到边界，比让整轮失败划算
    #
    # 2026-10-01 阈值定在 1.5。最早写的是"大于 1 就当百分数"，结果 1.5 被算成了 0.015——
    # 明明是想表达"非常确定"，一折算反而成了最不确定
    try:
        number_value = float(raw_value)
    except (TypeError, ValueError):
        return 0.0
    if number_value > 100:
        # 百分数还写超，那就是胡给的，按满分算
        number_value = 1.0
    elif number_value > 1.5:
        number_value = number_value / 100.0
    return max(0.0, min(1.0, number_value))


def validate_build_default_verdict(reason_text):
    # 设计说明：拿不到模型判定时的保守结论
    # 为什么：模型没配、超时、返回格式不对，都得让循环能继续。默认"本轮无发现、继续"，不中断任务
    # 放弃了：不重试。一轮判定失败就重试会把任务拖得很长，下一轮换个动作往往更有效
    return {
        "is_vuln": False,
        "confidence": 0.0,
        "reason": reason_text,
        "next_action": "continue",
        "verdict_source": "fallback",
    }


def validate_check_verdict(raw_verdict):
    # 设计说明：把模型返回的判定整成固定结构，整份不可用就返回 None
    # 为什么：模型有时漏字段、有时把 next_action 写成中文、有时回了 {"error": ...}。
    #         在这里统一收口，循环里就不用到处做类型兜底
    # 放弃了：不做逐字段报错。缺的按保守值补，整份不可用才回退
    if not isinstance(raw_verdict, dict) or raw_verdict.get("error"):
        return None

    next_action = str(raw_verdict.get("next_action") or "continue").strip().lower()
    if next_action not in VALID_ACTIONS:
        # 认不出来的动作一律当 continue。当 stop 会把任务提前掐掉，代价比多跑一轮大
        next_action = "continue"

    return {
        "is_vuln": validate_parse_flag(raw_verdict.get("is_vuln")),
        "confidence": validate_parse_confidence(raw_verdict.get("confidence")),
        "reason": str(raw_verdict.get("reason") or "模型没有给出判断依据"),
        "next_action": next_action,
        "verdict_source": "model",
    }


def validate_round_result(round_summary, scan_context, step_node):
    # 设计说明：验证器主入口，输入本轮摘要，输出结构化判定
    # 为什么：把目标背景、本轮动作、结果摘要一起给模型，"这个动作在这个目标上意味着什么"
    #         才能被判断出来——脱离上下文的话，一个孤零零的状态码 200 说明不了任何事
    # 放弃了：不让模型自己决定要不要再测一次。重测的决策交给外层循环，验证器只回答"这轮算不算发现"
    runtime_config = llm_build_runtime_config()
    if runtime_config is None:
        return validate_build_default_verdict("没有可用的模型配置，本轮不做漏洞判定")

    fingerprint_block = scan_context.get("fingerprint") or {}
    validator_prompt = VALIDATOR_USER_TEMPLATE.safe_substitute(
        target_url=scan_context.get("target_url") or "未知",
        technologies="、".join(fingerprint_block.get("technologies") or []) or "未识别",
        waf_signals="、".join(fingerprint_block.get("waf_or_cdn") or []) or "无",
        skill_name=step_node.get("skill_name") or "未知",
        tool_name=step_node.get("tool_name") or "未知",
        step_reason=step_node.get("step_reason") or "计划里没写理由",
        round_summary=json.dumps(round_summary, ensure_ascii=False, indent=2),
    )

    raw_verdict = llm_invoke_json(runtime_config, validator_prompt, VALIDATOR_SYSTEM_PROMPT)
    checked_verdict = validate_check_verdict(raw_verdict)
    if checked_verdict is None:
        logger.warning("模型返回的判定不可解析，按本轮无发现处理。原始返回：%s", str(raw_verdict)[:150])
        return validate_build_default_verdict("模型返回的判定不可解析，本轮按无发现处理")

    return checked_verdict
