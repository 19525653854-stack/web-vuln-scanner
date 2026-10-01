# -*- coding: utf-8 -*-
# 设计说明：规划器。把侦察结论和系统现有能力交给模型，换回一份测试计划
# 为什么：计划由模型出而不是代码写死顺序，这正是"智能体驱动"和"死脚本扫描"的分界线
# 放弃了：不做计划的多轮自评。计划好不好用，交给后面的反思器在一次真实执行之后再评判
#
# 2026-10-01 规划器接入模型。此前管线里是写死的"端口扫描 -> 指纹识别"，
# 那只是把固定流程跑通，谈不上规划；现在顺序由模型根据侦察结果决定
import json
import logging

from agent.prompt_templates import PLANNER_SYSTEM_PROMPT, PLANNER_USER_TEMPLATE
from llm.model_adapter import llm_invoke_json
from llm.model_config import llm_build_runtime_config
from skills.skill_manager import skill_fetch_metadata_list
from tools.tool_registry import tool_fetch_descriptions

logger = logging.getLogger("ai_scanner.planner")

# 计划步骤上限。再多的话一轮跑不完，而且步骤越长模型编得越离谱
MAX_PLAN_STEPS = 5


def plan_build_fallback(recon_result):
    # 设计说明：内置兜底计划，不依赖模型
    # 为什么：模型没配、超时、返回格式不对，都得让任务能收尾——侦察结论照样是有价值的产出，
    #         不能因为一句话没问出来就把整轮作废
    # 放弃了：兜底计划不安排深度测试。没有模型的判断，硬凑出来的步骤只会误导后面几轮
    target_host = recon_result.get("host") or "未知目标"
    return {
        "plan_goal": "整理 %s 的暴露面侦察结论" % target_host,
        "plan_steps": [
            {
                "step_no": 1,
                "skill_name": "web_recon",
                "tool_name": "port_scan",
                "step_reason": "模型不可用，本轮退回到固定的侦察流程",
            }
        ],
        "stop_condition": "侦察结论落库即结束",
        "plan_source": "fallback",
    }


def plan_check_plan(raw_plan):
    # 设计说明：把模型返回的计划整理成固定结构，整份不可用就返回 None
    # 为什么：模型偶尔会漏字段、把某个步骤写成纯字符串、或者干脆回了{"error": ...}。
    #         统一在这里收口，后面的反思器和报告就不用到处判空
    # 放弃了：不做逐字段报错。缺的补默认值，整份不可用才回退，别因为一个字段让整轮白跑
    if not isinstance(raw_plan, dict) or raw_plan.get("error"):
        return None

    raw_steps = raw_plan.get("plan_steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        return None

    cleaned_steps = []
    for step_index, raw_step in enumerate(raw_steps[:MAX_PLAN_STEPS], start=1):
        if not isinstance(raw_step, dict):
            continue
        cleaned_steps.append({
            # 步号以我们的顺序为准，不信模型自己编的编号——它经常从 0 开始或者跳号
            "step_no": step_index,
            "skill_name": str(raw_step.get("skill_name") or ""),
            "tool_name": str(raw_step.get("tool_name") or ""),
            "step_reason": str(raw_step.get("step_reason") or ""),
        })

    if not cleaned_steps:
        return None

    return {
        "plan_goal": str(raw_plan.get("plan_goal") or "模型没给出整体目标"),
        "plan_steps": cleaned_steps,
        "stop_condition": str(raw_plan.get("stop_condition") or "模型没给出结束条件"),
    }


def plan_build_recon_summary(recon_result):
    # 设计说明：把侦察结果压成一段话，喂给规划器
    # 为什么：直接把整份快照塞进提示词，指纹块里那些细节会把重点淹掉，还白烧 token
    # 放弃了：不在这里做摘要模型调用。这段是机械整理，不需要再请一次模型
    open_port_items = recon_result.get("open_ports") or []
    fingerprint_block = recon_result.get("fingerprint") or {}

    summary_parts = [
        "开放端口 %s 个" % len(open_port_items),
        "技术栈 %s" % ("、".join(fingerprint_block.get("technologies") or []) or "未识别"),
        "缺失安全响应头 %s 项" % len(fingerprint_block.get("missing_security_headers") or []),
    ]
    if fingerprint_block.get("waf_or_cdn"):
        summary_parts.append("疑似前置防护：%s" % "、".join(fingerprint_block["waf_or_cdn"]))
    if fingerprint_block.get("page_title"):
        summary_parts.append("页面标题：%s" % fingerprint_block["page_title"])

    return "；".join(summary_parts)


def plan_build_strategy(recon_result):
    # 设计说明：规划器主入口，返回一份可执行的测试计划
    # 为什么：提示词里把"可用工具"和"可用技能"一起给出去，模型才不会安排出系统里根本没有的动作
    # 放弃了：不让模型自由发挥工具名。它编名字的倾向很明确，给清单是成本最低的约束手段
    runtime_config = llm_build_runtime_config()
    if runtime_config is None:
        logger.warning("没有可用的模型配置，规划器回退到内置计划")
        return plan_build_fallback(recon_result)

    fingerprint_block = recon_result.get("fingerprint") or {}
    open_port_items = recon_result.get("open_ports") or []

    planner_prompt = PLANNER_USER_TEMPLATE.safe_substitute(
        target_url=recon_result.get("target_url") or recon_result.get("host") or "未知",
        target_host=recon_result.get("host") or "未知",
        open_port_list=json.dumps([item["port"] for item in open_port_items], ensure_ascii=False),
        technologies="、".join(fingerprint_block.get("technologies") or []) or "未识别",
        security_header_gap="、".join(fingerprint_block.get("missing_security_headers") or []) or "无",
        recon_summary=plan_build_recon_summary(recon_result),
        tool_list=json.dumps(tool_fetch_descriptions(), ensure_ascii=False, indent=2),
        skill_list=json.dumps(skill_fetch_metadata_list(), ensure_ascii=False, indent=2),
    )

    raw_plan = llm_invoke_json(runtime_config, planner_prompt, PLANNER_SYSTEM_PROMPT)

    checked_plan = plan_check_plan(raw_plan)
    if checked_plan is None:
        logger.warning("模型返回的计划不可用，回退到内置计划。原始返回：%s", str(raw_plan)[:150])
        fallback_plan = plan_build_fallback(recon_result)
        fallback_plan["plan_issue"] = "模型返回的计划不可用"
        return fallback_plan

    checked_plan["plan_source"] = "model"
    logger.info(
        "规划器产出计划，%s 步，来源 %s",
        len(checked_plan["plan_steps"]),
        checked_plan["plan_source"],
    )
    return checked_plan
