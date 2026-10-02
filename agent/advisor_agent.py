# -*- coding: utf-8 -*-
# 设计说明：顾问智能体。审查主控给出的测试计划，从另一个角度挑毛病、补盲区
# 为什么：同一个模型从头想到尾，很容易顺着自己的思路一路走到底。有个专门"唱反调"的角色，
#         才能把漏掉的攻击面翻出来——这是双智能体协作的意义
# 放弃了：不让顾问直接调工具。顾问只出意见，动手的永远是主控，权限边界必须清楚，
#         否则两个角色都能执行动作，出问题时分不清是谁下的手
import json
import logging

from agent.prompt_templates import ADVISOR_SYSTEM_PROMPT, ADVISOR_USER_TEMPLATE
from llm.model_adapter import llm_invoke_json
from llm.model_config import llm_build_runtime_config
from skills.skill_manager import skill_fetch_metadata_list
from tools.tool_registry import tool_fetch_descriptions

logger = logging.getLogger("ai_scanner.advisor")

# 顾问最多补这么多步。补太多会把计划撑爆，也说明主控那份计划本身没写好
MAX_ADVISOR_EXTRA_STEPS = 2


def agent_check_advisor_review(raw_review):
    # 设计说明：把顾问返回的意见整成固定结构，整份不可用就返回 None
    # 为什么：顾问的输出是自由文本数组，模型经常多写字段或者把步骤写成纯字符串。这里收口，
    #         合并逻辑就不用做类型兜底
    # 放弃了：不做逐字段报错。缺的按空处理，整份不可用就当顾问没说话
    if not isinstance(raw_review, dict) or raw_review.get("error"):
        return None

    raw_extra_steps = raw_review.get("advisor_extra_steps")
    cleaned_extra_steps = []
    if isinstance(raw_extra_steps, list):
        for raw_extra_step in raw_extra_steps:
            # 上限要在循环里按"已收下的条数"判，不能先切前 N 条再过滤——
            # 2026-10-02 一开始写的是 raw_extra_steps[:2]，结果夹在中间的一条乱数据
            # 白占一个名额，排在它后面的正常建议全被丢了
            if len(cleaned_extra_steps) >= MAX_ADVISOR_EXTRA_STEPS:
                break
            if not isinstance(raw_extra_step, dict):
                continue
            skill_name = str(raw_extra_step.get("skill_name") or "")
            tool_name = str(raw_extra_step.get("tool_name") or "")
            if not skill_name and not tool_name:
                continue
            cleaned_extra_steps.append({
                "skill_name": skill_name,
                "tool_name": tool_name,
                "step_reason": str(raw_extra_step.get("step_reason") or "顾问补充"),
            })

    raw_issues = raw_review.get("advisor_issues")
    cleaned_issues = []
    if isinstance(raw_issues, list):
        cleaned_issues = [str(issue_item) for issue_item in raw_issues if str(issue_item).strip()]

    return {
        "advisor_summary": str(raw_review.get("advisor_summary") or "顾问没有给出总体看法"),
        "advisor_issues": cleaned_issues,
        "advisor_extra_steps": cleaned_extra_steps,
    }


def agent_build_advisor_review(plan_result, recon_context, role_swapped=False):
    # 设计说明：顾问审查主控的计划，返回意见和补充步骤
    # 为什么：双模型模式下顾问走另一套模型配置——不同模型的训练数据和倾向不一样，
    #         盲区才不重合。单模型模式下顾问和主控是同一个模型，价值主要在多一道检查
    # 放弃了：不让顾问看到完整的历轮摘要。只给侦察结论和已执行动作，够它判断了
    if role_swapped:
        # 角色互换之后，顾问这一侧改用主控的模型配置
        runtime_config = llm_build_runtime_config("main")
    else:
        runtime_config = llm_build_runtime_config("advisor")

    if runtime_config is None:
        logger.warning("没有可用的模型配置，顾问审查跳过")
        return None

    advisor_prompt = ADVISOR_USER_TEMPLATE.safe_substitute(
        target_url=recon_context.get("target_url") or "未知",
        open_port_list=json.dumps(
            [item["port"] for item in (recon_context.get("open_ports") or [])], ensure_ascii=False),
        technologies="、".join((recon_context.get("technologies_list") or [])) or "未识别",
        security_header_gap="、".join((recon_context.get("security_header_gap_list") or [])) or "无",
        executed_action_list=json.dumps(
            recon_context.get("executed_actions") or [], ensure_ascii=False),
        main_plan_text=json.dumps(plan_result, ensure_ascii=False, indent=2),
        tool_list=json.dumps(tool_fetch_descriptions(), ensure_ascii=False, indent=2),
        skill_list=json.dumps(skill_fetch_metadata_list(), ensure_ascii=False, indent=2),
    )

    raw_review = llm_invoke_json(runtime_config, advisor_prompt, ADVISOR_SYSTEM_PROMPT)
    checked_review = agent_check_advisor_review(raw_review)
    if checked_review is None:
        logger.warning("顾问返回的意见不可解析，本轮按无意见处理。原始返回：%s", str(raw_review)[:150])
        return None

    logger.info(
        "顾问审查完成：%s 条意见，%s 条补充步骤",
        len(checked_review["advisor_issues"]),
        len(checked_review["advisor_extra_steps"]),
    )
    return checked_review
