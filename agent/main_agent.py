# -*- coding: utf-8 -*-
# 设计说明：主控智能体。负责出计划、吸收顾问意见、判断要不要交换角色
# 为什么：把"谁主导"这件事单独抽出来，编排器只管循环和闸门，协作规则变化时不用改循环
# 放弃了：不做多轮辩论。顾问给一轮意见就合并，来回辩会把每轮规划的成本翻好几倍
#
# 设计背景：双智能体协作的规则来自方案 4.2——主控主导、顾问辅助，连续失败到阈值就互换角色，
#           互换次数封顶，避免两个智能体来回踢皮球
import logging
import json

from agent.advisor_agent import MAX_ADVISOR_EXTRA_STEPS
from agent.prompt_templates import PLANNER_SYSTEM_PROMPT, PLANNER_USER_TEMPLATE
from config import AGENT_FAIL_SWAP_THRESHOLD, AGENT_MAX_SWAP_TIMES
from cognition.planner import (
    plan_build_recon_summary,
    plan_check_plan,
    plan_build_executed_action_list,
)
from llm.model_adapter import llm_invoke_json
from llm.model_config import llm_build_runtime_config, llm_fetch_active_config
from skills.skill_manager import skill_fetch_metadata_list
from tools.tool_registry import tool_fetch_descriptions

logger = logging.getLogger("ai_scanner.main_agent")

# 计划步骤上限，跟规划器那边保持一致
MAX_PLAN_STEPS = 5
# 合并后的步数上限：主控的名额 + 顾问能补的名额。
# 2026-10-02 一开始合并后也用 5 步上限，结果主控永远把 5 个名额占满，顾问补的建议一步都进不来，
# "顾问补的步骤要真的进计划"这句话就成了空话。改成给顾问单独留两个名额
MAX_MERGED_PLAN_STEPS = MAX_PLAN_STEPS + MAX_ADVISOR_EXTRA_STEPS


def agent_fetch_collaboration_mode():
    # 设计说明：从当前生效的模型配置里读协作模式
    # 为什么：单模型/双模型是用户在配置页随时可切的开关，代码里写死会让用户以为切了没生效
    # 放弃了：不在这里校验顾问配置是否完整。缺 Key 时适配器自己会退回主控那套，不用重复兜底
    active_config = llm_fetch_active_config(mask_key=True)
    return (active_config or {}).get("collaboration_mode") or "single"


def agent_check_swap_condition(consecutive_failures, swap_times):
    # 设计说明：判断要不要让主控和顾问互换角色
    # 为什么：连着失败说明当前这个主导视角已经被卡住了，换个视角往往能绕出去；
    #         但也不能无限换，来回换会变成两个智能体互相点头，浪费轮次
    # 放弃了：不做失败原因的自动归因。V1.0 只看失败次数，具体为什么卡住交给反思环节
    if consecutive_failures < AGENT_FAIL_SWAP_THRESHOLD:
        return False
    if swap_times >= AGENT_MAX_SWAP_TIMES:
        return False
    return True


def agent_build_main_plan(plan_context, role_swapped=False):
    # 设计说明：主控出计划
    # 为什么：角色互换之后，主导方改用顾问的模型配置和视角——同一份上下文换个模型来想，
    #         这正是"互换"要起的作用
    # 放弃了：不让主控看到顾问上一轮的意见。意见已经并进计划里了，重复给只会干扰它
    if role_swapped:
        runtime_config = llm_build_runtime_config("advisor")
    else:
        runtime_config = llm_build_runtime_config("main")

    if runtime_config is None:
        logger.warning("没有可用的模型配置，主控出不了计划")
        return None

    main_prompt = PLANNER_USER_TEMPLATE.safe_substitute(
        target_url=plan_context.get("target_url") or plan_context.get("host") or "未知",
        target_host=plan_context.get("host") or "未知",
        open_port_list=json.dumps(
            [item["port"] for item in (plan_context.get("open_ports") or [])], ensure_ascii=False),
        technologies="、".join((plan_context.get("technologies_list") or [])) or "未识别",
        security_header_gap="、".join((plan_context.get("security_header_gap_list") or [])) or "无",
        recon_summary=plan_build_recon_summary(plan_context),
        executed_action_list=plan_build_executed_action_list(plan_context.get("executed_actions")),
        task_tree_summary=plan_context.get("task_tree_summary") or "（这是第一版计划，还没有执行记录）",
        tool_list=json.dumps(tool_fetch_descriptions(), ensure_ascii=False, indent=2),
        skill_list=json.dumps(skill_fetch_metadata_list(), ensure_ascii=False, indent=2),
    )

    raw_plan = llm_invoke_json(runtime_config, main_prompt, PLANNER_SYSTEM_PROMPT)
    checked_plan = plan_check_plan(raw_plan)
    if checked_plan is None:
        logger.warning("主控给的计划不可解析，原始返回：%s", str(raw_plan)[:150])
        return None

    checked_plan["plan_source"] = "model"
    checked_plan["plan_author"] = "advisor" if role_swapped else "main"
    return checked_plan


def agent_merge_advisor_advice(main_plan, advisor_review):
    # 设计说明：把顾问补的步骤并进主控的计划，返回合并后的计划
    # 为什么：顾问的价值在于"想到主控没想到的角度"，它的补充要真的进计划才有意义；
    #         只把意见记进日志等于白问一场
    # 放弃了：不做步骤优先级重排。顾问的补充一律追加在后面，先后顺序仍由主控把握
    merged_steps = list(main_plan.get("plan_steps") or [])
    existing_keys = {
        (plan_step.get("skill_name"), plan_step.get("tool_name")) for plan_step in merged_steps
    }
    added_count = 0

    for extra_step in (advisor_review or {}).get("advisor_extra_steps") or []:
        if len(merged_steps) >= MAX_MERGED_PLAN_STEPS:
            break
        extra_key = (extra_step.get("skill_name"), extra_step.get("tool_name"))
        if extra_key in existing_keys:
            # 顾问补了主控已经排过的动作，直接丢掉，别让同一个动作在计划里出现两次
            continue

        merged_steps.append({
            "step_no": len(merged_steps) + 1,
            "skill_name": extra_step.get("skill_name") or "",
            "tool_name": extra_step.get("tool_name") or "",
            "step_reason": extra_step.get("step_reason") or "顾问补充",
            "step_from": "advisor",
        })
        existing_keys.add(extra_key)
        added_count += 1

    for plan_step in merged_steps:
        plan_step.setdefault("step_from", "main")

    # 步号在合并后重排一遍，顾问补进来的步骤编号一定是乱的
    for step_index, plan_step in enumerate(merged_steps, start=1):
        plan_step["step_no"] = step_index

    merged_plan = dict(main_plan)
    merged_plan["plan_steps"] = merged_steps
    merged_plan["advisor_added_count"] = added_count
    merged_plan["advisor_issue_count"] = len((advisor_review or {}).get("advisor_issues") or [])
    merged_plan["advisor_summary"] = (advisor_review or {}).get("advisor_summary") or ""
    return merged_plan
