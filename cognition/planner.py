# -*- coding: utf-8 -*-
# 设计说明：规划器。计划的结构校验、兜底计划和上下文压缩都放这里
# 为什么：计划是不是模型出的、模型给的格式对不对、拿不到计划时靠什么顶上，这些是规划这件事
#         的地基；具体"谁来出计划"是协作层的事，不混在一起
# 放弃了：不做计划的执行调度。出计划的不负责推进计划，推进在 agent/orchestrator.py
#
# 2026-10-01 规划器接入模型。此前管线里是写死的"端口扫描 -> 指纹识别"，
# 那只是把固定流程跑通，谈不上规划；顺序改为由模型根据侦察结果决定
# 2026-10-02 出计划的入口挪去了 agent/main_agent.py。双智能体协作进来之后，
# 计划要经过主控出稿、顾问审查、合并三步，那三步属于协作层，不该塞进规划器
import logging

logger = logging.getLogger("ai_scanner.planner")

# 计划步骤上限。再多的话一轮跑不完，而且步骤越长模型编得越离谱
MAX_PLAN_STEPS = 5


def plan_build_fallback(recon_result):
    # 设计说明：内置兜底计划，不依赖模型
    # 为什么：模型没配、超时、返回格式不对，都得让任务能收尾——侦察结论照样是有价值的产出，
    #         不能因为一句话没问出来就把整轮作废
    # 放弃了：兜底计划不安排深度测试。没有模型的判断，硬凑出来的步骤只会误导后面几轮
    target_host = recon_result.get("host") or "未知目标"
    executed_actions = {
        tuple(action_item) for action_item in (recon_result.get("executed_actions") or [])
    }
    logger.warning("模型不可用或没给出可用计划，回退到内置兜底计划，目标 %s", target_host)

    # 只排一个还没做过的侦察动作；全都做过了就交白卷，让循环正常收尾，别硬凑步骤
    fallback_candidates = (
        ("web_recon", "http_probe", "模型不可用，补一次 HTTP 探测再收尾"),
        ("web_recon", "fingerprint", "模型不可用，补一次指纹识别再收尾"),
        ("web_recon", "port_scan", "模型不可用，补一次端口扫描再收尾"),
    )
    plan_steps = [
        {
            "step_no": 1,
            "skill_name": candidate_skill,
            "tool_name": candidate_tool,
            "step_reason": candidate_reason,
        }
        for candidate_skill, candidate_tool, candidate_reason in fallback_candidates
        if (candidate_skill, candidate_tool) not in executed_actions
    ][:1]

    return {
        "plan_goal": "整理 %s 的暴露面侦察结论" % target_host,
        "plan_steps": plan_steps,
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


def plan_build_executed_action_list(executed_actions):
    # 设计说明：把已执行过的动作排成一列，塞进提示词
    # 为什么：模型对"不要重复安排"这种口头约束几乎不理会。把做过的组合逐条列出来，它才有东西可对照，
    #         实测列出来之后重复步骤明显减少
    # 放弃了：不带上每个动作的结果。结果已经在"上一轮侦察结论"那一段里，重复给只会把提示词撑长
    if not executed_actions:
        return "（还没有执行过任何动作）"
    return "\n".join("- %s / %s" % (action_item[0], action_item[1]) for action_item in executed_actions)
