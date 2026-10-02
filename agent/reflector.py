# -*- coding: utf-8 -*-
# 设计说明：反思器。两个职责——跑到中途把偏掉的策略拉回来，跑完了把发现逐条研判一遍
# 为什么：验证器只看单轮结果，它回答不了"整场测试下来这些发现到底算不算数""这条该给什么等级"
#         "该怎么修"。这些要横着看全部证据才判得出来，所以得单独有个角色
# 放弃了：不做漏洞的主动利用验证（拿去真打一遍确认）。那已经越界到攻击行为，V1.0 只做研判
#
# 设计背景：方案 4.5 把反思分成三段——前 5 轮正常执行、5 到 10 轮反思并调整策略、10 轮以后
#           转高风险模式。这里按前两段落地：每 5 轮做一次策略反思并带进下一版计划，
#           收尾时做一次全局研判，逐条确认、定级、给修复建议
import json
import logging

from agent.prompt_templates import (
    PROGRESS_REFLECT_SYSTEM_PROMPT,
    PROGRESS_REFLECT_USER_TEMPLATE,
    REFLECTOR_SYSTEM_PROMPT,
    REFLECTOR_USER_TEMPLATE,
)
from llm.model_adapter import llm_invoke_json, llm_invoke_prompt
from llm.model_config import llm_build_runtime_config
from models.tables import AuditLog, Finding

logger = logging.getLogger("ai_scanner.reflector")

# 判定不通过的发现降成这个等级，而不是删掉
# 为什么：删了之后没人知道这里曾经报过一条，报告也没法说明"我们当时判过、复核掉了"
UNCONFIRMED_LEVEL = "low"

VALID_LEVELS = ("high", "medium", "low")

# 单条发现喂给反思器时证据留多长。留太长一次研判要烧掉不少 token，留太短复核没依据
FINDING_EVIDENCE_LIMIT = 400


def agent_build_finding_briefs(finding_rows):
    # 设计说明：把漏洞行压成给反思器看的简报
    # 为什么：整行塞进去会把提示词撑爆，而且大部分字段反思器用不上；
    #         它要判断的是"类型、等级、证据、当时凭什么判的"这四件事
    # 放弃了：不带 plan_snapshot 里的原始响应。太长了，四百字的证据片段够复核
    return [
        {
            "finding_id": finding_row.id,
            "vuln_type": finding_row.vuln_type,
            "vuln_level": finding_row.vuln_level,
            "hit_url": finding_row.vuln_url,
            "confidence": finding_row.confidence,
            "judged_reason": finding_row.validate_reason,
            "evidence": (finding_row.raw_evidence or "")[:FINDING_EVIDENCE_LIMIT],
        }
        for finding_row in finding_rows
    ]


def agent_check_reflection(raw_reflection):
    # 设计说明：把反思器返回的研判结果整成固定结构，整份不可用就返回 None
    # 为什么：模型经常把 confirmed 写成字符串、把 level 写成中文、自己编 finding_id。
    #         这里统一收口，落库那段就不用做类型兜底
    # 放弃了：不做逐字段报错。单条对不上就跳过那一条，不因为一条脏数据丢掉整份研判
    if not isinstance(raw_reflection, dict) or raw_reflection.get("error"):
        return None

    raw_reviews = raw_reflection.get("finding_reviews")
    if not isinstance(raw_reviews, list):
        return None

    cleaned_reviews = []
    for raw_review in raw_reviews:
        if not isinstance(raw_review, dict):
            continue
        try:
            finding_id = int(raw_review.get("finding_id"))
        except (TypeError, ValueError):
            # 编号编不出来说明这条对不上任何一条发现，直接丢
            continue

        review_level = str(raw_review.get("level") or "").strip().lower()
        if review_level not in VALID_LEVELS:
            review_level = ""

        cleaned_reviews.append({
            "finding_id": finding_id,
            "confirmed": str(raw_review.get("confirmed")).strip().lower() in ("true", "1", "yes", "是"),
            "level": review_level,
            "reason": str(raw_review.get("reason") or "反思器没给出修改理由"),
            "fix_suggestion": str(raw_review.get("fix_suggestion") or "反思器没给出修复建议"),
        })

    return {
        "conclusion": str(raw_reflection.get("conclusion") or "反思器没给出整场结论"),
        "finding_reviews": cleaned_reviews,
    }


def agent_build_reflection_fallback(reason_text):
    # 设计说明：反思器用不了时的兜底结论
    # 为什么：模型没配或超时不该让整场测试白跑——发现已经落库了，只是缺了复核这一层
    # 放弃了：不做规则化的自动定级。等级本来就是靠判断给的，硬套规则只会给出看着像样的错数
    return {
        "conclusion": reason_text,
        "finding_reviews": [],
        "reflection_source": "fallback",
    }


def agent_apply_reflection(session, finding_rows, checked_reflection):
    # 设计说明：把研判结论落到每一条发现上
    # 为什么：等级要按复核结果改、修复建议要补上；但这张表没有"复核状态"这一列，
    #         所以用"降级 + 在判定理由里注明复核结论"来表达未被确认，结构化结论另存进计划快照
    # 放弃了：不加新列。加列要改表结构，而库里存着模型配置，重建库代价太大
    review_map = {
        review_item["finding_id"]: review_item
        for review_item in checked_reflection["finding_reviews"]
    }
    confirmed_count = 0
    unconfirmed_count = 0

    for finding_row in finding_rows:
        review_item = review_map.get(finding_row.id)
        if review_item is None:
            # 反思器漏掉的那几条保持原样，不擅自改判
            continue

        if review_item["confirmed"]:
            confirmed_count += 1
            if review_item["level"]:
                finding_row.vuln_level = review_item["level"]
            review_note = "反思器复核通过：%s" % review_item["reason"]
        else:
            unconfirmed_count += 1
            # 降级不删除：删了以后没人知道这里曾经报过一条
            finding_row.vuln_level = UNCONFIRMED_LEVEL
            review_note = "反思器复核未通过：%s" % review_item["reason"]

        finding_row.validate_reason = ("%s（%s）" % (finding_row.validate_reason, review_note))[:600]
        finding_row.fix_suggestion = review_item["fix_suggestion"]

    session.commit()
    return confirmed_count, unconfirmed_count


def agent_run_reflection(job_row, session, recon_result):
    # 设计说明：收尾研判主入口，返回研判结论摘要
    # 为什么：整场测试结束后必须有一个统一口径的结论，报告和漏洞列表页都靠它
    # 放弃了：不让反思器决定"还要不要继续测"。收尾就是收尾，要继续测是循环里的事
    finding_rows = (
        session.query(Finding)
        .filter(Finding.job_id == job_row.id)
        .order_by(Finding.id)
        .all()
    )

    if not finding_rows:
        # 一条发现都没有就没什么可研判的，省下这次模型调用
        empty_reflection = {
            "conclusion": "本次测试没有产出任何发现，无需逐条复核",
            "reviewed_count": 0,
            "confirmed_count": 0,
            "unconfirmed_count": 0,
            "reflection_source": "skipped",
        }
        recon_result["reflection"] = empty_reflection
        session.add(AuditLog(
            job_id=job_row.id,
            log_type="reflection",
            log_content="反思器收尾：没有发现可研判",
            log_reason="漏洞表里没有属于本任务的记录",
        ))
        session.commit()
        return empty_reflection

    runtime_config = llm_build_runtime_config()
    if runtime_config is None:
        fallback_reflection = agent_build_reflection_fallback("没有可用的模型配置，本轮没做复核")
        recon_result["reflection"] = fallback_reflection
        return fallback_reflection

    fingerprint_block = recon_result.get("fingerprint") or {}
    reflection_prompt = REFLECTOR_USER_TEMPLATE.safe_substitute(
        target_url=recon_result.get("target_url") or "未知",
        open_port_list=json.dumps(
            [item.get("port") for item in (recon_result.get("open_ports") or [])], ensure_ascii=False),
        technologies="、".join(fingerprint_block.get("technologies") or []) or "未识别",
        finding_briefs=json.dumps(agent_build_finding_briefs(finding_rows), ensure_ascii=False, indent=2),
    )

    raw_reflection = llm_invoke_json(runtime_config, reflection_prompt, REFLECTOR_SYSTEM_PROMPT)
    checked_reflection = agent_check_reflection(raw_reflection)
    if checked_reflection is None:
        logger.warning("反思器的返回不可解析，这次复核作废。原始返回：%s", str(raw_reflection)[:150])
        fallback_reflection = agent_build_reflection_fallback("反思器返回的研判结果不可解析")
        recon_result["reflection"] = fallback_reflection
        return fallback_reflection

    confirmed_count, unconfirmed_count = agent_apply_reflection(session, finding_rows, checked_reflection)

    checked_reflection.update({
        "reviewed_count": len(finding_rows),
        "confirmed_count": confirmed_count,
        "unconfirmed_count": unconfirmed_count,
        "reflection_source": "model",
    })
    recon_result["reflection"] = checked_reflection

    session.add(AuditLog(
        job_id=job_row.id,
        log_type="reflection",
        log_content="反思器收尾研判：%s" % checked_reflection["conclusion"],
        log_reason="复核 %s 条，确认 %s 条，未通过 %s 条" % (
            len(finding_rows), confirmed_count, unconfirmed_count),
    ))
    session.commit()

    logger.info(
        "反思器收尾完成：复核 %s 条，确认 %s 条，未通过 %s 条",
        len(finding_rows), confirmed_count, unconfirmed_count,
    )
    return checked_reflection


def agent_run_progress_reflection(round_summaries, task_tree_summary, scan_context):
    # 设计说明：中期策略反思，返回一段策略提示，会被带进下一版计划
    # 为什么：一场测试跑到一半最容易闷头往前冲。隔几轮停下来横着看一眼，
    #         能把"一直在重复无效动作"这类问题提前发现，而不是等跑完才发现白跑
    # 放弃了：不让反思器直接改计划。它只给提示，改计划仍然是主控的活，职责边界要清楚
    runtime_config = llm_build_runtime_config()
    if runtime_config is None:
        return ""

    # 只带最近五轮的结论。再往前的轮次对"接下来该干嘛"没有参考价值，还白占提示词
    round_briefs = [
        "第 %s 轮 [%s]：%s" % (
            round_item["round_index"],
            round_item["tool_name"],
            str(round_item["verdict"].get("reason"))[:80],
        )
        for round_item in (round_summaries or [])[-5:]
    ]
    fingerprint_block = (scan_context or {}).get("fingerprint") or {}

    progress_prompt = PROGRESS_REFLECT_USER_TEMPLATE.safe_substitute(
        target_url=(scan_context or {}).get("target_url") or "未知",
        technologies="、".join(fingerprint_block.get("technologies") or []) or "未识别",
        open_port_list="",
        task_tree_summary=task_tree_summary or "（还没有计划）",
        round_briefs="\n".join(round_briefs) or "（还没有产生轮次结论）",
    )

    try:
        strategy_note = llm_invoke_prompt(runtime_config, progress_prompt, PROGRESS_REFLECT_SYSTEM_PROMPT)
    except Exception as reflect_error:
        # 中期反思失败不该拖垮任务，记一笔就继续
        logger.warning("中期反思调用失败，本轮跳过：%s", reflect_error)
        return ""

    return (strategy_note or "").strip()[:300]
