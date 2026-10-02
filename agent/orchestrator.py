# -*- coding: utf-8 -*-
# 设计说明：编排器，PSV 推理循环的主体
# 为什么：固定顺序的管线只能跑预设流程；"规划 → 执行 → 总结 → 验证"循环起来，系统才能
#         根据实际拿到的东西决定下一步——这就是"智能体驱动"和"脚本扫描"的分界线
# 放弃了：不做独立的分支探索，V1.0 一条线走到底；也不做循环内的进度存档，任务中断就整单重开
#
# 设计背景：借鉴 AutoSec-Agent 提出的 PSV（规划-总结-验证）循环，按本系统规模做了简化——
#           执行一步、压缩一步、判定一步，验证结论决定是继续还是收尾。循环上限取 AGENT_MAX_ROUND
#           规划这一步是双智能体协作：主控出计划、顾问挑毛病、合并成最终计划；
#           连续失败到阈值就互换主次角色，互换次数封顶（方案 4.2）
import json
import logging

from agent.advisor_agent import agent_build_advisor_review
from agent.main_agent import (
    agent_build_main_plan,
    agent_check_swap_condition,
    agent_fetch_collaboration_mode,
    agent_merge_advisor_advice,
)
from agent.reflector import agent_run_progress_reflection
from cognition.planner import plan_build_fallback
from cognition.summarizer import summarize_round_result
from cognition.validator import validate_round_result
from config import AGENT_FAIL_SWAP_THRESHOLD, AGENT_MAX_ROUND
from models.tables import AuditLog, Finding
from tools.tool_registry import tool_fetch_descriptions, tool_invoke

logger = logging.getLogger("ai_scanner.agent")

# 工具名 -> 参数怎么凑。加新工具时在这里补一行，编排器本身不用改
#
# TODO(注缘): 这张表迟早要挪走。工具多起来之后，编排器不该知道每个工具要什么参数——
#             应该由工具在 tool_register 时自己声明参数构造规则，编排器只负责调用
TOOL_ARGUMENT_BUILDERS = {
    "port_scan": lambda scan_context: {"raw_host": scan_context["target_host"]},
    "http_probe": lambda scan_context: {"raw_url": scan_context["target_url"]},
    # 指纹识别依赖上一步的 HTTP 结果。拿不到就传空字典，让这一步正常地失败掉，
    # 而不是直接抛异常把整个任务带崩
    "fingerprint": lambda scan_context: {"http_result": scan_context.get("last_http_result") or {}},
    # 下面四个是专项检测技能自带的工具，参数都从目标地址和上一步的 HTTP 结果里取
    "sqli_probe": lambda scan_context: {
        "raw_url": scan_context["target_url"],
        "raw_body_snippet": (scan_context.get("last_http_result") or {}).get("body_snippet") or "",
    },
    "xss_probe": lambda scan_context: {
        "raw_url": scan_context["target_url"],
        "raw_body_snippet": (scan_context.get("last_http_result") or {}).get("body_snippet") or "",
    },
    "traversal_probe": lambda scan_context: {
        "raw_url": scan_context["target_url"],
        "raw_body_snippet": (scan_context.get("last_http_result") or {}).get("body_snippet") or "",
    },
    "leak_probe": lambda scan_context: {
        "raw_url": scan_context["target_url"],
        "raw_headers": (scan_context.get("last_http_result") or {}).get("headers") or {},
        "raw_body_snippet": (scan_context.get("last_http_result") or {}).get("body_snippet") or "",
    },
}

# 重新规划的次数上限。模型有反复给同一份计划的倾向，不封顶会把循环卡死
MAX_REPLAN_TIMES = 2
# 循环迭代次数的硬上限。跳过重复步骤不消耗轮次，得另有一道闸防止空转过久
MAX_LOOP_ITERATION = AGENT_MAX_ROUND * 3
# 每跑满这么多轮做一次中期反思，把策略提示带进下一版计划。
# 方案 4.5 把 5 到 10 轮划为"反思并调整策略"阶段，这个间隔就是照它定的
REFLECT_ROUND_INTERVAL = 5


def agent_build_task_tree(plan_result):
    # 设计说明：把规划器给的计划转成可推进的任务树
    # 为什么：计划只是一张静态清单，执行过程中要能标注"做过了/跳过了/失败了"，得有状态载体
    # 放弃了：不做真正带层级和依赖的树。V1.0 的计划是线性的，硬套一棵树只是自找麻烦
    return {
        "goal": plan_result.get("plan_goal"),
        "stop_condition": plan_result.get("stop_condition"),
        "plan_source": plan_result.get("plan_source"),
        "nodes": [
            {
                "step_no": plan_step["step_no"],
                "skill_name": plan_step["skill_name"],
                "tool_name": plan_step["tool_name"],
                "step_reason": plan_step["step_reason"],
                "node_status": "pending",
                "node_note": "",
            }
            for plan_step in (plan_result.get("plan_steps") or [])
        ],
    }


def agent_fetch_next_step(task_tree):
    # 设计说明：取下一个还没做的步骤
    # 为什么：顺序推进是 V1.0 的约定。计划里没写依赖关系，只能按给的顺序走
    for task_node in (task_tree or {}).get("nodes") or []:
        if task_node["node_status"] == "pending":
            return task_node
    return None


def agent_build_task_tree_summary(task_tree):
    # 设计说明：把任务树的执行情况压成几行，回喂给规划器
    # 为什么：重新规划时模型得知道上一版计划里哪些做完了、哪些失败了，否则它会原地重排一遍
    # 放弃了：不把每轮的完整摘要带进去。那样提示词会长得离谱，只带状态和备注就够
    if not task_tree:
        return "（这是第一版计划，还没有执行记录）"

    summary_lines = []
    for task_node in task_tree.get("nodes") or []:
        summary_lines.append(
            "步骤 %s [%s / %s] 状态 %s %s" % (
                task_node["step_no"],
                task_node["skill_name"],
                task_node["tool_name"],
                task_node["node_status"],
                task_node.get("node_note") or "",
            )
        )
    return "\n".join(summary_lines)


def agent_build_finding_type(step_node):
    # 设计说明：给发现归个类
    # 为什么：漏洞表要按类型筛选统计，但验证器的输出是方案定死的四字段，没有类型这一项，
    #         不能随手加字段，所以按"是哪个工具发现的"来归类
    # 放弃了：不让模型额外吐一个类型出来。加字段就得改验证器的输出契约，报告和前端都要跟着动
    #
    # 2026-10-02 补上四个专项检测工具的归类。之前没补，SQL 注入被记成"其他发现"，
    #         漏洞列表页按类型筛选就分不出来了
    tool_name = step_node.get("tool_name")
    if tool_name == "port_scan":
        return "端口暴露"
    if tool_name == "fingerprint":
        return "安全配置缺失"
    if tool_name == "http_probe":
        return "HTTP 响应异常"
    if tool_name == "sqli_probe":
        return "SQL注入"
    if tool_name == "xss_probe":
        return "跨站脚本"
    if tool_name == "traversal_probe":
        return "目录遍历"
    if tool_name == "leak_probe":
        return "敏感信息泄露"
    return "其他发现"


def agent_build_finding_level(confidence_score):
    # 设计说明：按置信度折算风险等级
    # 为什么：验证器只回答"有多确定"，报告上要的是"高/中/低"。换算放在这儿，两边各司其职
    if confidence_score >= 0.8:
        return "high"
    if confidence_score >= 0.5:
        return "medium"
    return "low"


def agent_execute_step(step_node, scan_context):
    # 设计说明：执行一个计划步骤，返回工具原始结果
    # 为什么：参数怎么凑交给 TOOL_ARGUMENT_BUILDERS，编排器只管"查工具在不在、凑参数、调出去"
    # 放弃了：不让模型自己生成工具参数。那等于开一个任意调用的口子，V1.0 只认固定映射
    tool_name = step_node.get("tool_name")
    if tool_name not in tool_fetch_descriptions():
        raise ValueError("计划里排了系统里不存在的工具：%s" % tool_name)

    argument_builder = TOOL_ARGUMENT_BUILDERS.get(tool_name)
    if argument_builder is None:
        raise ValueError("工具 %s 还没配参数构造规则" % tool_name)

    return tool_invoke(tool_name, **argument_builder(scan_context))


def agent_run_loop(job_row, session, recon_result):
    # 设计说明：PSV 循环主体，返回最终执行到的轮次
    # 为什么：每一轮都要走完"规划 → 执行 → 总结 → 验证"，验证结论决定继续还是收尾；
    #         已经执行过的动作不再重复，这一条是拦模型重复排计划的最后一道闸
    # 放弃了：不做循环内的检查点续跑。任务挂了就整单重开，比维护断点状态便宜
    target_url = recon_result.get("target_url") or ""
    scan_context = {
        "target_url": target_url,
        "target_host": recon_result.get("host") or "",
        "fingerprint": recon_result.get("fingerprint") or {},
        "executed_actions": set(),
        "last_http_result": None,
    }
    # 侦察阶段做过的动作先记进已执行清单，模型再排同样的步骤就会被拦下来
    for recon_action in recon_result.get("executed_actions") or []:
        scan_context["executed_actions"].add(tuple(recon_action))

    round_index = recon_result.get("finished_round") or 0
    task_tree = None
    idle_round = 0
    replan_times = 0
    loop_iteration = 0
    round_summaries = []
    # 协作状态：连续失败次数、已互换次数、当前是不是互换状态
    consecutive_failures = 0
    swap_times = 0
    role_swapped = False
    collaboration_mode = agent_fetch_collaboration_mode()
    # 中期反思攒下来的策略提示，重新规划时一并交给主控
    strategy_notes = []

    while round_index < AGENT_MAX_ROUND:
        loop_iteration += 1
        if loop_iteration > MAX_LOOP_ITERATION:
            logger.warning("循环迭代超过硬上限 %s 次，强制收尾", MAX_LOOP_ITERATION)
            break
        # ---- 规划：主控出计划 → 顾问挑毛病 → 合并成最终计划 ----
        if task_tree is None or agent_fetch_next_step(task_tree) is None:
            if replan_times >= MAX_REPLAN_TIMES:
                logger.info("重规划已达上限 %s 次，循环收尾", MAX_REPLAN_TIMES)
                break
            replan_times += 1
            fingerprint_block = scan_context["fingerprint"]
            replan_context = {
                "target_url": target_url,
                "host": scan_context["target_host"],
                "open_ports": recon_result.get("open_ports") or [],
                "fingerprint": fingerprint_block,
                # 提示词模板里要的是纯列表，在这儿先摊平，省得模板里再往外挖一层字典
                "technologies_list": fingerprint_block.get("technologies") or [],
                "security_header_gap_list": fingerprint_block.get("missing_security_headers") or [],
                "executed_actions": sorted(scan_context["executed_actions"]),
                "task_tree_summary": agent_build_task_tree_summary(task_tree),
                "strategy_notes": "\n".join(strategy_notes),
            }

            main_plan = agent_build_main_plan(replan_context, role_swapped)
            if main_plan is None:
                # 主控出不了计划就走兜底，别让整轮卡在"没计划可执行"上
                main_plan = plan_build_fallback(replan_context)

            advisor_review = agent_build_advisor_review(main_plan, replan_context, role_swapped)
            plan_result = agent_merge_advisor_advice(main_plan, advisor_review)
            task_tree = agent_build_task_tree(plan_result)

            collaboration_note = [
                "主导方 %s" % ("顾问（已互换）" if role_swapped else "主控"),
                "协作模式 %s" % collaboration_mode,
                "顾问 %s" % ("参与审查" if advisor_review else "本轮没给出可用意见"),
            ]
            if swap_times:
                collaboration_note.append("累计互换 %s 次" % swap_times)

            session.add(AuditLog(
                job_id=job_row.id,
                log_type="decision",
                log_content="第 %s 次规划：%s" % (replan_times, plan_result.get("plan_goal")),
                log_reason="%s；计划 %s 步（主控 %s 步 + 顾问补 %s 步），顾问提了 %s 条意见" % (
                    "，".join(collaboration_note),
                    len(plan_result.get("plan_steps") or []),
                    len(main_plan.get("plan_steps") or []),
                    plan_result.get("advisor_added_count", 0),
                    plan_result.get("advisor_issue_count", 0),
                ),
            ))
            recon_result["collaboration"] = {
                "mode": collaboration_mode,
                "role_swapped": role_swapped,
                "swap_times": swap_times,
                "advisor_summary": plan_result.get("advisor_summary") or "",
                "advisor_issues": (advisor_review or {}).get("advisor_issues") or [],
            }
            session.commit()
            if agent_fetch_next_step(task_tree) is None:
                break

        step_node = agent_fetch_next_step(task_tree)
        action_key = (step_node["skill_name"], step_node["tool_name"])

        # ---- 拦重复动作：模型排计划时经常忘了哪步做过，这里替它拦住 ----
        if action_key in scan_context["executed_actions"]:
            step_node["node_status"] = "skipped"
            step_node["node_note"] = "这一步前面已经执行过"
            recon_result["task_tree"] = task_tree
            job_row.plan_snapshot = json.dumps({"recon": recon_result}, ensure_ascii=False)
            session.add(AuditLog(
                job_id=job_row.id,
                log_type="decision",
                log_content="跳过重复动作 %s / %s" % action_key,
                log_reason="计划里排了已经做过的步骤，不重复执行",
            ))
            session.commit()
            # 跳过不算空转，也不消耗轮次——这是个不花钱的动作，接着看下一步有没有新东西。
            # 2026-10-01 最初把跳过计入空转，结果计划里连着几个重复步骤就直接收尾了，
            # 排在它们后面的新步骤压根没机会执行
            continue

        round_index += 1
        step_node["node_status"] = "running"

        # ---- 执行 ----
        try:
            raw_result = agent_execute_step(step_node, scan_context)
            step_node["node_status"] = "done"
        except Exception as step_error:
            step_node["node_status"] = "failed"
            step_node["node_note"] = str(step_error)[:120]
            idle_round += 1
            consecutive_failures += 1
            session.add(AuditLog(
                job_id=job_row.id,
                log_type="tool",
                log_content="步骤执行失败：%s / %s" % action_key,
                log_reason=str(step_error)[:200],
            ))

            # 连着卡住就换视角：主控和顾问互换角色，换个模型、换套提示词再来
            if agent_check_swap_condition(consecutive_failures, swap_times):
                role_swapped = not role_swapped
                swap_times += 1
                consecutive_failures = 0
                session.add(AuditLog(
                    job_id=job_row.id,
                    log_type="reflection",
                    log_content="触发角色互换，第 %s 次" % swap_times,
                    log_reason="连续失败达到阈值 %s 次，改由%s主导" % (
                        AGENT_FAIL_SWAP_THRESHOLD,
                        "顾问" if role_swapped else "主控",
                    ),
                ))
                session.commit()
                continue

            # 互换次数用尽还在失败，说明这条路真的走不通了，收尾
            if consecutive_failures >= AGENT_FAIL_SWAP_THRESHOLD:
                logger.info("连续失败 %s 次且互换次数已用尽，循环收尾", consecutive_failures)
                session.commit()
                break

            session.commit()
            continue

        scan_context["executed_actions"].add(action_key)
        if step_node["tool_name"] == "http_probe":
            # 缓存下来给后面依赖它的步骤用（指纹识别就要这个）
            scan_context["last_http_result"] = raw_result

        # ---- 总结 ----
        round_summary = summarize_round_result(step_node["tool_name"], raw_result)

        # ---- 验证 ----
        verdict = validate_round_result(round_summary, scan_context, step_node)

        round_summaries.append({
            "round_index": round_index,
            "skill_name": step_node["skill_name"],
            "tool_name": step_node["tool_name"],
            "round_summary": round_summary,
            "verdict": verdict,
        })

        if verdict.get("is_vuln"):
            session.add(Finding(
                job_id=job_row.id,
                vuln_type=agent_build_finding_type(step_node),
                vuln_level=agent_build_finding_level(verdict.get("confidence") or 0.0),
                vuln_url=target_url,
                # 证据留摘要而不是全文，报告要能溯源，库也不能被正文撑爆
                raw_evidence=json.dumps(round_summary, ensure_ascii=False)[:1000],
                confidence=verdict.get("confidence") or 0.0,
                validate_reason=verdict.get("reason"),
            ))

        session.add(AuditLog(
            job_id=job_row.id,
            log_type="reflection",
            log_content="第 %s 轮判定：%s" % (
                round_index, "发现可疑问题" if verdict.get("is_vuln") else "本轮无发现"),
            log_reason="置信度 %s；%s" % (verdict.get("confidence"), verdict.get("reason")),
        ))

        # 每轮结束都把任务树和轮次摘要落进快照，报告复盘全靠它
        recon_result["task_tree"] = task_tree
        recon_result["round_summaries"] = round_summaries
        recon_result["finished_round"] = round_index
        job_row.current_round = round_index
        job_row.plan_snapshot = json.dumps({"recon": recon_result}, ensure_ascii=False)
        session.commit()

        if verdict.get("next_action") == "stop":
            if agent_fetch_next_step(task_tree) is not None:
                # 2026-10-02 验证器喊收尾时计划里还有没跑的步骤，第一版直接 break 了，
                # 结果是它找到一处泄露就喊停，后面三个技能一个都没机会跑。
                # 规则改成：计划没走完就不收尾，已经列入计划的事不该被一句话丢掉
                session.add(AuditLog(
                    job_id=job_row.id,
                    log_type="decision",
                    log_content="验证器建议收尾，但计划里还有未执行步骤，继续执行",
                    log_reason="第 %s 轮判定给出 stop，剩余待执行步骤 %s 个" % (
                        round_index, len([n for n in task_tree["nodes"] if n["node_status"] == "pending"])),
                ))
                session.commit()
            else:
                logger.info("验证器给出 stop 且计划已走完，第 %s 轮收尾", round_index)
                break

        # 每跑满几轮停下来横着看一眼，把策略提示带进下一版计划（方案 4.5 的反思段）
        if round_index % REFLECT_ROUND_INTERVAL == 0:
            progress_note = agent_run_progress_reflection(
                round_summaries, agent_build_task_tree_summary(task_tree), scan_context)
            if progress_note:
                strategy_notes.append(progress_note)
                session.add(AuditLog(
                    job_id=job_row.id,
                    log_type="reflection",
                    log_content="第 %s 轮中期反思：%s" % (round_index, progress_note[:90]),
                    log_reason="每 %s 轮反思一次，结论会带进下一版计划" % REFLECT_ROUND_INTERVAL,
                ))
                session.commit()

        # 这一轮拿到了新东西，空转计数清零
        idle_round = 0

    # 循环退出后把最终树态落库。中途 break 出来的话，最后一次提交里还是旧状态，
    # 报告看到的会是"还有一堆步骤 pending"，其实它们早被判成跳过了
    recon_result["task_tree"] = task_tree
    recon_result["round_summaries"] = round_summaries
    recon_result["finished_round"] = round_index
    # 顺序不能反：先把之前记下的顾问意见铺开，再用最终状态覆盖同名键，
    # 否则快照里存的会是中途某一次互换前的旧状态
    recon_result["collaboration"] = {
        **(recon_result.get("collaboration") or {}),
        "mode": collaboration_mode,
        "role_swapped": role_swapped,
        "swap_times": swap_times,
    }
    job_row.current_round = round_index
    job_row.plan_snapshot = json.dumps({"recon": recon_result}, ensure_ascii=False)
    session.commit()
    return round_index
