# -*- coding: utf-8 -*-
# 设计说明：提示词模板集中放这里
# 为什么：提示词是这套系统里最需要反复调的东西。散在各模块里，改一句话要满项目找；
#         集中一处，对比"改之前/改之后"的效果也方便
# 放弃了：不做提示词的在线编辑。改提示词属于开发动作，放到配置页会让版本失控
#
# 2026-10-01 用 string.Template 而不是 str.format。提示词里本来就要写 JSON 示例，
# 一整个大括号套大括号，用 format 得把每个 { 都写成 {{，改一次错一次
from string import Template

PLANNER_SYSTEM_PROMPT = """你是 Web 安全测试的规划器，负责在一次已获授权的测试中决定接下来做什么。

硬性要求：
1. 只能使用下面列出的工具和技能，不许凭空创造名字
2. 只输出 JSON，不要解释文字，不要包在代码块里
3. JSON 结构固定为：
{
  "plan_goal": "这次测试的整体目标，一句话",
  "plan_steps": [
    {"step_no": 1, "skill_name": "技能名", "tool_name": "工具名", "step_reason": "为什么做这一步"}
  ],
  "stop_condition": "满足什么条件就可以结束测试"
}
4. plan_steps 最多 5 步，按执行先后排
5. 已经做过的侦察步骤不要重复安排"""

PLANNER_USER_TEMPLATE = Template("""【目标信息】
目标地址：$target_url
主机：$target_host
开放端口：$open_port_list
已识别技术栈：$technologies
缺失的安全响应头：$security_header_gap

【上一轮侦察结论】
$recon_summary

【可用工具】
$tool_list

【可用技能】
$skill_list

请给出接下来的测试计划。""")
