# -*- coding: utf-8 -*-
# 设计说明：技能管理器，负责技能的发现、按需加载和动态上下文注入
# 为什么：技能正文常驻上下文会把 token 吃光。三级渐进式披露——平时只留名字和描述（约 100 Token），
#         判断要用了才读正文，真要执行了才加载脚本
# 放弃了：不做运行时热加载（改完 SKILL.md 不重启就生效）。技能随代码发布，重启一下更省事
#
# 2026-10-01 动态注入没有照抄"执行命令"那套。原方案写的是 {{execute: echo $TARGET_URL}}，
# 这在 Windows 上取不到环境变量根本跑不通，而且等于留了个任意命令执行的口子。
# 改成白名单取值：只认三个固定名字，值由本模块直接给，不经过任何 shell
import importlib
import logging
import re
from pathlib import Path

logger = logging.getLogger("ai_scanner.skill")

# 项目根目录在 skills/ 的上一层，用来把脚本文件路径换算成 import 路径
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = Path(__file__).resolve().parent

# 元数据缓存。启动时扫一次填满，之后只读——技能目录运行期不会变
skill_metadata_cache = {}

# 动态注入的取值白名单。名字对不上的一律原样保留，宁可露出占位符也不猜一个值塞进去
DYNAMIC_CONTEXT_KEYS = ("target_url", "fingerprint", "round_index")

_EXECUTE_PATTERN = re.compile(r"\{\{execute:\s*([A-Za-z_]+)\s*\}\}")
_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)


def skill_parse_frontmatter(skill_text):
    # 设计说明：把 SKILL.md 头部的元数据块解析成字典
    # 为什么：不引 pyyaml。这里有意义的字段就三个，还是平铺的，为它多装一个依赖不值当
    # 放弃了：不解析嵌套结构和多行值。真需要那些的时候再换 yaml，现在够用
    frontmatter_match = _FRONTMATTER_PATTERN.match(skill_text)
    if not frontmatter_match:
        return {}

    parsed_meta = {}
    for meta_line in frontmatter_match.group(1).splitlines():
        if ":" not in meta_line:
            continue
        meta_key, _, meta_value = meta_line.partition(":")
        meta_key = meta_key.strip()
        meta_value = meta_value.strip()

        if meta_value.startswith("[") and meta_value.endswith("]"):
            # 列表写法 [a, b, c]。不引 yaml 就得自己拆，好在只有这一种形态
            parsed_meta[meta_key] = [
                item.strip().strip('"').strip("'")
                for item in meta_value[1:-1].split(",")
                if item.strip()
            ]
        else:
            parsed_meta[meta_key] = meta_value.strip('"').strip("'")

    return parsed_meta


def skill_load_metadata():
    # 设计说明：扫描技能目录，把每个 SKILL.md 的元数据读进缓存
    # 为什么：这是三级披露的第一级。启动时一次性读好，之后组装上下文直接拿现成的，不用每次翻文件
    # 放弃了：不监听目录变化做热更新。技能随代码发布，改了重启就够
    skill_metadata_cache.clear()

    for skill_file in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        skill_text = skill_file.read_text(encoding="utf-8")
        parsed_meta = skill_parse_frontmatter(skill_text)
        # 元数据里没写 name 就退回目录名，免得整个技能因为一行漏写就加载不到
        skill_name = parsed_meta.get("name") or skill_file.parent.name

        skill_metadata_cache[skill_name] = {
            "name": skill_name,
            "description": parsed_meta.get("description", ""),
            "trigger_keywords": parsed_meta.get("trigger_keywords", []),
            "skill_path": str(skill_file),
        }

    logger.info(
        "技能元数据加载完成，共 %s 个：%s",
        len(skill_metadata_cache),
        ", ".join(skill_metadata_cache) or "无",
    )
    return dict(skill_metadata_cache)


def skill_fetch_metadata_list():
    # 设计说明：返回给智能体看的技能清单
    # 为什么：这段要常驻上下文，必须短。把正文也塞进来就失去按需加载的意义了
    return [
        {"name": item["name"], "description": item["description"]}
        for item in skill_metadata_cache.values()
    ]


def skill_match_by_context(context_keywords):
    # 设计说明：按上下文关键词匹配出该加载哪些技能
    # 为什么：匹配只做关键词命中，不在这里调模型。这一层要保持又快又没副作用，
    #         要不要采纳匹配结果，是智能体那一层的事
    # 放弃了：不做打分排序。命中就是命中，多个技能同时命中就都返回，让调用方自己挑
    matched_skills = []
    context_text = " ".join(str(item) for item in (context_keywords or [])).lower()
    if not context_text:
        return matched_skills

    for skill_name, skill_meta in skill_metadata_cache.items():
        for trigger_keyword in skill_meta["trigger_keywords"]:
            if str(trigger_keyword).lower() in context_text:
                matched_skills.append(skill_name)
                break

    return matched_skills


def skill_load_body(skill_name):
    # 设计说明：读技能正文（三级披露的第二级），去掉头部元数据
    # 为什么：正文里写的是决策原则和失败处理，属于"要怎么干"。只有确定要用这个技能时才值得占上下文
    # 放弃了：不截断正文长度。技能正文由我们自己写，写太长是编写问题，不该在加载时偷偷砍掉
    skill_meta = skill_metadata_cache.get(skill_name)
    if skill_meta is None:
        logger.warning("技能 %s 不在元数据缓存里，正文加载跳过", skill_name)
        return ""

    skill_text = Path(skill_meta["skill_path"]).read_text(encoding="utf-8")
    # count=1 只脱掉开头这一块，正文里再出现 --- 那是分隔线，不能一起吃掉
    return _FRONTMATTER_PATTERN.sub("", skill_text, count=1).strip()


def skill_inject_dynamic_context(skill_body, context_values):
    # 设计说明：把正文里的 {{execute: xxx}} 换成实际值
    # 为什么：原方案这里是"执行命令取输出"，那既跑不通（Windows 取不到环境变量）又危险。
    #         改成白名单取值，名字不在表里就原样留着，暴露问题比悄悄填个错值强
    # 放弃了：不支持带参数的取值表达式。V1.0 就三个固定名字，够用
    def replace_slot(slot_match):
        slot_name = slot_match.group(1)
        if slot_name not in DYNAMIC_CONTEXT_KEYS:
            return slot_match.group(0)
        return str((context_values or {}).get(slot_name, ""))

    return _EXECUTE_PATTERN.sub(replace_slot, skill_body)


def skill_load_scripts(skill_name):
    # 设计说明：加载技能目录下的脚本（三级披露的第三级），返回被导入的模块
    # 为什么：技能脚本底部一般会调 tool_register 自报家门，import 一下就等于把技能带来的工具注册进系统。
    #         所以这一步是"加载即注册"，不是单纯列个文件清单
    # 放弃了：不做脚本级沙箱隔离，那是 tools/sandbox.py 的职责
    skill_meta = skill_metadata_cache.get(skill_name)
    if skill_meta is None:
        return []

    script_dir = Path(skill_meta["skill_path"]).parent / "scripts"
    if not script_dir.is_dir():
        return []

    loaded_modules = []
    for script_path in sorted(script_dir.glob("*.py")):
        if script_path.name == "__init__.py":
            continue
        # 把文件路径换算成 import 路径，例如 skills/web_recon/scripts/fingerprint.py
        module_name = ".".join(script_path.relative_to(PROJECT_ROOT).with_suffix("").parts)
        try:
            loaded_modules.append(importlib.import_module(module_name))
        except Exception as load_error:
            # 单个脚本挂掉不该让整个技能报废，记下来继续加载其余脚本
            logger.error("技能 %s 的脚本 %s 加载失败：%s", skill_name, module_name, load_error)

    logger.info("技能 %s 已加载脚本 %s 个", skill_name, len(loaded_modules))
    return loaded_modules
