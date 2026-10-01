# -*- coding: utf-8 -*-
# 设计说明：统一模型适配器。上层只调这里的函数，不关心底层是哪家厂商
# 为什么：各家接口差异全部收敛在这一层，换模型、加厂商都不动规划器和反思器的代码
# 放弃了：不用各家官方 SDK。SDK 各带一套依赖、各有各的调用姿势，直接发 HTTP 反而更可控
#
# 2026-10-01 适配器做成了模块级函数而不是类。全项目统一"模块前缀 + 动作动词 + 对象"，
# 类方法再套一层前缀很别扭；而且配置本身就是个普通字典，没必要专门养一个对象
import json
import logging

import requests

from llm.model_registry import llm_fetch_provider
from llm.providers.custom_provider import llm_invoke_custom_chat
from llm.providers.openai_compatible_provider import llm_invoke_compatible_chat
from llm.providers.zhipu_provider import llm_invoke_zhipu_chat

logger = logging.getLogger("ai_scanner.llm")

# 请求格式 -> 具体实现。加一种新格式只在这里补一行映射
PROVIDER_HANDLERS = {
    "openai_compatible": llm_invoke_compatible_chat,
    "zhipu": llm_invoke_zhipu_chat,
    "custom": llm_invoke_custom_chat,
}


def llm_build_provider_handler(active_config):
    # 设计说明：按配置里的请求格式挑出对应的实现函数
    # 为什么：厂商差异说到底只有"怎么把请求发出去"这一点，挑函数的事收敛在这一处
    # 放弃了：不做运行时插件发现。V1.0 支持的格式是个封闭集合，写死映射表更可靠
    provider_key = active_config.get("provider", "")
    provider_meta = llm_fetch_provider(provider_key)
    api_format = active_config.get("api_format") or provider_meta.get("api_format") or "openai_compatible"

    handler = PROVIDER_HANDLERS.get(api_format)
    if handler is None:
        raise ValueError("没有对应的请求格式实现：%s" % api_format)
    return handler


def llm_invoke_prompt(active_config, raw_prompt, system_prompt=None):
    # 设计说明：发一次对话请求，返回模型输出的纯文本
    # 为什么：规划器和反思器只想要一段文字，HTTP 怎么拼、头怎么带都不该它们操心
    # 放弃了：不做流式输出。V1.0 的回复都很短，等完整结果比边收边拼简单得多
    if not active_config:
        raise ValueError("还没有可用的模型配置，先去配置页填一套")

    message_list = []
    if system_prompt:
        message_list.append({"role": "system", "content": system_prompt})
    message_list.append({"role": "user", "content": raw_prompt})

    return llm_build_provider_handler(active_config)(active_config, message_list)


def llm_invoke_json(active_config, raw_prompt, system_prompt=None):
    # 设计说明：要求模型返回 JSON，解析成字典
    # 为什么：模型经常把 JSON 包在 ```json 代码块里，或者前后多一句"好的，以下是结果"。
    #         剥壳的逻辑收在这里，调用方就不必每处都写一遍同样的容错
    # 放弃了：不做字段级 schema 校验。字段齐不齐由调用方判断，这里只保证"能解析成字典"
    json_prompt = raw_prompt + "\n\n只输出 JSON，不要解释文字，不要包在代码块里。"
    raw_text = llm_invoke_prompt(active_config, json_prompt, system_prompt)
    cleaned_text = (raw_text or "").strip()

    if cleaned_text.startswith("```"):
        # 去掉开头的 ```json 那一行和结尾的 ```
        cleaned_text = cleaned_text.split("\n", 1)[-1] if "\n" in cleaned_text else cleaned_text
        cleaned_text = cleaned_text.rsplit("```", 1)[0].strip()

    try:
        return json.loads(cleaned_text)
    except (ValueError, TypeError):
        # 解析不了不算致命错误，回一个带原文的字典，让调用方自己决定要不要重试
        logger.warning("模型返回的不是合法 JSON，前 120 字：%s", cleaned_text[:120])
        return {"error": "模型返回的不是合法 JSON", "raw_text": (raw_text or "")[:500]}


def llm_check_connection(test_config):
    # 设计说明：连通性测试，配置页那个按钮走这里
    # 为什么：真发一次最短的对话请求，比只 ping 一下地址靠谱——地址通不代表 Key 能用、
    #         也不代表模型名填对了
    # 放弃了：不去拉厂商的模型列表做校验。各家接口不一样，为一个"顺便校验"多写三套适配不值当
    try:
        reply_text = llm_invoke_prompt(
            test_config,
            "回复两个字：正常",
            system_prompt="你是连通性测试探针，只按用户要求回复，不要任何多余说明。",
        )
    except requests.Timeout:
        return {"success": False, "message": "等超时了。检查网络，或者把超时时间调大点"}
    except requests.RequestException as net_error:
        return {"success": False, "message": "连不上，检查 Base URL 和网络：%s" % str(net_error)[:120]}
    except ValueError as config_error:
        return {"success": False, "message": str(config_error)}
    except (KeyError, IndexError, TypeError):
        # 响应结构对不上。多半是请求格式选错了，或者 Base URL 指到了别的服务上
        return {"success": False, "message": "响应结构对不上，检查请求格式和 Base URL 是不是匹配"}

    return {"success": True, "message": "连接成功，模型回了 %s 个字" % len(reply_text or "")}
