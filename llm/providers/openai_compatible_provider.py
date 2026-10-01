# -*- coding: utf-8 -*-
# 设计说明：OpenAI 兼容格式的请求实现
# 为什么：DeepSeek、通义、Kimi 都走这套协议，写一份三家通用，以后再加兼容厂商零改代码
# 放弃了：不处理函数调用和多模态。V1.0 只发纯文本对话，多出来的分支都是死代码
import requests


def llm_invoke_compatible_chat(active_config, message_list):
    # 设计说明：按 OpenAI 的 /chat/completions 协议发一次请求，返回正文
    # 为什么：直接用 requests 发。官方 SDK 各带一套依赖，还把请求体藏起来了，
    #         真出问题时连自己发出去的原文都看不到
    # 放弃了：不做重试。超时和限流要不要重来交给上层决定，这层只管发一次
    request_body = {
        "model": active_config.get("model_name"),
        "messages": message_list,
        "temperature": active_config.get("temperature", 0.3),
        "max_tokens": active_config.get("max_tokens", 4096),
    }

    response = requests.post(
        active_config["base_url"].rstrip("/") + "/chat/completions",
        headers={
            "Authorization": "Bearer %s" % active_config.get("api_key", ""),
            "Content-Type": "application/json",
        },
        json=request_body,
        timeout=active_config.get("timeout", 30),
    )

    # 状态码不对时把响应体也带上。只报一句 "400 Bad Request" 根本分不清是 Key 错了、
    # 模型名写错了还是额度用完了
    if response.status_code != 200:
        raise ValueError("厂商返回 %s：%s" % (response.status_code, response.text[:200]))

    response_data = response.json()
    return response_data["choices"][0]["message"]["content"]
