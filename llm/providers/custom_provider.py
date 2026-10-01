# -*- coding: utf-8 -*-
# 设计说明：自定义厂商的请求实现，兜底形态
# 为什么：用户自己填的厂商可能既不是 OpenAI 兼容也不是智谱，得有个能兜住的地方
# 放弃了：不做请求模板配置。真让用户在页面上填请求体模板、字段路径，配置页会复杂到没人填得明白，
#         V1.0 宁可多做几次字段猜测，也不把复杂度丢给用户
import requests

# 取正文时按顺序试这些位置。自建服务和小众厂商常把结果放在这些地方，
# 只认 choices[0].message.content 会一直取不到正文
CONTENT_PATHS = (
    ("choices", 0, "message", "content"),
    ("choices", 0, "text"),
    ("output", "text"),
    ("result", "content"),
    ("data", "content"),
    ("content",),
    ("text",),
)


def llm_parse_content_by_path(response_data, content_path):
    # 设计说明：按一条字段路径从响应里取值，取不到返回 None
    # 为什么：逐层 get 加类型判断，比 try/except 包一大段更好定位问题出在哪一层
    current_value = response_data
    for path_item in content_path:
        if isinstance(path_item, int):
            if not isinstance(current_value, (list, tuple)) or len(current_value) <= path_item:
                return None
            current_value = current_value[path_item]
        else:
            if not isinstance(current_value, dict):
                return None
            current_value = current_value.get(path_item)
        if current_value is None:
            return None
    return current_value if isinstance(current_value, str) else None


def llm_invoke_custom_chat(active_config, message_list):
    # 设计说明：自定义厂商请求实现。按最朴素的约定发请求，响应按候选路径逐个试
    # 为什么：兜底实现的价值就在"猜得中"。多试几个常见字段位置，比让用户先去读厂商文档再回来改代码强
    # 放弃了：不支持自定义鉴权方式。V1.0 统一按 Bearer 发，不满足的话就走智谱那种专用实现
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

    if response.status_code != 200:
        raise ValueError("厂商返回 %s：%s" % (response.status_code, response.text[:200]))

    response_data = response.json()
    for content_path in CONTENT_PATHS:
        content_text = llm_parse_content_by_path(response_data, content_path)
        if content_text:
            return content_text

    # 一个都没命中，把响应结构的前一段抛出去。报"取不到正文"没用，得让人看见长什么样
    raise ValueError("认不出响应结构，原文开头：%s" % str(response_data)[:200])
