# -*- coding: utf-8 -*-
# 设计说明：厂商注册表，登记每家厂商的请求格式、默认地址和常用模型
# 为什么：新增厂商只改这一张表，适配器和智能体都不用动——这是"不写死任何模型"的落点
# 放弃了：不做厂商能力描述（上下文长度、是否支持函数调用）。V1.0 只关心"话怎么发出去"
#
# 2026-10-01 百川和 MiniMax 暂时归到 custom 格式。这两家的接口文档细节没抠到位，
# 先走通用解析兜底，等真接了再归到各自格式
MODEL_PROVIDERS = {
    "deepseek": {
        "label": "DeepSeek",
        "api_format": "openai_compatible",
        "default_base_url": "https://api.deepseek.com/v1",
        "models": ["deepseek-chat", "deepseek-reasoner"],
    },
    "zhipu": {
        "label": "智谱GLM",
        "api_format": "zhipu",
        "default_base_url": "https://open.bigmodel.cn/api/paas/v4",
        "models": ["glm-4-plus", "glm-4-flash"],
    },
    "qwen": {
        "label": "通义千问",
        "api_format": "openai_compatible",
        "default_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-max", "qwen-plus"],
    },
    "kimi": {
        "label": "Kimi",
        "api_format": "openai_compatible",
        "default_base_url": "https://api.moonshot.cn/v1",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
    },
    "baichuan": {
        "label": "百川",
        "api_format": "custom",
        "default_base_url": "https://api.baichuan-ai.com/v1",
        "models": ["baichuan4"],
    },
    "minimax": {
        "label": "MiniMax",
        "api_format": "custom",
        "default_base_url": "https://api.minimax.chat/v1",
        "models": ["abab6.5s-chat"],
    },
    "custom": {
        "label": "自定义",
        "api_format": "openai_compatible",
        "default_base_url": "",
        "models": [],
    },
}


def llm_fetch_providers():
    # 设计说明：返回全部预置厂商，供配置页的下拉框渲染
    # 为什么：厂商清单前端不该自己写一份。写两份的结果是加了一个厂商前端还是选不到
    return [
        {
            "provider": provider_key,
            "label": provider_meta["label"],
            "api_format": provider_meta["api_format"],
            "default_base_url": provider_meta["default_base_url"],
            "models": list(provider_meta["models"]),
        }
        for provider_key, provider_meta in MODEL_PROVIDERS.items()
    ]


def llm_fetch_provider(provider_key):
    # 设计说明：按厂商标识取一条预置信息，取不到返回空字典
    # 为什么：自定义厂商允许随便填标识，取不到是正常情况，不该抛异常打断保存流程
    return MODEL_PROVIDERS.get(provider_key, {})


def llm_fetch_model_names(provider_key):
    # 设计说明：取某厂商的预置模型名列表
    # 为什么：配置页里换厂商要联动刷新模型下拉框，数据源就是这里
    return list(llm_fetch_provider(provider_key).get("models", []))
