# -*- coding: utf-8 -*-
# 设计说明：智谱 GLM 的请求实现
# 为什么：智谱的鉴权方式和 OpenAI 不一样——不能直接把 API Key 当 Bearer 用，
#         得先用它签一个短时效的 JWT 再去换请求资格。照抄 OpenAI 那套会一直 401
# 放弃了：不做 token 缓存。V1.0 调用频率很低，每次多签一次 JWT 无所谓，缓存反而容易踩到过期
import warnings
from datetime import datetime, timedelta, timezone

import jwt
import requests

try:
    from jwt.exceptions import InsecureKeyLengthWarning
except ImportError:
    # 老版本 PyJWT 没有这个警告类，退到基类，过滤范围只是宽一点点
    InsecureKeyLengthWarning = Warning

# 智谱的 secret 段只有 16 字节，比 RFC 7518 建议的 32 字节短，但长度是厂商定的，我们改不了。
# 2026-10-01 过滤掉这条：每次调用都刷两遍，日志里真正的告警会被它淹掉
warnings.filterwarnings("ignore", category=InsecureKeyLengthWarning)

# 签出去的 JWT 只活 5 分钟。够发一次请求就行，签长了万一泄露窗口也大
TOKEN_ALIVE_MINUTES = 5


def llm_build_zhipu_token(raw_api_key):
    # 设计说明：用智谱的 API Key 签出一个 JWT
    # 为什么：智谱的 Key 是 "id.secret" 两段式。id 要放进载荷的 api_key 字段，
    #         secret 当签名密钥用，缺一段都签不出来
    # 放弃了：不做格式校验后报错。不规范的 Key 让它在请求时被厂商拒掉，
    #         比在这里猜格式、给一堆误判提示更省事
    key_id, _, key_secret = raw_api_key.partition(".")
    if not key_secret:
        # 不是两段式就整串当 secret 用。签出来的 token 厂商会拒，但至少进程不会崩
        key_id, key_secret = raw_api_key, raw_api_key

    now_time = datetime.now(timezone.utc)
    token_payload = {
        "api_key": key_id,
        "exp": int((now_time + timedelta(minutes=TOKEN_ALIVE_MINUTES)).timestamp() * 1000),
        "timestamp": int(now_time.timestamp() * 1000),
    }
    return jwt.encode(
        token_payload,
        key_secret,
        algorithm="HS256",
        headers={"alg": "HS256", "sign_type": "SIGN"},
    )


def llm_invoke_zhipu_chat(active_config, message_list):
    # 设计说明：按智谱的对话协议发一次请求，返回正文
    # 为什么：请求体和响应体的结构和 OpenAI 基本一致，差别只在鉴权头，所以这里只重写鉴权
    # 放弃了：不适配流式。V1.0 一律等完整结果
    access_token = llm_build_zhipu_token(active_config.get("api_key", ""))

    request_body = {
        "model": active_config.get("model_name"),
        "messages": message_list,
        "temperature": active_config.get("temperature", 0.3),
        "max_tokens": active_config.get("max_tokens", 4096),
    }

    response = requests.post(
        active_config["base_url"].rstrip("/") + "/chat/completions",
        headers={
            "Authorization": "Bearer %s" % access_token,
            "Content-Type": "application/json",
        },
        json=request_body,
        timeout=active_config.get("timeout", 30),
    )

    if response.status_code != 200:
        raise ValueError("智谱返回 %s：%s" % (response.status_code, response.text[:200]))

    response_data = response.json()
    return response_data["choices"][0]["message"]["content"]
