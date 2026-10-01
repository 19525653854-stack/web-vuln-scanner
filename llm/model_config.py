# -*- coding: utf-8 -*-
# 设计说明：模型配置的存取与 API Key 加解密
# 为什么：Key 不能明文落库。库文件被拷走就等于把用户的模型账号一起送人，
#         所以用 SECRET_KEY 派生密钥做对称加密，库里只存密文
# 放弃了：不做密钥轮换。SECRET_KEY 一换已存的 Key 就解不开了，V1.0 接受这个代价
#
# 2026-10-01 加密从自写的异或挪到了 Fernet。最早用 HMAC 造密钥流异或，能跑，
# 但自己拼密码学构造这件事本身就不该干，换成标准实现更踏实
import base64
import hashlib
import logging
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken

from config import SECRET_KEY
from llm.model_registry import llm_fetch_provider
from models.database import SessionLocal
from models.tables import ModelConfig

logger = logging.getLogger("ai_scanner.llm")

# 打码露出的首尾字符数。露太多等于没打码，太少用户认不出自己填的是哪把 Key
MASK_HEAD_LEN = 4
MASK_TAIL_LEN = 4


def llm_build_key_cipher():
    # 设计说明：用 SECRET_KEY 派生出一个对称加解密器
    # 为什么：Fernet 要求密钥是 32 字节的 urlsafe base64，而 SECRET_KEY 是随便一段字符串，
    #         先 sha256 压成定长再编码才符合它的输入要求
    # 放弃了：不用非对称加密。加解密都在同一个进程里，非对称带来的复杂度换不来任何好处
    derived_key = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def llm_build_encrypted_key(raw_api_key):
    # 设计说明：把明文 Key 加密后返回，用于入库
    # 为什么：入库存密文，就算库文件泄露，没有 SECRET_KEY 也解不出来
    if not raw_api_key:
        return ""
    return llm_build_key_cipher().encrypt(raw_api_key.encode("utf-8")).decode("utf-8")


def llm_parse_encrypted_key(stored_api_key):
    # 设计说明：把库里的密文解回明文
    # 为什么：真发请求时必须用明文。解不开说明 SECRET_KEY 换过了，这时只能当没填处理
    if not stored_api_key:
        return ""
    try:
        return llm_build_key_cipher().decrypt(stored_api_key.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        logger.error("配置里的 API Key 解不开，多半是 SECRET_KEY 换过了，需要到配置页重填")
        return ""


def llm_build_masked_key(raw_api_key):
    # 设计说明：把 Key 打码，用于回显给前端
    # 为什么：配置页要显示成 ****，但又得让用户一眼认出填的是哪一把
    if not raw_api_key:
        return ""
    if len(raw_api_key) <= MASK_HEAD_LEN + MASK_TAIL_LEN:
        return "*" * len(raw_api_key)
    return raw_api_key[:MASK_HEAD_LEN] + "****" + raw_api_key[-MASK_TAIL_LEN:]


def llm_check_key_masked(raw_api_key):
    # 设计说明：判断前端传回来的 Key 是不是打码值
    # 为什么：编辑配置时前端会把 **** 原样回传。不当打码值处理的话，
    #         用户只改个温度也会把库里的 Key 覆盖成 "sk-1****cdef"
    return "****" in (raw_api_key or "")


def llm_build_config_dict(config_row, mask_key=True):
    # 设计说明：把数据库行转成字典，并决定 Key 回显打码值还是明文
    # 为什么：同一行要给两处用——接口回显要打码，适配器发请求要明文，
    #         用一个开关区分，比在两个地方各写一遍取值逻辑可靠
    raw_main_key = llm_parse_encrypted_key(config_row.main_model_api_key)
    raw_advisor_key = llm_parse_encrypted_key(config_row.advisor_model_api_key)

    return {
        "id": config_row.id,
        "config_name": config_row.config_name,
        "main_model_provider": config_row.main_model_provider,
        "main_model_name": config_row.main_model_name,
        "main_model_api_key": llm_build_masked_key(raw_main_key) if mask_key else raw_main_key,
        "main_model_base_url": config_row.main_model_base_url,
        "advisor_model_provider": config_row.advisor_model_provider,
        "advisor_model_name": config_row.advisor_model_name,
        "advisor_model_api_key": llm_build_masked_key(raw_advisor_key) if mask_key else raw_advisor_key,
        "advisor_model_base_url": config_row.advisor_model_base_url,
        "collaboration_mode": config_row.collaboration_mode,
        "temperature": config_row.temperature,
        "max_tokens": config_row.max_tokens,
        "timeout": config_row.timeout,
        "is_active": config_row.is_active,
        "created_at": config_row.created_at.strftime("%Y-%m-%d %H:%M") if config_row.created_at else None,
    }


def llm_save_config(config_payload):
    # 设计说明：保存一套模型配置，按配置名覆盖或新建，并处理激活
    # 为什么：按配置名做唯一键。用户认的就是"我那套 DeepSeek 配置"，重名之后下拉框里分不清
    # 放弃了：不做配置删除。删之前得先确认没有任务在引用它，V1.0 不值得为这个加一套交互
    session = SessionLocal()
    try:
        config_name = (config_payload.get("config_name") or "").strip()
        if not config_name:
            return {"ok": False, "message": "配置名称不能为空"}

        config_row = session.query(ModelConfig).filter(ModelConfig.config_name == config_name).first()
        is_new_config = config_row is None
        if is_new_config:
            config_row = ModelConfig(config_name=config_name)
            session.add(config_row)

        provider_key = config_payload.get("main_model_provider") or "custom"
        provider_meta = llm_fetch_provider(provider_key)
        config_row.main_model_provider = provider_key
        config_row.main_model_name = config_payload.get("main_model_name") or ""
        # 地址没填就退回该厂商的预置地址，省得用户自己去翻文档
        config_row.main_model_base_url = (
            config_payload.get("main_model_base_url") or provider_meta.get("default_base_url") or ""
        )

        incoming_main_key = config_payload.get("main_model_api_key") or ""
        if is_new_config and not incoming_main_key:
            config_row.main_model_api_key = ""
        elif not llm_check_key_masked(incoming_main_key):
            config_row.main_model_api_key = llm_build_encrypted_key(incoming_main_key)

        config_row.advisor_model_provider = config_payload.get("advisor_model_provider") or ""
        config_row.advisor_model_name = config_payload.get("advisor_model_name") or ""
        config_row.advisor_model_base_url = config_payload.get("advisor_model_base_url") or ""
        incoming_advisor_key = config_payload.get("advisor_model_api_key") or ""
        if is_new_config and not incoming_advisor_key:
            config_row.advisor_model_api_key = ""
        elif not llm_check_key_masked(incoming_advisor_key):
            config_row.advisor_model_api_key = llm_build_encrypted_key(incoming_advisor_key)
        elif config_row.advisor_model_api_key is None:
            config_row.advisor_model_api_key = ""

        config_row.collaboration_mode = config_payload.get("collaboration_mode") or "single"
        config_row.temperature = float(config_payload.get("temperature", 0.3))
        config_row.max_tokens = int(config_payload.get("max_tokens", 4096))
        config_row.timeout = int(config_payload.get("timeout", 30))

        if config_payload.get("activate", True):
            # 先把其余配置全部置为未激活，再激活这一条。顺序反了会出现两条同时 active
            session.query(ModelConfig).filter(ModelConfig.is_active.is_(True)).update({"is_active": False})
            config_row.is_active = True

        session.commit()
        return {
            "ok": True,
            "message": "配置已保存",
            "config_id": config_row.id,
            "config_name": config_row.config_name,
        }
    finally:
        session.close()


def llm_fetch_active_config(mask_key=True):
    # 设计说明：取当前生效的那套配置
    # 为什么：一条 active 都没有时退回最新一条。页面至少能显示出用户填过什么，而不是一片空白
    session = SessionLocal()
    try:
        config_row = session.query(ModelConfig).filter(ModelConfig.is_active.is_(True)).first()
        if config_row is None:
            config_row = session.query(ModelConfig).order_by(ModelConfig.id.desc()).first()
        if config_row is None:
            return None
        return llm_build_config_dict(config_row, mask_key)
    finally:
        session.close()


def llm_fetch_config_list():
    # 设计说明：列出全部配置，供配置页做多套切换
    # 为什么：只回打码值。列表页没必要看到 Key，少一处泄露面
    session = SessionLocal()
    try:
        config_rows = session.query(ModelConfig).order_by(ModelConfig.id.desc()).all()
        return [llm_build_config_dict(config_row, mask_key=True) for config_row in config_rows]
    finally:
        session.close()


def llm_build_runtime_config(role="main"):
    # 设计说明：组装适配器要用的运行时配置，Key 是明文
    # 为什么：适配器不认数据库行，只认这么一个小字典。把"从库里取"和"怎么发请求"分开，
    #         以后换成从环境变量取配置也不会牵动适配器
    # 放弃了：role 只支持 main / advisor 两种。V1.0 就这两个角色，不做通用角色表
    active_config = llm_fetch_active_config(mask_key=False)
    if active_config is None:
        return None

    if role == "advisor" and active_config.get("collaboration_mode") == "dual":
        advisor_provider = active_config.get("advisor_model_provider") or active_config["main_model_provider"]
        advisor_meta = llm_fetch_provider(advisor_provider)
        return {
            "provider": advisor_provider,
            "api_format": advisor_meta.get("api_format", "openai_compatible"),
            "model_name": active_config.get("advisor_model_name") or active_config["main_model_name"],
            "api_key": active_config.get("advisor_model_api_key") or active_config["main_model_api_key"],
            "base_url": active_config.get("advisor_model_base_url") or active_config["main_model_base_url"],
            "temperature": active_config["temperature"],
            "max_tokens": active_config["max_tokens"],
            "timeout": active_config["timeout"],
        }

    main_meta = llm_fetch_provider(active_config["main_model_provider"])
    return {
        "provider": active_config["main_model_provider"],
        "api_format": main_meta.get("api_format", "openai_compatible"),
        "model_name": active_config["main_model_name"],
        "api_key": active_config["main_model_api_key"],
        "base_url": active_config["main_model_base_url"],
        "temperature": active_config["temperature"],
        "max_tokens": active_config["max_tokens"],
        "timeout": active_config["timeout"],
    }


def llm_export_config():
    # 设计说明：导出全部配置
    # 为什么：导出的是密文而不是明文。明文导出等于把用户的模型账号打包成文件送出去；
    #         密文至少保证"拿到文件也解不开"，只有本机同 SECRET_KEY 才导得回去
    session = SessionLocal()
    try:
        config_rows = session.query(ModelConfig).order_by(ModelConfig.id).all()
        exported_list = []
        for config_row in config_rows:
            exported_list.append({
                "config_name": config_row.config_name,
                "main_model_provider": config_row.main_model_provider,
                "main_model_name": config_row.main_model_name,
                "main_model_api_key": config_row.main_model_api_key,
                "main_model_base_url": config_row.main_model_base_url,
                "advisor_model_provider": config_row.advisor_model_provider,
                "advisor_model_name": config_row.advisor_model_name,
                "advisor_model_api_key": config_row.advisor_model_api_key,
                "advisor_model_base_url": config_row.advisor_model_base_url,
                "collaboration_mode": config_row.collaboration_mode,
                "temperature": config_row.temperature,
                "max_tokens": config_row.max_tokens,
                "timeout": config_row.timeout,
                "is_active": config_row.is_active,
            })
        return {
            "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "key_encrypted": True,
            "note": "API Key 以密文导出，只能导回同一 SECRET_KEY 的本系统",
            "configs": exported_list,
        }
    finally:
        session.close()


def llm_import_config(import_payload):
    # 设计说明：导入配置，按配置名覆盖
    # 为什么：导入的 Key 是别人的密文，本机 SECRET_KEY 不同就解不开。这时候照样保存，
    #         但在返回值里告诉用户有几条需要重填，别让他以为导完就能用
    imported_names = []
    need_refill = 0
    for config_payload in (import_payload or {}).get("configs") or []:
        save_result = llm_save_config(config_payload)
        if not save_result.get("ok"):
            continue
        imported_names.append(save_result["config_name"])
        if not llm_parse_encrypted_key(config_payload.get("main_model_api_key") or ""):
            need_refill += 1

    return {
        "imported_count": len(imported_names),
        "imported_names": imported_names,
        "need_refill_count": need_refill,
    }
