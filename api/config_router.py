# -*- coding: utf-8 -*-
# 设计说明：模型配置路由，对应方案 5.6 的接口清单
# 为什么：配置全落库、Key 加密存、切模型只改数据不动代码——这是"不写死任何模型"的落点
# 放弃了：不做配置的权限分级。V1.0 只有管理员一个身份，能登录就能改配置
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.auth_router import auth_check_token
from llm.model_adapter import llm_check_connection
from llm.model_config import (
    llm_check_key_masked,
    llm_export_config,
    llm_fetch_active_config,
    llm_fetch_config_list,
    llm_import_config,
    llm_save_config,
)
from llm.model_registry import llm_fetch_model_names, llm_fetch_provider, llm_fetch_providers

router = APIRouter(prefix="/config", tags=["模型配置"])

# 连通性测试只让模型回两个字，max_tokens 给 64 就够。
# 给大了万一模型话痨，测试一次白烧一段额度
CONNECTION_TEST_MAX_TOKENS = 64


class ModelConfigRequest(BaseModel):
    # 设计说明：保存配置的入参
    # 为什么：字段名跟表结构一一对应。中间再起一层别名，排查问题时要在两个名字之间来回对
    # 放弃了：不给厂商和模型名加枚举校验。自定义厂商填什么都有可能，写死枚举反而把人挡住
    config_name: str = Field(min_length=1, max_length=64)
    main_model_provider: str = Field(default="custom", max_length=32)
    main_model_name: str = Field(default="", max_length=64)
    main_model_api_key: str = Field(default="", max_length=512)
    main_model_base_url: str = Field(default="", max_length=256)
    advisor_model_provider: str = Field(default="", max_length=32)
    advisor_model_name: str = Field(default="", max_length=64)
    advisor_model_api_key: str = Field(default="", max_length=512)
    advisor_model_base_url: str = Field(default="", max_length=256)
    collaboration_mode: str = "single"
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 30
    activate: bool = True


class ConnectionTestRequest(BaseModel):
    # 设计说明：连通性测试的入参，允许直接传还没保存的配置
    # 为什么：能先测通再保存。不然用户得先存一套错的配置、再回来改，来回折腾
    main_model_provider: str = Field(default="custom", max_length=32)
    main_model_name: str = Field(default="", max_length=64)
    main_model_api_key: str = Field(default="", max_length=512)
    main_model_base_url: str = Field(default="", max_length=256)


class ConfigImportRequest(BaseModel):
    # 设计说明：导入入参，结构就是导出文件里的 configs 那一段
    configs: list[dict] = []


@router.get("/presets")
def config_fetch_presets(current_user: str = Depends(auth_check_token)):
    # 设计说明：预置厂商清单
    # 为什么：厂商清单前端不该自己写一份。写两份的结果是后端加了个厂商，前端还是选不到
    return {"code": 0, "data": llm_fetch_providers()}


@router.get("/models")
def config_fetch_models(provider: str = "", current_user: str = Depends(auth_check_token)):
    # 设计说明：取某厂商的预置模型名
    # 为什么：配置页换厂商时模型下拉框要联动刷新，数据源就是这里
    return {"code": 0, "data": llm_fetch_model_names(provider)}


@router.get("/current")
def config_fetch_current(current_user: str = Depends(auth_check_token)):
    # 设计说明：当前生效的配置，Key 已打码
    # 为什么：打码是这里的默认行为。真需要明文的地方（发请求）走 llm_build_runtime_config，
    #         不走接口，免得密钥从 HTTP 里漏出去
    active_config = llm_fetch_active_config(mask_key=True)
    if active_config is None:
        return {"code": 1, "msg": "还没有配置过模型，先在配置页填一套"}
    return {"code": 0, "data": active_config}


@router.get("/list")
def config_fetch_config_list(current_user: str = Depends(auth_check_token)):
    # 设计说明：列出全部配置，支持多套之间切换
    # 为什么：只回打码值。列表页没必要看到 Key，少开一处泄露面
    return {"code": 0, "data": llm_fetch_config_list()}


@router.post("/save")
def config_run_save(save_request: ModelConfigRequest, current_user: str = Depends(auth_check_token)):
    # 设计说明：保存配置，按配置名覆盖或新建
    # 为什么：Key 是打码值时保留库里原有的密文。不做这一步，用户只改温度也会把 Key 覆盖成 ****
    save_result = llm_save_config(save_request.model_dump())
    if not save_result.get("ok"):
        return {"code": 1, "msg": save_result.get("message")}

    return {
        "code": 0,
        "msg": save_result["message"],
        "data": {
            "config_id": save_result["config_id"],
            "config_name": save_result["config_name"],
        },
    }


@router.post("/test")
def config_run_connection_test(
    test_request: ConnectionTestRequest,
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：连通性测试
    # 为什么：允许用还没保存的配置去测。测通了再保存，省一轮来回
    # 放弃了：不并发测多个厂商。一次测一家，界面上一个按钮一条结果更清楚
    provider_meta = llm_fetch_provider(test_request.main_model_provider)
    test_config = {
        "provider": test_request.main_model_provider,
        "api_format": provider_meta.get("api_format", "openai_compatible"),
        "model_name": test_request.main_model_name,
        "api_key": test_request.main_model_api_key,
        "base_url": test_request.main_model_base_url or provider_meta.get("default_base_url", ""),
        "temperature": 0.3,
        "max_tokens": CONNECTION_TEST_MAX_TOKENS,
        "timeout": 30,
    }

    # 前端回显的是打码值，这种情况要拿库里存的那把真 Key 去测
    if llm_check_key_masked(test_request.main_model_api_key):
        active_config = llm_fetch_active_config(mask_key=False)
        test_config["api_key"] = (active_config or {}).get("main_model_api_key") or ""

    if not test_config["base_url"]:
        return {"code": 1, "msg": "Base URL 是空的，自定义厂商得自己填地址"}

    test_result = llm_check_connection(test_config)
    return {
        "code": 0 if test_result["success"] else 1,
        "msg": test_result["message"],
        "data": test_result,
    }


@router.post("/export")
def config_run_export(current_user: str = Depends(auth_check_token)):
    # 设计说明：导出全部配置
    # 为什么：导出的是密文。明文导出等于把用户的模型账号打包成文件送出去
    return {"code": 0, "data": llm_export_config()}


@router.post("/import")
def config_run_import(
    import_request: ConfigImportRequest,
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：导入配置
    # 为什么：导入的 Key 是别的机器加密的，本机 SECRET_KEY 不同就解不开。照样存下来，
    #         但把"有几条需要重填"告诉用户，别让他以为导完就能直接用
    import_result = llm_import_config(import_request.model_dump())
    return {
        "code": 0,
        "msg": "导入 %s 条，其中 %s 条的 Key 需要重新填" % (
            import_result["imported_count"], import_result["need_refill_count"]),
        "data": import_result,
    }
