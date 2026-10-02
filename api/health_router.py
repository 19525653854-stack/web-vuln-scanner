# -*- coding: utf-8 -*-
# 设计说明：健康检查与根路径提示
# 为什么：单独走一个不碰数据库的轻接口。要是拿查库的接口做健康检查，库一卡这里跟着超时，
#         会被误判成服务挂了，然后白白重启一遍
# 放弃了：不在这里校验模型连通性，那是 /config/test 的活
from fastapi import APIRouter

from config import APP_NAME, APP_VERSION

router = APIRouter(tags=["健康检查"])


@router.get("/health")
def health_fetch_status():
    # 设计说明：健康检查接口
    # 为什么：库卡了不该连累它，所以什么资源都不碰，纯粹证明进程还活着
    return {
        "code": 0,
        "data": {"name": APP_NAME, "version": APP_VERSION, "status": "ok"},
    }


@router.get("/")
def health_fetch_root():
    # 设计说明：根路径提示
    # 为什么：有人直接开浏览器访问根路径，看到 404 会以为服务没起来，甚至反复重启
    # 放弃了：不做前端首页跳转，前后端分开部署更省事
    return {"code": 0, "data": "服务已启动，接口文档见 /docs"}
