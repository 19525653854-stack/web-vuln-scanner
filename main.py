# -*- coding: utf-8 -*-
# 设计说明：应用入口，只负责建应用、挂中间件、启动时初始化数据库
# 为什么：业务路由全部挂在 api/ 下，入口文件只管组装；不然 main.py 早晚膨胀成几千行
# 放弃了：不在这里顺手写几个接口图省事，V1.0 宁可每次多写一行 include_router
#
# 2026-09-30 补上 app_ 前缀。之前这几个函数都是裸名（health_check、root_index），
# 跟全项目"模块前缀 + 动作动词 + 对象"的写法对不上
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import APP_NAME, APP_VERSION
from models.database import db_create_tables

# 单进程用 basicConfig 就够了，真上多进程再换结构化日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("ai_scanner")


@asynccontextmanager
async def app_run_lifespan(app: FastAPI):
    # 设计说明：生命周期钩子，启动时建表，退出时打一行日志
    # 为什么：用 lifespan 而不是 @app.on_event，后者在新版 FastAPI 里已经标了弃用，一启动就刷警告
    # 放弃了：不做优雅停机。V1.0 的扫描任务本来就允许中断后重跑，没必要为此加信号处理
    table_names = db_create_tables()
    # 表名一起打出来。之前只打"数据表已就绪"，出问题根本看不出是没建还是建失败
    logger.info("数据表已就绪，共 %s 张：%s", len(table_names), ", ".join(table_names))
    logger.info("%s %s 启动完成", APP_NAME, APP_VERSION)
    yield
    logger.info("服务已停止")


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=app_run_lifespan)

# 前端跑在 5173，不放通配浏览器会把请求全拦掉。这是开发期写法
# TODO(开发者): 交付前把 allow_origins 收敛成实际前端地址，别再留着通配
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def app_health_check():
    # 设计说明：健康检查接口
    # 为什么：单独走一个不碰数据库的轻接口。要是拿查库的接口做健康检查，库一卡这里跟着超时，
    #         会被误判成服务挂了，然后白白重启一遍
    # 放弃了：不在这里校验模型连通性，那是 /config/test 的活
    return {
        "code": 0,
        "data": {"name": APP_NAME, "version": APP_VERSION, "status": "ok"},
    }


@app.get("/")
def app_root_index():
    # 设计说明：根路径返回一句提示
    # 为什么：有人直接开浏览器访问根路径，看到 404 会以为服务没起来，甚至反复重启
    # 放弃了：不做前端首页跳转，前后端分开部署更省事
    return {"code": 0, "data": "服务已启动，接口文档见 /docs"}
