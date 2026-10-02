# -*- coding: utf-8 -*-
# 设计说明：应用入口，只做装配。业务逻辑全落在各自模块里，入口只负责把它们拼起来
# 为什么：业务细节堆在入口，main.py 早晚膨胀成几千行；拆出去之后入口只读得懂结构，不读细节
# 放弃了：不在这里顺手写几个接口图省事，宁可每次多写一行 include_router
#
# 2026-10-02 把 CORS、全局异常、健康检查、日志配置拆到独立模块（api/middleware.py、
# api/errors.py、api/health_router.py、core/logger.py），入口只留装配调用和启动事件
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.auth_router import auth_create_default_user
from api.auth_router import router as auth_router
from api.config_router import router as config_router
from api.errors import setup_error_handlers
from api.finding_router import router as finding_router
from api.health_router import router as health_router
from api.job_router import router as job_router
from api.middleware import setup_cors
from api.report_router import router as report_router
from api.target_router import router as target_router
from config import APP_NAME, APP_VERSION
from core.logger import core_setup_logging
from models.database import db_create_tables
from skills.skill_manager import skill_load_all_scripts, skill_load_metadata
from tools.job_scheduler import job_start_scheduler, job_stop_scheduler

logger = core_setup_logging()


@asynccontextmanager
async def app_run_lifespan(app_instance: FastAPI):
    # 设计说明：生命周期钩子，启动时建表、灌默认账号、加载技能、起调度器，退出时停调度器
    # 为什么：用 lifespan 而不是 @app.on_event，后者在新版 FastAPI 里已经标了弃用，一启动就刷警告
    # 放弃了：不做优雅停机。V1.0 的扫描任务本来就允许中断后重跑，没必要为此加信号处理
    table_names = db_create_tables()
    # 表名一起打出来。之前只打"数据表已就绪"，出问题根本看不出是没建还是建失败
    logger.info("数据表已就绪，共 %s 张：%s", len(table_names), ", ".join(table_names))

    default_user_name = auth_create_default_user()
    if default_user_name:
        logger.info("首次启动，已创建默认账号 %s，部署后记得改密码", default_user_name)

    # 技能元数据要赶在调度器之前加载。任务一进来就得能匹配到技能，晚一步就得干等
    skill_load_metadata()

    # 技能脚本紧跟着全部加载。脚本里的 tool_register 是能力注册，不加载的话规划器
    # 看到的工具清单是残缺的，模型只能靠猜工具名
    skill_load_all_scripts()

    # 调度器放在建表之后启动。倒过来它可能先于表去接任务，第一条任务就得失败
    job_start_scheduler()

    logger.info("%s %s 启动完成", APP_NAME, APP_VERSION)
    yield

    job_stop_scheduler()
    logger.info("服务已停止")


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=app_run_lifespan)

# 下面是装配。跨域、错误处理、各业务路由的实现都在各自模块里，这里只做挂载
setup_cors(app)
setup_error_handlers(app)
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(target_router)
app.include_router(job_router)
app.include_router(config_router)
app.include_router(report_router)
app.include_router(finding_router)
