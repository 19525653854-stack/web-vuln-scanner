# -*- coding: utf-8 -*-
# 设计说明：数据库连接与会话管理，全项目只有这里建 engine
# 为什么：engine 建多份会各自维护一套连接池，SQLite 下还会互相抢文件锁
# 放弃了：不上连接池调参，本地单文件库没这个必要
#
# 2026-10-01 补了外键开关。加索引那会儿顺手写了 ForeignKey，测试时插一条 job_id 不存在的
# 漏洞记录，居然插进去了，查文档才知道 SQLite 默认不校验外键
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATABASE_URL

# 不关掉这个线程检查会随机报 "SQLite objects created in a thread can only be used in that same thread"，
# 因为 FastAPI 的同步接口实际跑在线程池里，跟建连接的那个线程不是同一个
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


@event.listens_for(engine, "connect")
def db_enable_sqlite_foreign_key(dbapi_connection, connection_record):
    # 设计说明：把 SQLite 的外键校验打开
    # 为什么：SQLite 默认把外键当摆设。不显式打开的话，模型里那些 ForeignKey 一条都不生效，
    #         脏数据插进去不报错，等报告里冒出对不上号的记录才发现
    # 放弃了：不额外写触发器兜底，靠建表时声明的 ondelete=CASCADE 就够
    #
    # 注意这里是"每建立一条物理连接"执行一次，不是启动一次。连接池回收后重建连接还得再开
    if not DATABASE_URL.startswith("sqlite"):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def db_get_session():
    # 设计说明：请求级数据库会话，给 FastAPI 依赖注入用
    # 为什么：一个请求一个会话，处理完立刻关。共用一个话，慢查询会把连接一直占着
    # 放弃了：不做断线自动重连，本地 SQLite 用不上这套
    session = SessionLocal()
    try:
        yield session
    finally:
        # 用 finally 不用 except：异常路径也得关，否则一出错连接就漏了
        session.close()


def db_create_tables():
    # 设计说明：建表入口，启动时调一次
    # 为什么：集中一处建表，免得以后每个 router 各建各的，改字段时找不到地方
    # 放弃了：不上 Alembic 迁移。V1.0 表结构还在动，直接删库重建比写迁移脚本快
    #
    # 必须先把 tables 模块 import 进来：Base 见过类定义才知道有哪些表，
    # 否则 create_all 一张表都不建，而且不抛异常，最费时间
    import models.tables  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # 2026-10-01 改成返回表名。之前启动日志只写"数据表已就绪"，到底建出来几张谁也看不出
    return sorted(Base.metadata.tables.keys())
