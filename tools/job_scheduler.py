# -*- coding: utf-8 -*-
# 设计说明：扫描任务调度器，负责任务排队和并发上限
# 为什么：FastAPI 自带的 BackgroundTasks 没有并发控制，10 个人同时点开扫就会 10 路并发直接怼到目标上；
#         用调度器的线程池把并发压在配置的上限里，超出的老老实实排队
# 放弃了：不上 Celery、RQ 那套消息队列。V1.0 单机跑，进程内线程池就够，引队列纯属折腾
#
# 2026-10-01 调度器随任务接口一起加进来。最初打算直接 BackgroundTasks，
# 后来想到限速配置写在 config 里却没人执行，等于白写
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler

from config import SCAN_MAX_CONCURRENCY
from models.database import SessionLocal
from models.tables import AuditLog, Job, Target

logger = logging.getLogger("ai_scanner.job")

# 并发数直接读 config 的安全约束，这里不再单独配一份。改一处就够，两处迟早改岔
scan_scheduler = BackgroundScheduler(
    executors={"default": ThreadPoolExecutor(SCAN_MAX_CONCURRENCY)},
    job_defaults={"coalesce": True, "max_instances": 1},
)


def job_start_scheduler():
    # 设计说明：启动调度器，应用生命周期里调一次
    # 为什么：不在 import 这个模块时就 start。单元测试导一下模块就会把线程池带起来，泄漏线程
    # 放弃了：不做调度器自身的健康监控。线程池挂了任务状态会停在 pending，肉眼就能发现
    if not scan_scheduler.running:
        scan_scheduler.start()
        logger.info("任务调度器已启动，并发上限 %s 路", SCAN_MAX_CONCURRENCY)


def job_stop_scheduler():
    # 设计说明：停调度器
    # 为什么：shutdown 不等任务跑完（wait=False）。等的话，一个卡死的任务能把整个进程拖住退不出去
    if scan_scheduler.running:
        scan_scheduler.shutdown(wait=False)
        logger.info("任务调度器已停止")


def job_submit_scan(job_id):
    # 设计说明：把任务丢进调度队列，立即返回，不阻塞接口
    # 为什么：add_job 带上 id。同一个任务被重复提交时 APScheduler 会抛冲突，正好替我们拦一道
    # 放弃了：不做优先级。先来后到就够了，V1.0 没有插队的场景
    scan_scheduler.add_job(
        job_run_scan,
        args=[job_id],
        id="scan-%s" % job_id,
    )
    logger.info("任务 %s 已进入调度队列", job_id)


def job_run_scan(job_id):
    # 设计说明：任务执行入口，走完一整条状态流转 pending -> running -> done / failed
    # 为什么：这里自己开会话。后台线程拿不到请求级的会话，用请求结束就关掉的会话必炸
    # 放弃了：不做断点续扫。中断的任务直接标 failed 重开一单，比存进度便宜
    session = SessionLocal()
    try:
        job_row = session.query(Job).filter(Job.id == job_id).first()
        if job_row is None:
            # 调度器拿到不存在的任务号，多半是库被手工动过，记下来别让它悄悄吞掉
            logger.error("任务 %s 不存在，调度器拿到了脏数据", job_id)
            return

        job_row.current_job_status = "running"
        job_row.started_at = datetime.now()
        session.commit()
        logger.info("任务 %s 开始执行", job_id)

        total_round = job_execute_pipeline(job_row, session)

        job_row.current_job_status = "done"
        job_row.total_round = total_round
        job_row.finished_at = datetime.now()
        session.add(AuditLog(
            job_id=job_id,
            log_type="system",
            log_content="任务 %s 执行完成" % job_id,
            log_reason="共 %s 轮" % total_round,
        ))
        session.commit()
        logger.info("任务 %s 执行完成，共 %s 轮", job_id, total_round)
    except Exception as scan_error:
        session.rollback()
        # 失败也得把状态落库。直接往外抛的话任务会永远停在 running，页面上躺着一条僵尸任务
        failed_row = session.query(Job).filter(Job.id == job_id).first()
        if failed_row is not None:
            failed_row.current_job_status = "failed"
            failed_row.finished_at = datetime.now()
            session.add(AuditLog(
                job_id=job_id,
                log_type="system",
                log_content="任务 %s 执行失败" % job_id,
                log_reason=str(scan_error)[:200],
            ))
            session.commit()
        logger.error("任务 %s 执行失败：%s", job_id, scan_error)
    finally:
        session.close()


def job_execute_pipeline(job_row, session):
    # 设计说明：扫描管线，逐轮推进，返回实际执行的轮数
    # 为什么：侦察必须是第一轮。后面所有测试都要靠这轮摸到的端口分布决定测什么
    # 放弃了：不做侦察结果缓存。同一个目标隔几天重扫，缓存的端口可能已经变了
    #
    # TODO(注缘): PSV 循环接进来之后，这里改成由规划器决定每轮做什么，别再写死顺序
    # V1.0 先把第一轮端口扫描接进来，后面的技能逐个模块补
    #
    # 先让工具模块完成自我注册。只 import 不调用，import 时模块底部的 tool_register 就执行了
    import tools.port_tool  # noqa: F401
    from tools.tool_registry import tool_invoke

    target_row = session.query(Target).filter(Target.id == job_row.target_id).first()
    target_host = urlparse(target_row.target_url).hostname
    if not target_host:
        # 地址里连主机名都没有，属于脏数据，直接报错走 failed，别闷头扫下去
        raise ValueError("目标地址里取不到主机名：%s" % target_row.target_url)

    # 第一轮固定做端口扫描。先摸清暴露面，后面才有得测
    open_ports = tool_invoke("port_scan", raw_host=target_host)

    job_row.current_round = 1
    # 侦察结果存进计划快照。报告要复盘"当时摸到了什么"，全靠这份快照
    job_row.plan_snapshot = json.dumps(
        {"recon": {"host": target_host, "open_ports": open_ports}},
        ensure_ascii=False,
    )
    session.add(AuditLog(
        job_id=job_row.id,
        log_type="tool",
        log_content="端口扫描完成：%s" % target_host,
        log_reason="开放端口 %s 个" % len(open_ports),
    ))
    session.commit()
    return 1
