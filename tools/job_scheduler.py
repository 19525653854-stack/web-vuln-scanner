# -*- coding: utf-8 -*-
# 设计说明：扫描任务调度器，负责任务排队和并发上限
# 为什么：FastAPI 自带的 BackgroundTasks 没有并发控制，10 个人同时点开扫就会 10 路并发直接怼到目标上；
#         用调度器的线程池把并发压在配置的上限里，超出的老老实实排队
# 放弃了：不上 Celery、RQ 那套消息队列。V1.0 单机跑，进程内线程池就够，引队列纯属折腾
#
# 2026-10-01 调度器随任务接口一起加进来。最初打算直接 BackgroundTasks，
# 后来想到限速配置写在 config 里却没人执行，等于白写
import logging
from datetime import datetime

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler

from config import SCAN_MAX_CONCURRENCY
from models.database import SessionLocal
from models.tables import AuditLog, Job

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
    # 设计说明：扫描管线骨架，逐轮推进，返回实际执行的轮数
    # 为什么：先把结构立起来。端口扫描、指纹识别这些技能后面逐个模块接进来，插的位置就是这里
    # 放弃了：不做轮次之间的休眠。限速由每个技能自己控制，调度层再睡就成双重限速了
    #
    # TODO(开发者): 端口扫描模块接进来之后，这里改成真正按技能逐轮执行
    # V1.0 当前技能列表还是空的，走零轮直接收尾，先把状态流转跑通
    return 0
