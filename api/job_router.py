# -*- coding: utf-8 -*-
# 设计说明：任务管理接口，负责创建扫描任务和查询任务状态
# 为什么：开扫前的授权校验必须放在服务端。前端那个勾选框只挡君子，绕过页面就形同虚设
# 放弃了：不做任务取消接口。V1.0 任务都跑得快，取消带来的状态复杂度不值得
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.auth_router import auth_check_token
from models.database import db_get_session
from models.tables import AuditLog, Job, Target
from tools.job_scheduler import job_submit_scan

router = APIRouter(prefix="/job", tags=["任务管理"])


class JobCreateRequest(BaseModel):
    # 设计说明：创建任务的入参
    # 为什么：只收 target_id。目标地址这些信息都在目标表里，接口再收一遍迟早出现两边对不上的情况
    # 放弃了：不收扫描参数（选测哪些漏洞类型）。V1.0 由智能体根据侦察结果自己决定测什么
    target_id: int


@router.post("/create")
def job_create_scan(
    create_request: JobCreateRequest,
    session: Session = Depends(db_get_session),
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：为一个已录入的目标创建扫描任务
    # 为什么：没勾授权的目标在这里硬拦。授权确认是合规底线，绕过它开扫等于把系统变成攻击工具
    # 放弃了：不做定时扫描。任务都是手动触发的，定时偷扫别人家不是这个系统该干的事
    target_row = session.query(Target).filter(Target.id == create_request.target_id).first()
    if target_row is None:
        return {"code": 1, "msg": "目标不存在，先去目标页录入"}

    if not target_row.authorized_flag:
        return {"code": 1, "msg": "这个目标还没确认测试授权，勾完授权再来开扫"}

    # 同一目标同时在跑两个任务，漏洞和报告就会对不上号，这里直接拦掉
    running_row = session.query(Job).filter(
        Job.target_id == target_row.id,
        Job.current_job_status.in_(["pending", "running"]),
    ).first()
    if running_row is not None:
        return {"code": 1, "msg": "这个目标还有任务 %s 在跑，等它结束再开" % running_row.id}

    new_job = Job(target_id=target_row.id, current_job_status="pending")
    session.add(new_job)
    session.add(AuditLog(
        log_type="decision",
        log_content="创建扫描任务，目标 %s" % target_row.target_url,
        log_reason="操作者 %s，目标授权确认于 %s" % (current_user, target_row.authorized_at),
    ))
    session.commit()

    # 必须先 commit 再进队列。倒过来的话后台线程可能抢在落库前查这条任务，拿到一个空
    job_submit_scan(new_job.id)

    return {
        "code": 0,
        "data": {"job_id": new_job.id, "status": new_job.current_job_status},
    }


@router.get("/status/{job_id}")
def job_fetch_status(
    job_id: int,
    session: Session = Depends(db_get_session),
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：查单个任务的执行状态
    # 为什么：前端轮询进度全靠这个接口，把轮次一起带出去，页面才画得出进度条
    # 放弃了：不上 WebSocket 实时推送。轮询对这个量级够用，复杂度差一个量级
    job_row = session.query(Job).filter(Job.id == job_id).first()
    if job_row is None:
        return {"code": 1, "msg": "任务不存在"}

    return {
        "code": 0,
        "data": {
            "job_id": job_row.id,
            "target_id": job_row.target_id,
            "status": job_row.current_job_status,
            "current_round": job_row.current_round,
            "total_round": job_row.total_round,
            "started_at": job_row.started_at.strftime("%Y-%m-%d %H:%M:%S") if job_row.started_at else None,
            "finished_at": job_row.finished_at.strftime("%Y-%m-%d %H:%M:%S") if job_row.finished_at else None,
        },
    }
