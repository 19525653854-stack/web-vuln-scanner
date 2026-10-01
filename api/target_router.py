# -*- coding: utf-8 -*-
# 设计说明：目标管理接口，负责录入和列出扫描目标
# 为什么：授权确认跟着目标走，录入时就落库，开扫前只查记录，不依赖前端那个勾选框
# 放弃了：不做目标的编辑和删除。录错了重新录一条就是，V1.0 目标量少，不值得加一套状态维护
#
# 2026-10-01 接口补挂了 token 校验。第一版忘了挂，目标列表不带令牌也能拉，
# 虽然只是内网工具，但这种口子不能开
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_router import auth_check_token
from models.database import db_get_session
from models.tables import AuditLog, Target

router = APIRouter(prefix="/target", tags=["目标管理"])


class TargetAddRequest(BaseModel):
    # 设计说明：录入目标的入参
    # 为什么：authorized 跟着一起传。授权确认必须在录入时落库，等开扫再勾就来不及了
    # 放弃了：不收备注字段。目标别名足够定位，自由文本备注 V1.0 用不上
    target_name: str = Field(min_length=1, max_length=128)
    target_url: str = Field(min_length=8, max_length=512)
    authorized: bool = False


def target_check_url(raw_url):
    # 设计说明：判断地址是不是能下手的 http(s) 地址
    # 为什么：不在这里拦住，后面的端口扫描拿到 javascript:、ftp: 这类串会直接崩
    # 放弃了：不做存活探测。录目标不代表马上扫，目标暂时连不上是正常情况
    parsed_url = urlparse(raw_url)
    if parsed_url.scheme not in ("http", "https"):
        return False
    return bool(parsed_url.netloc)


@router.post("/add")
def target_create_record(
    add_request: TargetAddRequest,
    session: Session = Depends(db_get_session),
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：录入一个扫描目标
    # 为什么：重复目标按 URL 拦。不拦的话任务页同一个地址出现好几遍，分不清哪条是哪条
    # 放弃了：不自动抓页面标题补别名。多一次网络请求，录入就变慢了
    if not target_check_url(add_request.target_url):
        return {"code": 1, "msg": "URL格式不对，得带 http:// 或 https://"}

    exists_row = session.query(Target).filter(Target.target_url == add_request.target_url).first()
    if exists_row:
        return {"code": 1, "msg": "这个目标已经录过了，编号 %s" % exists_row.id}

    new_target = Target(
        target_name=add_request.target_name,
        target_url=add_request.target_url,
        authorized_flag=add_request.authorized,
        # 没勾授权就不写时间。空值比塞一个默认时间诚实，事后查证也分得清
        authorized_at=datetime.now() if add_request.authorized else None,
    )
    session.add(new_target)
    # 录目标也算一次系统操作，进审计日志。谁在什么时候录的、勾没勾授权，都得能查
    session.add(AuditLog(
        log_type="system",
        log_content="录入扫描目标 %s" % add_request.target_url,
        log_reason="操作者 %s，授权确认 %s" % (current_user, "已勾选" if add_request.authorized else "未勾选"),
    ))
    session.commit()

    return {
        "code": 0,
        "data": {
            "id": new_target.id,
            "target_name": new_target.target_name,
            "target_url": new_target.target_url,
            "authorized": new_target.authorized_flag,
        },
    }


@router.get("/list")
def target_fetch_list(
    session: Session = Depends(db_get_session),
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：列出全部目标
    # 为什么：按创建时间倒序。使用者最关心刚录的那条，正序的话录十条以后得翻到最后一页
    # 放弃了：不做分页。V1.0 的目标量到不了需要分页的程度
    target_rows = session.query(Target).order_by(Target.created_at.desc()).all()
    return {
        "code": 0,
        "data": [
            {
                "id": row.id,
                "target_name": row.target_name,
                "target_url": row.target_url,
                "authorized": row.authorized_flag,
                "created_at": row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else None,
            }
            for row in target_rows
        ],
    }
