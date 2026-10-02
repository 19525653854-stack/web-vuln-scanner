# -*- coding: utf-8 -*-
# 设计说明：漏洞列表路由，给漏洞列表页提供查询、筛选和统计
# 为什么：漏洞是这套系统最终要交付的东西。列表页要按任务、按等级、按类型自由组合筛选，
#         筛选放在后端算，前端只管显示，翻页时也不用把全量数据拉到浏览器里
# 放弃了：不做关键词全文检索。漏洞是几十条的量级，按三个字段筛就够用
from fastapi import APIRouter, Depends
from sqlalchemy import case, func

from api.auth_router import auth_check_token
from models.database import SessionLocal
from models.tables import Finding

router = APIRouter(prefix="/finding", tags=["漏洞"])

# 一页最多给这么多条。前端传超了会把整页卡住，后端封个顶
MAX_PAGE_SIZE = 100

# 等级排序权。高危永远排最前面，其次中危，认不出来的等级排最后
LEVEL_RANK_PAIRS = {"high": 0, "medium": 1, "low": 2}


def finding_build_item(finding_row):
    # 设计说明：把漏洞行转成接口返回的字典
    # 为什么：证据和修复建议可能很长，列表页放不下。这里不截断，交给前端按需折叠——
    #         后端截断了详情弹窗就没得看了
    return {
        "finding_id": finding_row.id,
        "job_id": finding_row.job_id,
        "vuln_type": finding_row.vuln_type,
        "vuln_level": finding_row.vuln_level,
        "vuln_url": finding_row.vuln_url,
        "raw_payload": finding_row.raw_payload,
        "raw_evidence": finding_row.raw_evidence,
        "confidence": finding_row.confidence,
        "validate_reason": finding_row.validate_reason,
        "fix_suggestion": finding_row.fix_suggestion,
        "created_at": finding_row.created_at.strftime("%Y-%m-%d %H:%M:%S") if finding_row.created_at else "",
    }


def finding_build_filters(job_id, vuln_level, vuln_type):
    # 设计说明：把三个筛选条件拼成查询条件列表
    # 为什么：三个条件可以任意组合，写成列表逐条叠加比写一堆 if 分支清楚
    # 放弃了：不支持按时间范围筛。报告是按任务出的，时间范围这个维度用不上
    filter_conditions = []
    if job_id:
        filter_conditions.append(Finding.job_id == job_id)
    if vuln_level:
        filter_conditions.append(Finding.vuln_level == vuln_level)
    if vuln_type:
        filter_conditions.append(Finding.vuln_type == vuln_type)
    return filter_conditions


@router.get("/list")
def finding_fetch_list(
    job_id: int = 0,
    vuln_level: str = "",
    vuln_type: str = "",
    page_index: int = 1,
    page_size: int = 20,
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：分页查漏洞列表
    # 为什么：默认按等级再按编号倒序。看漏洞的人第一眼要看高危，最新发现的排前面
    # 放弃了：不做服务端导出 Excel。报告那条路已经能出 PDF 了，再加一种导出格式是重复投入
    page_index = max(page_index, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))

    session = SessionLocal()
    try:
        filter_conditions = finding_build_filters(job_id, vuln_level, vuln_type)
        base_query = session.query(Finding).filter(*filter_conditions)
        total_count = base_query.count()

        level_rank = case(LEVEL_RANK_PAIRS, value=Finding.vuln_level, else_=9)
        finding_rows = (
            base_query.order_by(level_rank, Finding.id.desc())
            .offset((page_index - 1) * page_size)
            .limit(page_size)
            .all()
        )

        return {
            "code": 0,
            "data": {
                "total": total_count,
                "page_index": page_index,
                "page_size": page_size,
                "items": [finding_build_item(finding_row) for finding_row in finding_rows],
            },
        }
    finally:
        session.close()


@router.get("/summary")
def finding_fetch_summary(
    job_id: int = 0,
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：给列表页顶部那几块统计卡片和筛选项供数
    # 为什么：等级分布和可选类型都要让后端算。让前端从当前页数据里统计，翻页数字就变了
    session = SessionLocal()
    try:
        level_query = session.query(Finding.vuln_level, func.count(Finding.id))
        type_query = session.query(Finding.vuln_type, func.count(Finding.id))
        if job_id:
            level_query = level_query.filter(Finding.job_id == job_id)
            type_query = type_query.filter(Finding.job_id == job_id)

        level_counts = {"high": 0, "medium": 0, "low": 0, "other": 0}
        for level_value, level_count in level_query.group_by(Finding.vuln_level).all():
            level_key = str(level_value or "").lower()
            if level_key in level_counts:
                level_counts[level_key] = level_count
            else:
                level_counts["other"] += level_count

        type_rows = type_query.group_by(Finding.vuln_type).all()
        return {
            "code": 0,
            "data": {
                "total": sum(level_counts.values()),
                "level_counts": level_counts,
                "vuln_type_list": [
                    {"vuln_type": type_value, "count": type_count}
                    for type_value, type_count in sorted(type_rows, key=lambda item: -item[1])
                ],
            },
        }
    finally:
        session.close()


@router.get("/detail/{finding_id}")
def finding_fetch_detail(finding_id: int, current_user: str = Depends(auth_check_token)):
    # 设计说明：取单条漏洞的全部字段
    # 为什么：列表里只显示摘要，证据原文和修复建议要点开才看，这一条接口就是给弹窗用的
    session = SessionLocal()
    try:
        finding_row = session.query(Finding).filter(Finding.id == finding_id).first()
        if finding_row is None:
            return {"code": 1, "msg": "这条漏洞记录不存在"}
        return {"code": 0, "data": finding_build_item(finding_row)}
    finally:
        session.close()
