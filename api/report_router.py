# -*- coding: utf-8 -*-
# 设计说明：报告路由，负责生成和下载 PDF 报告
# 为什么：生成慢、下载频繁，两者分开更清楚；报告是最终交付物，得有独立的入口
# 放弃了：不做后台异步生成。一份报告几百毫秒就出来了，不值得为它加一套任务机制
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.auth_router import auth_check_token
from report.report_builder import report_build_pdf, report_fetch_file_list, report_fetch_latest_file

router = APIRouter(prefix="/report", tags=["报告"])


class ReportGenerateRequest(BaseModel):
    # 设计说明：生成报告的入参
    # 为什么：只收 job_id。报告内容全部从库里取，接口再收一遍就成了两个数据源
    # 放弃了：不支持自定义报告标题、页眉这些。V1.0 版式写死，需要定制再说
    job_id: int


@router.post("/generate")
def report_run_generate(
    generate_request: ReportGenerateRequest,
    current_user: str = Depends(auth_check_token),
):
    # 设计说明：为一个任务生成报告
    # 为什么：允许反复生成。版式改了不用重跑扫描，直接重出一份就行
    generate_result = report_build_pdf(generate_request.job_id)
    if not generate_result.get("ok"):
        return {"code": 1, "msg": generate_result.get("message")}
    return {"code": 0, "msg": generate_result["message"], "data": generate_result}


@router.get("/download/{job_id}")
def report_run_download(job_id: int, current_user: str = Depends(auth_check_token)):
    # 设计说明：下载某个任务最新生成的那份报告
    # 为什么：下载头里的文件名用英文。中文文件名在 Content-Disposition 里得额外做编码，
    #         处理不好浏览器收到的就是一堆百分号乱码
    report_path = report_fetch_latest_file(job_id)
    if report_path is None:
        return {"code": 1, "msg": "这个任务还没生成过报告，先生成再下载"}

    return FileResponse(
        str(report_path),
        media_type="application/pdf",
        filename="scan_report_job%s.pdf" % job_id,
    )


@router.get("/list")
def report_fetch_report_list(current_user: str = Depends(auth_check_token)):
    # 设计说明：列出已生成的全部报告
    # 为什么：报告页得能看出"都出过哪些报告"，光给一个下载按钮不够用
    return {"code": 0, "data": report_fetch_file_list()}
