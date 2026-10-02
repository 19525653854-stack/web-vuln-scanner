# -*- coding: utf-8 -*-
# 设计说明：全局异常处理。把 FastAPI 默认的 {"detail": ...} 统一成约定的 {"code":1,"msg":...}
# 为什么：前端只写一套取错逻辑就够了，不用一处看 detail、一处看 msg。
#         这个约定要是不统一，前端每加一个页面都得在两种错误格式之间挑
# 放弃了：不做异常类型的细分返回。错误提示尽量统一，细分会增加前端的判断分支
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


def setup_error_handlers(app_instance: FastAPI):
    # 设计说明：把异常处理器挂到应用上
    # 为什么：挂哪一类、返回什么结构是装配决策，写在一处比散在入口文件清楚
    # 放弃了：不在这里记审计日志，鉴权失败的噪声太大，真要查有访问日志

    @app_instance.exception_handler(HTTPException)
    async def error_build_response(request: Request, exc: HTTPException):
        # 统一返回 {"code":1,"msg":...}。具体错误文字用后端写好的那句人话，别再二次包装
        return JSONResponse(status_code=exc.status_code, content={"code": 1, "msg": exc.detail})
