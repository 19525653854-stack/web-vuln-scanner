# -*- coding: utf-8 -*-
# 设计说明：跨域配置。前端跑在 5173，不放通配浏览器会把请求全拦掉
# 为什么：源、方法、头怎么放是装配决策，写在一处比散在入口文件清楚；
#         以后收敛成真实前端地址时也只改这一处
# 放弃了：不用环境变量配源。V1.0 就本机一个前端，做成配置化的成本没必要
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


def setup_cors(app_instance: FastAPI):
    # 设计说明：把跨域中间件挂到应用上
    # 为什么：这是开发期写法。源一旦收敛，动这里不用碰入口
    #
    # TODO(注缘): 交付前把 allow_origins 收敛成实际前端地址，别再留着通配
    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
