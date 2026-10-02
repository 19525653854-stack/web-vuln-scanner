# -*- coding: utf-8 -*-
# 设计说明：日志配置。单进程用 basicConfig 就够了，真上多进程再换结构化
# 为什么：日志格式收敛在一处，改格式不用翻遍项目；之前它和路由、装配逻辑挤在入口文件里
# 放弃了：不接日志文件，只看控制台。V1.0 是单机交付，加一个文件就多一份要管的东西
import logging


def core_setup_logging():
    # 设计说明：配置全局日志格式，并返回本应用统一用的 logger
    # 为什么：从入口文件拆出来，入口只负责"什么时候调"，格式长什么样归这里管
    # 放弃了：不做日志等级按模块细分。统一 INFO 就够看，细分了排查时反而要翻配置
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    return logging.getLogger("ai_scanner")
