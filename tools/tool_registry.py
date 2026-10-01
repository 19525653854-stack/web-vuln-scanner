# -*- coding: utf-8 -*-
# 设计说明：工具注册表。全系统调工具都从这里拿，技能层不许直接 import 具体工具
# 为什么：智能体后面要按名字调工具（"给我扫个端口"），得有个按名字找实现的地方；
#         技能里直接 import 工具的话，换个实现得把所有技能翻一遍
# 放弃了：不做插件化目录扫描。V1.0 工具一只手数得过来，写死的注册映射比扫描目录可靠
registered_tools = {}


def tool_register(tool_name, tool_description, tool_handler):
    # 设计说明：把一个工具登记进来
    # 为什么：登记时必须带描述。技能管理器要给智能体看"有哪些工具、各是干嘛的"，全靠这段话
    # 放弃了：不做参数签名声明。V1.0 调用方都清楚自己要传什么，强类型化反而碍事
    registered_tools[tool_name] = {
        "description": tool_description,
        "handler": tool_handler,
    }


def tool_invoke(tool_name, **tool_kwargs):
    # 设计说明：按名字调用工具
    # 为什么：收敛成统一入口，才能在这里记调用记录。各调各的，审计日志得满项目插桩
    # 放弃了：不包异常。工具自己崩了让它崩上去，注册表吞掉的话排查更难
    if tool_name not in registered_tools:
        raise KeyError("工具 %s 没有注册" % tool_name)
    return registered_tools[tool_name]["handler"](**tool_kwargs)


def tool_fetch_descriptions():
    # 设计说明：返回全部工具的名字和描述
    # 为什么：组装智能体上下文时要用。智能体看着这个清单决定自己下一步调哪个
    return {tool_name: tool_meta["description"] for tool_name, tool_meta in registered_tools.items()}
