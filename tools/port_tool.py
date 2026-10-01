# -*- coding: utf-8 -*-
# 设计说明：端口扫描工具，探测目标主机常见端口的开放情况
# 为什么：socket 直连，不用 nmap。nmap 要在使用者机器上装一整套，别人拿这系统去实测时门槛陡增
# 放弃了：不做全端口和 UDP。65535 个端口扫一遍又慢又容易被 WAF 封，V1.0 只扫 21 个常见的
#
# 2026-10-01 并发从线程数改成了读配置。最早写死 50 个线程，自己机器上都把端口挤得误报，
# 后来统一跟 SCAN_MAX_CONCURRENCY 走
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import SCAN_MAX_CONCURRENCY

from tools.tool_registry import tool_register

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "http-dev",
    27017: "mongodb", 9001: "supervisor", 9200: "elasticsearch",
}


def probe_check_single_port(raw_host, single_port):
    # 设计说明：测一个端口通不通
    # 为什么：connect_ex 不抛异常只返回码。用 connect 的话，一个被拒的端口能把整个循环打断
    # 放弃了：不抓 banner。抓到了确实能识别服务，但有的服务不主动发，白等一个超时
    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 超时 1 秒。2 秒太慢会拖垮整轮扫描，0.5 秒在跨网段的场景误报多
    probe_socket.settimeout(1)
    try:
        connect_code = probe_socket.connect_ex((raw_host, single_port))
        return single_port if connect_code == 0 else None
    finally:
        probe_socket.close()


def probe_fetch_ports(raw_host):
    # 设计说明：扫常见端口，返回开放端口和服务名
    # 为什么：全端口扫太慢，容易被 WAF 封 IP；这 21 个端口覆盖了九成以上的暴露面
    # 放弃了：服务识别、版本探测。那是指纹识别模块的活，端口扫描只回答"通不通"
    open_ports = []
    with ThreadPoolExecutor(max_workers=SCAN_MAX_CONCURRENCY) as port_pool:
        future_map = {
            port_pool.submit(probe_check_single_port, raw_host, single_port): single_port
            for single_port in COMMON_PORTS
        }
        for future in as_completed(future_map):
            found_port = future.result()
            if found_port is not None:
                open_ports.append(found_port)

    # 按端口号排序再回。按探测完成的顺序回，页面和报告里乱跳，不好看
    open_ports.sort()
    return [
        {"port": open_port, "service": COMMON_PORTS[open_port]}
        for open_port in open_ports
    ]


# 注册进工具表。技能层和任务管线通过 "port_scan" 这个名字调，不直接 import 本模块
tool_register(
    "port_scan",
    "端口扫描：探测目标主机 21 个常见端口的开放情况，返回开放端口与服务名列表",
    probe_fetch_ports,
)
