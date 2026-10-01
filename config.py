# -*- coding: utf-8 -*-
# 设计说明：全局配置中心，所有跟环境相关的值都从这里出去
# 为什么：以前端口、路径这些散在各模块里写死，换台机器部署要满项目翻，还老漏改
# 放弃了：没用 pydantic-settings 做一层强类型校验，V1.0 一共十来个配置项，不值当再多引一个依赖
#
# 2026-09-28 从写死改成读 .env。最开始 SECRET_KEY 和端口都硬编码在代码里，换环境只能改代码
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# 运行期产物统一收进 data/ 和 logs/，.gitignore 两条规则就能兜住，
# 省得哪天手滑把 scanner.db 提交上去
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = DATA_DIR / "reports"
for runtime_dir in (DATA_DIR, LOG_DIR, REPORT_DIR):
    runtime_dir.mkdir(parents=True, exist_ok=True)

# 文件不存在也不报错，直接走下面的默认值，新人 clone 下来就能把服务起起来
load_dotenv(BASE_DIR / ".env")

APP_NAME = "智能Web漏洞扫描系统"
APP_VERSION = "V1.0"

# 监听 0.0.0.0 是为了同网段的其他机器也能连上；只在自己机器上跑的话改成 127.0.0.1 更稳妥
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8000"))

# 库文件早期是放在项目根目录的，跑两天根目录就多出 scanner.db 和 scanner.db-journal，
# 后来统一挪进 data/ 才清爽
DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///" + (DATA_DIR / "scanner.db").as_posix()

# 这个默认值只为了让服务能起来，正式部署必须换掉
SECRET_KEY = os.getenv("SECRET_KEY", "dev_only_secret_key_please_change")
# 12 小时。设太短，干活干到一半就被踢出去；设太长等于没做过期
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "720"))

# ---- 扫描安全约束：改这里的值等于改全系统所有任务的默认行为 ----
# 5 次/秒是拿本地靶场压出来的数。调到 10 会把小站打挂，降到 2 又慢得干等
SCAN_RATE_LIMIT_PER_SECOND = int(os.getenv("SCAN_RATE_LIMIT_PER_SECOND", "5"))
# 3 路并发是顺手定的，再往上就得考虑目标侧会不会直接判定成攻击
SCAN_MAX_CONCURRENCY = int(os.getenv("SCAN_MAX_CONCURRENCY", "3"))
# 单条 payload 30 秒。超时还没回来的基本是死连接，继续等只是白占并发额度
PAYLOAD_EXEC_TIMEOUT = int(os.getenv("PAYLOAD_EXEC_TIMEOUT", "30"))
# 15 轮封顶。算过 token 成本，超过 20 轮上下文就开始溢出，压缩也救不回来
AGENT_MAX_ROUND = int(os.getenv("AGENT_MAX_ROUND", "15"))
# 连续失败 3 次才触发角色互换。触发太早，正常的多步探测会被误判成卡死
AGENT_FAIL_SWAP_THRESHOLD = int(os.getenv("AGENT_FAIL_SWAP_THRESHOLD", "3"))
AGENT_MAX_SWAP_TIMES = int(os.getenv("AGENT_MAX_SWAP_TIMES", "2"))

# ---- 首次启动建的管理员账号：装完就能登进去，部署完第一件事就是改掉它 ----
# 口令从环境变量读，不写死在代码里，不然换个部署环境还得回来改源码
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

# TODO(开发者): 上线前把 SECRET_KEY 和 API Key 改成从系统密钥库读，别再落 .env
