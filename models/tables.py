# -*- coding: utf-8 -*-
# 设计说明：数据表定义，六张表分两类——系统支撑（user / model_config / audit_log）和扫描业务（target / job / finding）
# 为什么：ORM 全放一个文件里，表结构一眼能看全，改字段不用在多个模块之间来回跳
# 放弃了：不按业务拆成多个文件，也不上 Alembic，V1.0 表结构还会动
#
# 2026-09-29 把 model_config 加进来。原本只打算建三张业务表，模型信息准备写死在 config.py 里，
# 后来确认要支持用户随时切换厂商，写死那套根本撑不住
# 2026-10-01 补外键和索引。一开始只写了关联用的整型字段，没有任何约束，插一条 job_id 不存在的
# 漏洞记录照样能进——真出脏数据的时候才发现少了东西
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from models.database import Base


class User(Base):
    # 设计说明：登录用户表
    # 为什么：V1.0 实际只有一个人用，字段仍按多用户设计，以后要加人不用改表
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, comment="登录名")
    # 只存哈希。库里落明文的话，哪天库文件被人拷走就等于直接送账号
    password_hash = Column(String(256), nullable=False, comment="口令哈希，不存明文")
    created_at = Column(DateTime, default=datetime.now)


class Target(Base):
    # 设计说明：扫描目标表
    # 为什么：授权确认必须落库。只在前端勾一下就完事，真出了事查无对证
    __tablename__ = "target"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_name = Column(String(128), nullable=False, comment="目标别名，便于识别")
    target_url = Column(String(512), nullable=False, comment="目标地址，必须带协议头")
    authorized_flag = Column(Boolean, default=False, comment="是否已确认获得测试授权")
    # 时间单独存一列，不跟 flag 合并。"什么时候确认的"比"确认过没有"更要紧
    authorized_at = Column(DateTime, nullable=True, comment="授权确认时间")
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        # 目标列表默认按创建时间倒序翻，走这条索引就不用全表扫
        Index("idx_target_created", "created_at"),
    )


class Job(Base):
    # 设计说明：扫描任务表。同一个目标可以反复扫，每扫一次算一条独立任务
    __tablename__ = "job"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # 删目标的时候连带着把任务删掉。任务脱离目标没有任何意义，留着只会让报告对不上号
    target_id = Column(
        Integer, ForeignKey("target.id", ondelete="CASCADE"), nullable=False, comment="关联 target.id"
    )
    # 2026-10-01 从 job_status 改名过来，对齐规范里给的示例变量 current_job_status
    current_job_status = Column(String(32), default="pending", comment="pending/running/done/failed")
    current_round = Column(Integer, default=0, comment="智能体当前进行到第几轮")
    total_round = Column(Integer, default=0, comment="实际执行的总轮次")
    # 每轮的测试计划存成 JSON 文本。报告要复盘"当时为什么走这一步"，全靠这一列
    plan_snapshot = Column(Text, nullable=True, comment="测试计划快照，JSON 文本")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        # 任务页要按目标查、按状态筛，这两个字段经常一起出现在 where 里
        Index("idx_job_target_status", "target_id", "current_job_status"),
    )


class Finding(Base):
    # 设计说明：漏洞发现表，一行一个漏洞
    # 为什么：原始响应单独留一列。报告和人工复核都要回看证据，不能只留一句结论
    # 放弃了：V1.0 不做漏洞去重合并，同一个点被多轮触发就多行，先如实记下来
    __tablename__ = "finding"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # 任务被删时漏洞跟着删。不然报告里会冒出找不到所属任务的孤儿记录
    job_id = Column(
        Integer, ForeignKey("job.id", ondelete="CASCADE"), nullable=False, comment="关联 job.id"
    )
    vuln_type = Column(String(64), nullable=False, comment="漏洞类型，如 注入类 / 跨站脚本类")
    vuln_level = Column(String(16), default="medium", comment="high/medium/low")
    vuln_url = Column(String(512), nullable=True, comment="命中地址")
    raw_payload = Column(Text, nullable=True, comment="触发的 payload 原文")
    raw_evidence = Column(Text, nullable=True, comment="响应证据片段")
    # 智能体自评的置信度。低于 0.5 的在报告里标成待复核，不当成确认结论
    confidence = Column(Float, default=0.0, comment="智能体自评置信度，0 到 1")
    validate_reason = Column(Text, nullable=True, comment="验证器给出的判定理由")
    fix_suggestion = Column(Text, nullable=True, comment="修复建议")
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        # 漏洞页默认按"某个任务下的高危"来翻，这个复合索引正好对上
        Index("idx_finding_job_level", "job_id", "vuln_level"),
    )


class ModelConfig(Base):
    # 设计说明：模型配置表，字段跟方案 5.3 一一对应
    # 为什么：厂商、地址、Key 全部落库，切模型只改数据不动代码，新增厂商也不用碰智能体
    # 放弃了：不做配置版本回溯。改坏了就重填一遍，V1.0 配置项不多
    __tablename__ = "model_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_name = Column(String(64), nullable=False, comment="配置名称，支持多套并存")
    main_model_provider = Column(String(32), nullable=False)
    main_model_name = Column(String(64), nullable=False)
    main_model_api_key = Column(String(256), nullable=False, comment="加密后存储，不存明文")
    main_model_base_url = Column(String(256), nullable=False)
    advisor_model_provider = Column(String(32), nullable=True)
    advisor_model_name = Column(String(64), nullable=True)
    advisor_model_api_key = Column(String(256), nullable=True)
    advisor_model_base_url = Column(String(256), nullable=True)
    collaboration_mode = Column(String(16), default="single", comment="single/dual")
    # 0.3 是试出来的。再高一点，规划器就会开始给不存在的页面编路径
    temperature = Column(Float, default=0.3)
    max_tokens = Column(Integer, default=4096)
    timeout = Column(Integer, default=30)
    # 同一时刻只应有一条为 true。切模型时先置旧记录为 false 再插新记录，顺序别反
    is_active = Column(Boolean, default=False, comment="同一时刻只应有一条为 true")
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        # 配置名允许用户自己起，但不能重名——重名之后下拉框里根本分不清哪条是哪条
        UniqueConstraint("config_name", name="uq_model_config_name"),
        Index("idx_model_config_active", "is_active"),
    )


class AuditLog(Base):
    # 设计说明：审计日志表
    # 为什么：方案要求记录每次工具调用与决策理由且不可删除，所以这里只开写入和查询，不设删除接口
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # 这一条故意不写 ondelete=CASCADE：任务被删了，它留下的审计日志也得留着，不然事后查无对证
    job_id = Column(Integer, ForeignKey("job.id"), nullable=True, comment="关联任务，系统级操作可为空")
    log_type = Column(String(32), nullable=False, comment="tool/decision/reflection/system")
    log_content = Column(Text, nullable=False, comment="日志正文")
    # 理由单独一列。只记"做了什么"没法复盘，得知道"当时为什么这么判断"
    log_reason = Column(Text, nullable=True, comment="决策理由，方案要求必须记")
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        Index("idx_audit_job_created", "job_id", "created_at"),
    )
