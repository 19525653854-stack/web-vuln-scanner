# -*- coding: utf-8 -*-
# 设计说明：认证模块，负责登录签发令牌和令牌校验
# 为什么：业务路由都要挂鉴权依赖，认证逻辑必须收在一处，各写各的迟早出现漏挂的路由
# 放弃了：不做多用户和角色权限。V1.0 只有管理员一种身份，RBAC 是后面的事
#
# 2026-10-01 口令哈希从 bcrypt 换成 pbkdf2_sha256。bcrypt 依赖 C 扩展，
# 换台机器装不上就得折腾编译环境；pbkdf2 是纯 Python，安全性也够
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException
from passlib.hash import pbkdf2_sha256
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from config import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    SECRET_KEY,
    TOKEN_EXPIRE_MINUTES,
)
from models.database import SessionLocal, db_get_session
from models.tables import User

router = APIRouter(prefix="/auth", tags=["认证"])

# 算法写死。要是允许从请求头里读 alg，攻击者填个 none 就能伪造任意令牌
_TOKEN_ALGORITHM = "HS256"


class LoginRequest(BaseModel):
    # 设计说明：登录入参
    # 为什么：用 Pydantic 模型而不是自己取 request.json()，字段缺失时 FastAPI 直接回 422，
    #         少写一堆判空
    # 放弃了：不在这里做口令强度校验，那是改密码接口该管的事
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


def auth_build_password_hash(raw_password):
    # 设计说明：把明文口令转成可入库的哈希
    # 为什么：pbkdf2_sha256 每次自带随机盐，同一个口令算两遍结果不一样，彩虹表直接失效
    # 放弃了：不加 pepper 二次盐，加完换密钥全库口令都得重置，V1.0 不值当
    return pbkdf2_sha256.hash(raw_password)


def auth_verify_password(raw_password, stored_hash):
    # 设计说明：校验口令
    # 为什么：比对交给 passlib 的 verify，内部是定长比较，不会因为碰上第一个不同字符就返回
    # 放弃了：不在这里做登录失败次数限制，应用层做容易被绕过，交给网关
    try:
        return pbkdf2_sha256.verify(raw_password, stored_hash)
    except Exception:
        # 库里的哈希串如果是老格式或者被手改坏了，这里会抛异常，当成校验失败处理就行
        return False


def auth_create_token(raw_username):
    # 设计说明：签发访问令牌
    # 为什么：过期时间写进载荷，令牌自己带着有效期走，服务端不用维护会话表，重启也不掉登录
    # 放弃了：不做刷新令牌，有效期给到 12 小时，到期重新登一次不算麻烦
    expire_time = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": raw_username, "exp": expire_time}, SECRET_KEY, algorithm=_TOKEN_ALGORITHM)


def auth_parse_token(raw_token):
    # 设计说明：解析令牌并取出登录名
    # 为什么：单独抽出来，以后后台定时任务也要认令牌，不必再走一遍 HTTP
    # 放弃了：不做令牌吊销黑名单。无状态令牌要吊销就得引入存储，代价不值
    try:
        payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[_TOKEN_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="登录已过期，重新登录一下")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="令牌无效，请重新登录")
    return payload.get("sub")


def auth_check_token(authorization: str = Header(default="")):
    # 设计说明：FastAPI 依赖，业务路由挂上它就自动校验令牌
    # 为什么：直接读 Authorization 头，没用 OAuth2PasswordBearer。前端的登录是 JSON，
    #         不是表单，套 OAuth2 反而要在 Swagger 上多绕一圈
    # 放弃了：不支持 Cookie 鉴权，前端是纯 SPA，令牌放本地存储更省事
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少令牌，先登录")
    return auth_parse_token(authorization[7:])


def auth_create_default_user():
    # 设计说明：首次启动建一个默认管理员
    # 为什么：空库进去连登录页都过不去，还得手工插数据，太劝退
    # 放弃了：不随机生成口令再打到日志里，容器部署时经常看不到日志，反而更麻烦
    session = SessionLocal()
    try:
        if session.query(User).first():
            return None
        default_user = User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=auth_build_password_hash(DEFAULT_ADMIN_PASSWORD),
        )
        session.add(default_user)
        session.commit()
        return default_user.username
    finally:
        session.close()


@router.post("/login")
def auth_run_login(login_request: LoginRequest, session: Session = Depends(db_get_session)):
    # 设计说明：登录接口，校验口令后签发令牌
    # 为什么：账号不存在和口令错误回同一句话，不然等于告诉对方"这个账号是存在的"，方便人家枚举
    # 放弃了：不做图形验证码和登录频率限制，那是部署层面的事
    user_row = session.query(User).filter(User.username == login_request.username).first()
    if user_row is None or not auth_verify_password(login_request.password, user_row.password_hash):
        return {"code": 1, "msg": "用户名或密码不对"}

    access_token = auth_create_token(user_row.username)
    return {
        "code": 0,
        "data": {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_EXPIRE_MINUTES * 60,
        },
    }
