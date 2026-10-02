@echo off
chcp 936 >nul
title 安装依赖 - 智能Web漏洞扫描系统 V1.0
setlocal

echo ================================================
echo   安装依赖
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 没有检测到 python 命令
    echo        请先安装 Python 3.11 或以上版本
    echo        安装时记得勾选 Add Python to PATH
    echo.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] 正在创建虚拟环境 .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [错误] 虚拟环境创建失败
        pause
        exit /b 1
    )
) else (
    echo [1/4] 虚拟环境已存在，跳过创建
)

echo [2/4] 正在安装后端依赖，第一次会比较慢 ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 (
    echo        国内镜像没装全，换官方源再补一次
    echo        cryptography 这类包在部分镜像上有同步延迟，走到这一步是正常的
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [错误] 后端依赖安装失败，请检查网络后重试
        pause
        exit /b 1
    )
)

echo [3/4] 正在安装前端依赖，第一次会比较慢 ...
where npm >nul 2>nul
if errorlevel 1 (
    echo        [提示] 没有检测到 npm，本次跳过前端依赖
    echo        要用界面的话得装 Node.js 18 或以上版本，装完重新跑一次本脚本
) else (
    pushd frontend
    call npm install --no-audit --no-fund --registry=https://registry.npmmirror.com
    if errorlevel 1 (
        echo        国内镜像没装成，换默认源再试一次
        call npm install --no-audit --no-fund
    )
    popd
)

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo [4/4] 已生成 .env，请打开它填入模型 API Key
) else (
    echo [4/4] .env 已存在，未覆盖
)

echo.
echo 安装完成。下一步双击 start.bat 启动系统。
echo.
pause
