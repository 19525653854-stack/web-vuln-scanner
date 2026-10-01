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
    echo [1/3] 正在创建虚拟环境 .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [错误] 虚拟环境创建失败
        pause
        exit /b 1
    )
) else (
    echo [1/3] 虚拟环境已存在，跳过创建
)

echo [2/3] 正在安装后端依赖，第一次会比较慢 ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 (
    echo [错误] 依赖安装失败，请检查网络后重试
    pause
    exit /b 1
)

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo [3/3] 已生成 .env，请打开它填入模型 API Key
) else (
    echo [3/3] .env 已存在，未覆盖
)

echo.
echo 安装完成。下一步双击 start.bat 启动系统。
echo.
pause
