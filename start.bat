@echo off
chcp 936 >nul
title 智能Web漏洞扫描系统 V1.0
setlocal

echo ================================================
echo   智能Web漏洞扫描系统 V1.0
echo ================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [错误] 没有找到虚拟环境 .venv
    echo        请先双击 install.bat 安装依赖
    echo.
    pause
    exit /b 1
)

echo [1/3] 正在启动后端服务，端口 8000 ...
start "ai-scanner-backend" cmd /k ".venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000"
timeout /t 5 >nul

if exist "frontend\package.json" (
    echo [2/3] 正在启动前端界面，端口 5173 ...
    start "ai-scanner-frontend" cmd /k "cd frontend && npm run dev"
    timeout /t 6 >nul
    echo [3/3] 正在打开浏览器 ...
    start "" http://127.0.0.1:5173
) else (
    echo [2/3] 前端工程尚未创建，本次跳过前端启动
    echo [3/3] 直接打开后端接口文档 ...
    start "" http://127.0.0.1:8000/docs
)

echo.
echo 系统已启动。
echo 注意：关闭本窗口不会停止服务，请单独关闭那两个服务窗口。
echo.
pause
