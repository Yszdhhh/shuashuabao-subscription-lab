@echo off
chcp 65001 >nul
cd /d "G:\刷刷宝\Worktrees\subscription-lab-642235c"
set PROVIDER_MODE=inmemory
set SUBSCRIPTION_ADMIN_USER=admin
set SUBSCRIPTION_ADMIN_PASSWORD=admin
echo ===================================================
echo   刷刷宝 订阅管理中控台 (Local Admin)
echo   访问地址: http://127.0.0.1:8010/admin
echo   账号: admin
echo   密码: admin
echo ===================================================
start http://127.0.0.1:8010/admin
echo 正在启动本地服务，请勿关闭本窗口...
python -m uvicorn bridge.app.main:app --host 127.0.0.1 --port 8010
pause
