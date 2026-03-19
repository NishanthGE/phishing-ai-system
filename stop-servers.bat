@echo off
echo =====================================
echo Stopping Phishing Detection System
echo =====================================
echo.

echo Stopping Frontend Server (Port 8080)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8080') do (
    taskkill /F /PID %%a 2>nul
    if !errorlevel! equ 0 (
        echo ✅ Frontend server stopped
    )
)

echo.
echo Stopping Backend Server (Port 8081)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8081') do (
    taskkill /F /PID %%a 2>nul
    if !errorlevel! equ 0 (
        echo ✅ Backend server stopped
    )
)

echo.
echo Checking for any remaining Node processes...
tasklist | findstr node.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo ⚠️  Other Node.js processes are still running.
    echo Do you want to kill ALL Node.js processes? (Y/N)
    set /p choice=
    if /i "%choice%"=="Y" (
        taskkill /F /IM node.exe
        echo ✅ All Node.js processes stopped
    )
) else (
    echo ✅ No Node.js processes running
)

echo.
echo =====================================
echo Servers stopped successfully!
echo =====================================
echo.
pause
