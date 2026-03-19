@echo off
echo =====================================
echo AI Phishing Detection System
echo Starting Frontend + Backend Servers
echo =====================================
echo.

cd /d "e:\Capstone\phishing-ai-system"

echo Checking Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js not installed!
    echo Install from: https://nodejs.org/
    pause
    exit /b 1
)

echo Installing dependencies...
call npm install

echo.
echo =====================================
echo Starting servers...
echo Frontend: http://localhost:8080
echo Backend:  http://localhost:8081
echo =====================================
echo.

REM Start both servers in separate windows
start "Backend API Server" cmd /k "node src/backend/server.js"
timeout /t 2 /nobreak >nul
start "Frontend Server" cmd /k "node src/backend/frontend-server.js"

echo.
echo ✅ Both servers started!
echo.
echo 🌐 Open your browser to: http://localhost:8080
echo 📚 API Docs: http://localhost:8081/api/docs
echo.
echo Press any key to open browser...
pause >nul

start http://localhost:8080

echo.
echo Servers are running in separate windows.
echo Close those windows to stop the servers.
echo.
pause
