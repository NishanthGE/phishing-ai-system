@echo off
REM Test Frontend-Backend Connection

echo.
echo ========================================
echo Testing Frontend-Backend Connection
echo ========================================
echo.

REM Test Backend Health
echo [1/3] Testing Backend Health Check...
curl -s http://localhost:8081/api/health | findstr "success" >nul
if %errorlevel% equ 0 (
    echo ✅ Backend is running and responding
) else (
    echo ❌ Backend is NOT responding
    echo Make sure backend is running: node src/backend/server.js
    pause
    exit /b 1
)

echo.
echo [2/3] Testing Email Analysis Endpoint...
curl -s -X POST http://localhost:8081/api/analyze-email ^
  -H "Content-Type: application/json" ^
  -d "{\"emailContent\":\"Test email\"}" | findstr "success" >nul
if %errorlevel% equ 0 (
    echo ✅ Email analysis endpoint is working
) else (
    echo ❌ Email analysis endpoint failed
)

echo.
echo [3/3] Testing URL Analysis Endpoint...
curl -s -X POST http://localhost:8081/api/analyze-url ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://example.com\"}" | findstr "success" >nul
if %errorlevel% equ 0 (
    echo ✅ URL analysis endpoint is working
) else (
    echo ❌ URL analysis endpoint failed
)

echo.
echo ========================================
echo ✅ All tests completed!
echo ========================================
echo.
echo Frontend: http://localhost:8080
echo Backend: http://localhost:8081
echo.
pause
