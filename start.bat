@echo off
echo =====================================
echo AI-Based Phishing Detection System
echo Professional Cybersecurity Solution
echo =====================================
echo.

echo Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed!
    echo.
    echo Please install Node.js from: https://nodejs.org/
    echo Download the LTS version and restart this script.
    echo.
    pause
    exit /b 1
)

echo Node.js found! Installing dependencies...
echo.

npm install
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies!
    echo Please check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo Dependencies installed successfully!
echo Starting the AI Phishing Detection System...
echo.
echo =====================================
echo Server will start on: http://localhost:3000
echo =====================================
echo.

npm start

pause