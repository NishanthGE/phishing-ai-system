@echo off
echo Testing Node.js installation...
node --version
if %errorlevel% equ 0 (
    echo ✅ Node.js is installed!
    echo Starting your AI Phishing Detection System...
    cd /d "e:\Capstone\phishing-ai-system"
    npm install
    npm start
) else (
    echo ❌ Node.js not found. Please install from https://nodejs.org/
    pause
)