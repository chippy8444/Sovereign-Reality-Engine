@echo off
setlocal
cd /d "%~dp0"
title Resolution AI - Sovereign Reality Engine BLUE
set RA_PROVIDER=anthropic
set RA_DEFAULT_PROVIDER=anthropic
set RA_FALLBACK_PROVIDER=local
set RA_THEME=resolution_assurance_blue
set RA_FAST_MODE=1
set RA_PARALLEL_RETRIEVAL=1
set RA_STREAM=1
if not exist data mkdir data
if not exist logs mkdir logs

echo Killing anything already using port 3030...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3030 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>nul

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js LTS from https://nodejs.org/
  pause
  exit /b 1
)
if not exist node_modules\express (
  echo Installing required modules...
  call npm install
  if errorlevel 1 (
    echo npm install failed.
    pause
    exit /b 1
  )
)
echo Starting Resolution AI BLUE on http://localhost:3030/?blue=%RANDOM%%RANDOM%
start "" "http://localhost:3030/?blue=%RANDOM%%RANDOM%"
node server.mjs
pause
