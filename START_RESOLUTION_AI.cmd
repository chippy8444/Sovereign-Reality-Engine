@echo off
setlocal
cd /d "%~dp0"
title Resolution AI - Sovereign Reality Engine
set RA_PROVIDER=anthropic
set RA_DEFAULT_PROVIDER=anthropic
set RA_FALLBACK_PROVIDER=ollama
set RA_THEME=resolution_assurance_blue
set RA_FAST_MODE=1
set RA_PARALLEL_RETRIEVAL=1
set RA_STREAM=1
if not exist data mkdir data
if not exist logs mkdir logs
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
echo Starting Resolution AI on http://localhost:3030
start "" "http://localhost:3030"
node server.mjs
pause
