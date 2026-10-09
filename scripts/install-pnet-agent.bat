@echo off
setlocal
cd /d "%~dp0.."
if "%~1"=="" (
  echo Usage: install-pnet-agent.bat YOUR_AGENT_TOKEN [AGENT_URL]
  echo Create the token in PNet: open a device, click Install agent.
  exit /b 1
)
set "AGENT_URL=%~2"
if "%AGENT_URL%"=="" set "AGENT_URL=http://localhost/pnet/agent.php"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0pnet-agent.ps1" -Token "%~1" -Url "%AGENT_URL%"
exit /b %ERRORLEVEL%
