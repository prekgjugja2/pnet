@echo off
cd /d "%~dp0"

rem Prefer live Electron from this repo (always has latest preload.js)
if exist "desktop\node_modules\electron\dist\electron.exe" (
  cd desktop
  start "" "node_modules\electron\dist\electron.exe" .
  exit /b 0
)

rem Prefer local unpacked build
if exist "desktop\dist\win-unpacked\PNet.exe" (
  start "" "desktop\dist\win-unpacked\PNet.exe"
  exit /b 0
)

rem Installed app
if exist "%LOCALAPPDATA%\Programs\pnet\PNet.exe" (
  start "" "%LOCALAPPDATA%\Programs\pnet\PNet.exe"
  exit /b 0
)

if exist "PNet-Setup.exe" (
  start "" "PNet-Setup.exe"
  exit /b 0
)

msg * Install Electron deps first: cd desktop ^& npm install
exit /b 1
