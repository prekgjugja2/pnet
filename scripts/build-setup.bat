@echo off
setlocal EnableDelayedExpansion
title Build PNet-Setup.exe
cd /d "%~dp0\.."

echo Building PNet-Setup.exe (developers only)...
echo.

call scripts\ensure-compiler.bat
if errorlevel 1 ( pause & exit /b 1 )

where g++ >nul 2>&1
if errorlevel 1 (
  for /d %%D in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*") do (
    if exist "%%D\mingw64\bin\g++.exe" set "PATH=%%D\mingw64\bin;!PATH!"
  )
)

call engine\build.bat
if errorlevel 1 ( pause & exit /b 1 )

where npm >nul 2>&1
if errorlevel 1 (
  echo Install Node.js from https://nodejs.org/
  pause
  exit /b 1
)

pushd desktop
call npm install --no-fund --no-audit
if errorlevel 1 ( popd & pause & exit /b 1 )
set CSC_IDENTITY_AUTO_DISCOVERY=false
call npx --yes electron-builder --win nsis
set ERR=!ERRORLEVEL!
popd
if not !ERR!==0 ( pause & exit /b 1 )

if exist "desktop\dist\PNet-Setup-1.0.0.exe" (
  copy /Y "desktop\dist\PNet-Setup-1.0.0.exe" "PNet-Setup.exe" >nul
)

echo.
echo Done: PNet-Setup.exe
if exist "PNet-Setup.exe" explorer /select,"%CD%\PNet-Setup.exe"
pause
