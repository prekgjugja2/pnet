@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0\.."

where g++ >nul 2>&1
if %ERRORLEVEL%==0 (
  echo   Compiler OK: g++
  exit /b 0
)

where cl >nul 2>&1
if %ERRORLEVEL%==0 (
  echo   Compiler OK: MSVC cl
  exit /b 0
)

echo   No C/C++ compiler in PATH. Trying WinGet MinGW...
where winget >nul 2>&1
if errorlevel 1 (
  echo.
  echo   winget not found. Install MinGW manually, then run install.bat again:
  echo     winget install BrechtSanders.WinLibs.POSIX.UCRT
  echo.
  exit /b 1
)

winget install --id BrechtSanders.WinLibs.POSIX.UCRT -e --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
  echo   WinGet install failed.
  exit /b 1
)

for /d %%D in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*") do (
  if exist "%%D\mingw64\bin\g++.exe" (
    set "PNET_MINGW=%%D\mingw64\bin"
    goto found
  )
)

if exist "C:\mingw64\bin\g++.exe" set "PNET_MINGW=C:\mingw64\bin"

:found
if not defined PNET_MINGW (
  echo   MinGW installed but g++ path not found. Open a new terminal and run install.bat again.
  exit /b 1
)

set "PATH=%PNET_MINGW%;%PATH%"
echo   Added MinGW to PATH for this session: %PNET_MINGW%
exit /b 0
