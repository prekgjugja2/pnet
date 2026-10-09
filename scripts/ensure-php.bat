@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0\.."

set "PHP="
if exist "C:\xampp\php\php.exe" set "PHP=C:\xampp\php\php.exe"
if not defined PHP where php >nul 2>&1 && for /f "delims=" %%P in ('where php 2^>nul') do set "PHP=%%P" & goto havephp

:havephp
if not defined PHP (
  echo   PHP not found. Install XAMPP or add php.exe to PATH.
  echo   Web UI: https://www.apachefriends.org/
  exit /b 1
)

echo   PHP OK: %PHP%
"%PHP%" -m 2>nul | findstr /i "pdo_sqlite sqlite3" >nul
if errorlevel 1 (
  echo   WARNING: Enable extension=pdo_sqlite and extension=sqlite3 in php.ini, then restart Apache.
)
exit /b 0
