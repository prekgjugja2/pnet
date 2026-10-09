@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

where g++ >nul 2>&1
if %ERRORLEVEL%==0 goto mingw

rem WinGet MinGW is often not on PATH until a new shell opens
for /d %%D in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*") do (
  if exist "%%D\mingw64\bin\g++.exe" set "PATH=%%D\mingw64\bin;!PATH!"
)
if exist "C:\mingw64\bin\g++.exe" set "PATH=C:\mingw64\bin;%PATH%"

where g++ >nul 2>&1
if %ERRORLEVEL%==0 goto mingw

where cl >nul 2>&1
if %ERRORLEVEL%==0 goto msvc

echo.
echo No C/C++ compiler found.
echo Install one of:
echo   winget install BrechtSanders.WinLibs.POSIX.UCRT
echo   or Visual Studio Build Tools with "Desktop development with C++"
echo.
exit /b 1

:mingw
echo Building with MinGW g++...
if not exist build mkdir build
g++ -O2 -std=c++17 -Iinclude -c src\main.cpp -o build\main.o
gcc -O2 -std=c11 -Iinclude -c src\pnet_scan.c -o build\pnet_scan.o
gcc -O2 -std=c11 -Iinclude -c src\pnet_monitor.c -o build\pnet_monitor.o
g++ -O2 -static -static-libgcc -static-libstdc++ -o build\pnet_scan.exe build\main.o build\pnet_scan.o build\pnet_monitor.o -lws2_32 -liphlpapi -lpsapi
if errorlevel 1 exit /b 1
echo Built: engine\build\pnet_scan.exe
build\pnet_scan.exe --help
exit /b 0

:msvc
echo Building with MSVC...
if not exist build mkdir build
cl /nologo /O2 /EHsc /std:c++17 /Iinclude /c src\main.cpp /Fobuild\main.obj
cl /nologo /O2 /Iinclude /c src\pnet_scan.c /Fobuild\pnet_scan.obj
cl /nologo /O2 /Iinclude /c src\pnet_monitor.c /Fobuild\pnet_monitor.obj
link /nologo /OUT:build\pnet_scan.exe build\main.obj build\pnet_scan.obj build\pnet_monitor.obj ws2_32.lib iphlpapi.lib psapi.lib
if errorlevel 1 exit /b 1
echo Built: engine\build\pnet_scan.exe
build\pnet_scan.exe --help
exit /b 0
