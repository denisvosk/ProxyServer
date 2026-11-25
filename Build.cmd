@echo off
setlocal
cd /d "%~dp0"
set "PROXY_MSBUILD="
for /f "delims=" %%I in ('where msbuild.exe 2^>nul') do if not defined PROXY_MSBUILD set "PROXY_MSBUILD=%%I"
if defined PROXY_MSBUILD goto build
set "PROXY_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%PROXY_VSWHERE%" goto legacy
for /f "usebackq delims=" %%I in (`"%PROXY_VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do if not defined PROXY_MSBUILD set "PROXY_MSBUILD=%%I"
if defined PROXY_MSBUILD goto build
:legacy
if exist "%ProgramFiles(x86)%\MSBuild\14.0\Bin\MSBuild.exe" set "PROXY_MSBUILD=%ProgramFiles(x86)%\MSBuild\14.0\Bin\MSBuild.exe"
if defined PROXY_MSBUILD goto build
echo Visual Studio C++ build tools were not found.
echo Open ProxyServer.sln in Visual Studio with Desktop development with C++ installed.
echo The ready-to-run ProxyServer.exe is also included in the release archive.
pause
exit /b 1
:build
set "PROXY_PLATFORM=x64"
if /i "%~1"=="Win32" set "PROXY_PLATFORM=Win32"
"%PROXY_MSBUILD%" ProxyServer.sln /m /t:Build /p:Configuration=Release /p:Platform=%PROXY_PLATFORM% /nologo
if errorlevel 1 (
  echo.
  echo Build failed. See the compiler error above.
  pause
  exit /b 1
)
echo.
echo Ready: bin\%PROXY_PLATFORM%\Release\ProxyServer.exe
pause
