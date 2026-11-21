@echo off
setlocal
set "rr_target=gcc_ntox86_64"
set "rr_build=build"
if not "%~2"=="" goto usage
if "%~1"=="" goto setup
if /i "%~1"=="x86_64" goto setup
if /i not "%~1"=="aarch64le" goto usage
set "rr_target=gcc_ntoaarch64le"
set "rr_build=build\aarch64le"

:setup
if not defined QNX_HOST if exist "%USERPROFILE%\qnx800\qnxsdp-env.bat" call "%USERPROFILE%\qnx800\qnxsdp-env.bat" >nul
@echo off
where qcc >nul 2>&1
if errorlevel 1 goto sdk_missing
where secpolcompile >nul 2>&1
if errorlevel 1 goto sdk_missing
cd /d "%~dp0"
if errorlevel 1 exit /b %errorlevel%
if not exist "%rr_build%" mkdir "%rr_build%"
if not exist "%rr_build%" exit /b 1
qcc -V%rr_target% -D_QNX_SOURCE -std=c11 -Wall -Wextra -Werror -O2 receipt.c issuer.c sealed_recording.c obd_capture.c probe.c -lsecpol -lcrypto -o "%rr_build%\repair-receipt"
if errorlevel 1 exit /b %errorlevel%
secpolcompile -o "%rr_build%\secpol.bin" policy.conf
exit /b %errorlevel%

:usage
echo Usage: build-qnx.cmd [x86_64^|aarch64le] 1>&2
exit /b 2

:sdk_missing
echo QNX build tools are missing. Load the QNX SDP 8.0 environment and try again. 1>&2
exit /b 2
