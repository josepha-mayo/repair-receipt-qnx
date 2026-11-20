@echo off
setlocal
if not defined QNX_HOST if exist "%USERPROFILE%\qnx800\qnxsdp-env.bat" call "%USERPROFILE%\qnx800\qnxsdp-env.bat" >nul
@echo off
where qcc >nul 2>&1
if errorlevel 1 goto sdk_missing
where secpolcompile >nul 2>&1
if errorlevel 1 goto sdk_missing
cd /d "%~dp0"
if errorlevel 1 exit /b %errorlevel%
if not exist build mkdir build
qcc -Vgcc_ntox86_64 -D_QNX_SOURCE -std=c11 -Wall -Wextra -Werror -O2 receipt.c issuer.c sealed_recording.c obd_capture.c probe.c -lsecpol -lcrypto -o build/repair-receipt
if errorlevel 1 exit /b %errorlevel%
secpolcompile -o build/secpol.bin policy.conf
exit /b %errorlevel%

:sdk_missing
echo QNX build tools are missing. Load the QNX SDP 8.0 environment and try again. 1>&2
exit /b 2
