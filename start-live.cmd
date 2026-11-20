@echo off
setlocal
if not defined QNX_HOST if exist "%USERPROFILE%\qnx800\qnxsdp-env.bat" call "%USERPROFILE%\qnx800\qnxsdp-env.bat" >nul
@echo off
if not "%~1"=="" goto run
python "%~dp0live.py" --open
exit /b %errorlevel%

:run
python "%~dp0live.py" %*
exit /b %errorlevel%
