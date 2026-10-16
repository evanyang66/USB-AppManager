@echo off
setlocal
cd /d "%~dp0"
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0WinBatch.ps1" -Demo
exit /b 0
