@echo off
cd /d "%~dp0"
set /p DURATION=Duration in minutes (example 5, 30, 60, 120): 
set /p INTERVAL=Interval in seconds (example 10): 
if "%DURATION%"=="" set DURATION=30
if "%INTERVAL%"=="" set INTERVAL=10
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WiFi-Diag-Monitor.ps1" -DurationMinutes %DURATION% -IntervalSeconds %INTERVAL% -PingTimeoutMs 1000 -OpenReportFolder
pause
