@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WiFi-Diag-Monitor.ps1" -DurationMinutes 60 -IntervalSeconds 10 -PingTimeoutMs 1000 -OpenReportFolder
pause
