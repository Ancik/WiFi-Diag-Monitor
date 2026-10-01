@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WiFi-Diag-Monitor.ps1" -DurationMinutes 30 -IntervalSeconds 10 -PingTimeoutMs 1000 -OpenReportFolder
pause
