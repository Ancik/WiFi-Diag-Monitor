@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WiFi-Diag-Monitor.ps1" -DurationMinutes 240 -IntervalSeconds 30 -PingTimeoutMs 1000 -OpenReportFolder
pause
