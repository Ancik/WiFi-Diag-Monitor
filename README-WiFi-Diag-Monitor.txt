WiFi-Diag-Monitor v1.5.6-netsh-regex-fallback

Vendor-neutral Windows Wi-Fi diagnostics monitor.

Key points:
- No speedtest; the script does not generate heavy traffic.
- Native WLAN API is tried first.
- If Native WLAN API returns Access Denied / Win32 error 5 or does not provide SSID/BSSID, the script tries NetshRegexFallback.
- NetshRegexFallback is ASCII-only but can match common English/Polish netsh labels using regex wildcards for diacritics.
- If Wi-Fi details are still unavailable, IP/gateway/DNS/ping diagnostics continue.
- Offline summary.html includes embedded SVG charts; no Internet/CDN/JavaScript/Excel modules required.

Recommended first run:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WiFi-Diag-Monitor.ps1 -DurationMinutes 5 -IntervalSeconds 10 -PingTimeoutMs 1000 -OpenReportFolder

If NativeWlanApi shows Win32 error 5, check whether WiFiDataSource switches to NetshRegexFallback.
If it still cannot parse SSID/BSSID, review Raw\netsh_wlan_interfaces_start.txt and send that file for parser tuning.
