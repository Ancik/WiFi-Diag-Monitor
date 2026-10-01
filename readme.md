WiFi-Diag-Monitor

Vendor-neutral Wi-Fi diagnostics and monitoring tool for Windows 10/11.

WiFi-Diag-Monitor is a PowerShell-based diagnostic utility designed to investigate intermittent Wi-Fi, roaming, latency, packet-loss and connectivity problems directly from a Windows endpoint.

Instead of running a single connectivity test, the tool collects Wi-Fi and network telemetry over time and produces a complete diagnostic package with CSV logs, Windows events, raw system information and an offline HTML report with embedded charts.

No wireless controller or access-point credentials are required.

Features

Wi-Fi telemetry

The monitor collects:

SSID

BSSID / connected access point

Wi-Fi channel

frequency band

signal percentage

estimated RSSI in dBm

radio / PHY type

receive link rate

transmit link rate

authentication type

cipher

WLAN profile

connection state

Native WLAN API

The preferred data source is the Windows Native WLAN API (wlanapi.dll).

This avoids many of the parsing and localization problems associated with command-line output and makes Wi-Fi detection largely independent of the Windows display language.

Netsh fallback

If the Native WLAN API:

returns Access Denied,

returns Win32 error 5,

fails to return connected SSID/BSSID information,

the monitor automatically attempts to collect Wi-Fi information using:

netsh wlan show interfaces

The fallback parser supports common English and Polish netsh output.

The PowerShell source remains ASCII-safe to reduce encoding and mojibake problems in Windows PowerShell 5.1.

Network diagnostics continue even without Wi-Fi metadata

If SSID/BSSID information cannot be obtained, the monitor does not stop.

It continues collecting:

IPv4 configuration

default gateway

DNS servers

gateway latency and packet loss

DNS-server latency and packet loss

Internet-target latency and packet loss

This makes it possible to distinguish a Wi-Fi telemetry problem from an actual network connectivity problem.

Roaming detection

WiFi-Diag-Monitor tracks the currently associated BSSID.

When the client moves from one BSSID to another, the change is recorded as a roaming event.

The event includes:

previous SSID

current SSID

previous BSSID

current BSSID

channel

band

signal strength

estimated RSSI

Wi-Fi data source

This can help identify:

excessive roaming

unstable AP association

weak coverage

mesh transitions

band steering

AP handovers

Latency and packet-loss monitoring

Each monitoring cycle can test connectivity to:

default gateway

DNS server

Internet target 1

Internet target 2

Default Internet targets:

1.1.1.1
8.8.8.8

This makes it easier to determine where packet loss occurs.

For example:

Gateway loss
    ↓
Possible Wi-Fi / AP / local LAN issue

Gateway OK
Internet loss
    ↓
Possible WAN / routing / firewall / provider issue

Nearby Wi-Fi networks

At configurable intervals the monitor runs:

netsh wlan show networks mode=bssid

The raw scan output is stored for later analysis.

This can be useful when investigating:

channel congestion

overlapping WLANs

nearby APs

multiple BSSIDs

changing radio environment

Nearby scanning can also be disabled.

Windows event collection

At the end of the monitoring session, the tool collects relevant Windows events.

Sources include:

Microsoft-Windows-WLAN-AutoConfig/Operational

System event log

Network-related providers are filtered where possible, including WLAN, TCP/IP, DHCP, DNS, NDIS and network-adapter events.

This provides additional context around:

WLAN disconnects

reconnects

DHCP issues

adapter resets

driver-related events

network stack problems

Endpoint inventory

Each diagnostic run records basic endpoint information, including:

computer name

logged-on user

Windows version and build

system locale

UI language

PowerShell version

computer manufacturer

computer model

Wi-Fi adapter

Wi-Fi driver information

This is particularly useful when comparing the same Wi-Fi problem across multiple laptops or driver versions.

Offline HTML report

At the end of the monitoring session the tool generates:

summary.html

The report works completely offline.

No external dependencies are required:

no Internet connection

no CDN

no JavaScript libraries

no Excel

no external PowerShell modules

Charts are generated as embedded SVG.

The report includes visualizations for:

Wi-Fi connection state

signal percentage

estimated RSSI

gateway latency

Internet latency

BSSID distribution

Wi-Fi band distribution

channel distribution

Wi-Fi data-source distribution

Lightweight by design

WiFi-Diag-Monitor does not run a speed test.

It only generates small diagnostic probes such as ICMP pings and normal Windows WLAN queries.

This makes it suitable for investigating unstable connections without significantly affecting the network being measured.

Requirements

Windows 10 or Windows 11

Windows PowerShell 5.1 or compatible PowerShell environment

Wi-Fi adapter for WLAN-specific telemetry

Administrator privileges are useful for obtaining the most complete diagnostic information, but the monitor is designed to continue collecting whatever information is available when some data cannot be accessed.

No third-party PowerShell modules are required.

Quick start

Open PowerShell in the directory containing the script and run:

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WiFi-Diag-Monitor.ps1 -DurationMinutes 5 -IntervalSeconds 10 -PingTimeoutMs 1000 -OpenReportFolder

This performs a five-minute diagnostic run with a ten-second sampling interval.

When monitoring is complete, the report directory opens automatically.

Included launchers

For convenience, the repository includes BAT launchers for common monitoring durations:

Run-WiFi-Diag-Monitor-30min.bat
Run-WiFi-Diag-Monitor-1h.bat
Run-WiFi-Diag-Monitor-2h.bat
Run-WiFi-Diag-Monitor-4h.bat
Run-WiFi-Diag-Monitor-custom.bat

The custom launcher asks for:

monitoring duration

sampling interval

This allows the tool to be used by support technicians without manually entering PowerShell parameters.

Main parameters

Parameter

Description

Default

DurationMinutes

Monitoring duration

30

IntervalSeconds

Sampling interval

10

InternetTargets

Internet hosts used for connectivity tests

1.1.1.1, 8.8.8.8

NearbyScanIntervalSeconds

Nearby WLAN scan interval

60

EventLookbackHours

Windows Event Log lookback period

24

PingTimeoutMs

ICMP timeout

1000

NoNearbyScan

Disable nearby WLAN scans

Off

OpenReportFolder

Open output directory when monitoring completes

Off

Quiet

Reduce console output

Off

Example:

.\WiFi-Diag-Monitor.ps1 `
    -DurationMinutes 60 `
    -IntervalSeconds 10 `
    -PingTimeoutMs 1000 `
    -OpenReportFolder

Output

Each execution creates a dedicated directory similar to:

WiFiDiag_COMPUTERNAME_20261001_103000

Example structure:

WiFiDiag_COMPUTERNAME_20261001_103000
│
├── summary.html
├── summary.txt
├── runtime.log
├── wifi_samples.csv
├── wifi_roaming_events.csv
├── wlan_autoconfig_events.csv
├── network_system_events.csv
├── endpoint_inventory.csv
├── wifi_adapter_drivers.csv
│
├── Raw
│   ├── ipconfig_all_start.txt
│   ├── ipconfig_all_end.txt
│   ├── route_print_start.txt
│   ├── route_print_end.txt
│   ├── netsh_wlan_interfaces_start.txt
│   ├── netsh_wlan_interfaces_end.txt
│   ├── netsh_wlan_drivers_start.txt
│   ├── netsh_wlan_drivers_end.txt
│   ├── endpoint_inventory.txt
│   └── wifi_adapter_drivers.txt
│
└── NearbyNetworks
    ├── nearby_networks_YYYYMMDD_HHMMSS.txt
    └── ...

Some files are created only when corresponding data or events are available.

Wi-Fi data sources

The WiFiDataSource field shows how WLAN information was collected.

NativeWlanApi

Preferred source.

Wi-Fi information was retrieved directly through the Windows Native WLAN API.

WiFiDataSource = NativeWlanApi

NetshRegexFallback

The Native WLAN API did not provide sufficient information and the localized netsh wlan show interfaces output was successfully parsed.

WiFiDataSource = NetshRegexFallback

NetworkOnly

Wi-Fi-specific information could not be obtained.

IP, gateway, DNS and Internet diagnostics continue normally.

WiFiDataSource = NetworkOnly

Troubleshooting

Native WLAN API returns Win32 error 5

If the diagnostic report shows an access-denied condition from the Native WLAN API, check the WiFiDataSource field.

The script should attempt to switch to:

NetshRegexFallback

The diagnostic session can still continue.

SSID or BSSID is missing

Check:

Raw\netsh_wlan_interfaces_start.txt

The localized netsh format may differ from currently supported English/Polish output.

That raw file can be used to extend the fallback parser for another Windows language or output format.

Wi-Fi information is unavailable but ping data exists

This is expected behavior.

The monitor deliberately keeps the network diagnostics running even if WLAN-specific data cannot be collected.

Look at:

GatewayPingOk
GatewayPingMs
DnsPingOk
DnsPingMs
Internet1PingOk
Internet1PingMs
Internet2PingOk
Internet2PingMs

to determine whether actual connectivity was affected.

Understanding Estimated RSSI

EstimatedRSSI_dBm is calculated from the Windows WLAN signal-quality percentage.

It is useful for observing relative signal changes over time, but it should not be treated as a direct RF measurement from the access point or WLAN controller.

For RF troubleshooting, controller-side RSSI/SNR data is generally more authoritative.

Typical use cases

WiFi-Diag-Monitor can help investigate:

intermittent Wi-Fi disconnects

random Internet interruptions

high wireless latency

packet loss

unstable roaming

frequent AP changes

weak Wi-Fi coverage

Wi-Fi driver problems

DHCP/DNS-related incidents

home and SMB wireless troubleshooting

enterprise endpoint troubleshooting

problems that are difficult to reproduce during a short support session

A typical workflow is to start the monitor, let the user continue working normally until the issue occurs, and then review the generated HTML report, CSV telemetry and Windows events.

Privacy and security

The tool does not require:

WLAN controller credentials

access-point credentials

cloud-management credentials

The script does not collect Wi-Fi passwords.

However, diagnostic output can contain infrastructure information such as:

computer name

username

IP addresses

SSID

BSSID / AP MAC addresses

DNS servers

gateway addresses

Wi-Fi adapter and driver information

Review diagnostic packages before publishing or sharing them externally.

Version

Current version:

v1.5.6-netsh-regex-fallback

Major changes in v1.5.6:

regex-based netsh fallback parser

ASCII-safe PowerShell source

improved matching of Polish localized netsh labels

NetshRegexFallback data-source reporting

fallback attempts when the Native WLAN API returns Access Denied or incomplete SSID/BSSID data

License

Add the license appropriate for your use case, for example:

MIT License

Apache License 2.0

proprietary/internal-use license

A LICENSE file should be included in the repository.

Disclaimer

WiFi-Diag-Monitor is a diagnostic aid.

Its output should be interpreted together with WLAN infrastructure logs, access-point/controller telemetry, network monitoring and other troubleshooting information when available.