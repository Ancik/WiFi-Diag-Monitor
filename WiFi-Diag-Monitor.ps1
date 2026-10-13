<#
.SYNOPSIS
  Vendor-neutral Wi-Fi diagnostics monitor for Windows 10/11.

.DESCRIPTION
  WiFi-Diag-Monitor v1.5.6-netsh-regex-fallback

  Collects Wi-Fi client-side telemetry over time:
  - SSID / BSSID / channel / band / signal / estimated RSSI / radio type / Tx/Rx rate
  - IP / gateway / DNS
  - packet loss and latency to gateway, DNS, and internet targets
  - BSSID changes as roaming between APs
  - WLAN AutoConfig and network-related system events
  - raw snapshots: netsh wlan, ipconfig, route, nearby networks
  - offline HTML charts embedded as SVG in summary.html
  - Native WLAN API collection with netsh and NetworkOnly fallbacks
  - endpoint inventory: OS language, PowerShell version, computer model, Wi-Fi adapter and driver

.NOTES
  No Wi-Fi controller/AP credentials are required.
  This script does not collect Wi-Fi passwords.
  This version is ASCII-only in PowerShell source to avoid encoding/mojibake parser issues.
#>

[CmdletBinding()]
param(
    [int]$DurationMinutes = 30,
    [int]$IntervalSeconds = 10,
    [string[]]$InternetTargets = @('1.1.1.1', '8.8.8.8'),
    [int]$NearbyScanIntervalSeconds = 60,
    [int]$EventLookbackHours = 24,
    [int]$PingTimeoutMs = 1000,
    [switch]$NoNearbyScan,
    [switch]$OpenReportFolder,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$script:NativeWlanApiReady = $false
$script:NativeWlanApiFailed = $false
$script:NativeWlanApiError = $null
$script:QuietMode = [bool]$Quiet
$script:runtimeLog = $null

function Get-ScriptRootSafe {
    if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) { return $PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return (Split-Path -Parent $MyInvocation.MyCommand.Path) }
    return (Get-Location).Path
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Convert-ToNumberSafe {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $clean = ($text -replace '[^0-9,\.\-]', '') -replace ',', '.'
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    $number = 0.0
    $ok = [double]::TryParse($clean, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)
    if ($ok) { return $number }
    return $null
}

function Convert-SignalPercentToEstimatedRssiDbm {
    param([object]$SignalPercent)
    $value = Convert-ToNumberSafe $SignalPercent
    if ($null -eq $value) { return $null }
    if ($value -lt 0) { $value = 0 }
    if ($value -gt 100) { $value = 100 }
    return [math]::Round(($value / 2.0) - 100, 0)
}

function Convert-ChannelToBand {
    param(
        [object]$Channel,
        [string]$BandFromNetsh
    )
    if (-not [string]::IsNullOrWhiteSpace($BandFromNetsh)) { return $BandFromNetsh.Trim() }
    $ch = Convert-ToNumberSafe $Channel
    if ($null -eq $ch) { return $null }
    if ($ch -ge 1 -and $ch -le 14) { return '2.4 GHz' }
    if ($ch -ge 32 -and $ch -le 177) { return '5 GHz' }
    if ($ch -gt 177) { return '6 GHz' }
    return 'Unknown'
}

function Get-NetshValue {
    param(
        [string]$Text,
        [string[]]$Labels
    )
    foreach ($label in $Labels) {
        $escaped = [regex]::Escape($label)
        $pattern = "(?im)^\s*$escaped\s*:\s*(.*?)\s*$"
        $match = [regex]::Match($Text, $pattern)
        if ($match.Success) { return $match.Groups[1].Value.Trim() }
    }
    return $null
}

function Initialize-NativeWlanApi {
    if ($script:NativeWlanApiReady) { return $true }
    if ($script:NativeWlanApiFailed) { return $false }

    $existingType = 'WlanNativeHelper' -as [type]
    if ($existingType) {
        $script:NativeWlanApiReady = $true
        return $true
    }

    $code = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class WlanConnectionInfo
{
    public string Name { get; set; }
    public string Description { get; set; }
    public string GUID { get; set; }
    public string State { get; set; }
    public string SSID { get; set; }
    public string BSSID { get; set; }
    public string RadioType { get; set; }
    public string Authentication { get; set; }
    public string Cipher { get; set; }
    public string Profile { get; set; }
    public string ConnectionMode { get; set; }
    public int Channel { get; set; }
    public int FrequencyMHz { get; set; }
    public string Band { get; set; }
    public double RxMbps { get; set; }
    public double TxMbps { get; set; }
    public int SignalPercent { get; set; }
    public int EstimatedRSSI_dBm { get; set; }
    public string DataSource { get; set; }
    public string DetectionStatus { get; set; }
}

public static class WlanNativeHelper
{
    private const int WLAN_CLIENT_VERSION_XP_SP2 = 1;
    private const int WLAN_CLIENT_VERSION_LONGHORN = 2;
    private const int WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7;

    private enum WLAN_INTERFACE_STATE
    {
        NotReady = 0, Connected = 1, AdHocNetworkFormed = 2, Disconnecting = 3,
        Disconnected = 4, Associating = 5, Discovering = 6, Authenticating = 7
    }

    private enum WLAN_CONNECTION_MODE
    {
        Profile = 0, TemporaryProfile = 1, DiscoverySecure = 2,
        DiscoveryUnsecure = 3, Auto = 4, Invalid = 5
    }

    private enum WLAN_OPCODE_VALUE_TYPE { QueryOnly = 0, SetByGroupPolicy = 1, SetByUser = 2, Invalid = 3 }
    private enum DOT11_BSS_TYPE { Infrastructure = 1, Independent = 2, Any = 3 }
    private enum DOT11_PHY_TYPE
    {
        Unknown = 0, Any = 0, FHSS = 1, DSSS = 2, IRBaseband = 3,
        OFDM = 4, HRDSSS = 5, ERP = 6, HT = 7, VHT = 8, DMG = 9, HE = 10, EHT = 11
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strInterfaceDescription;
        public WLAN_INTERFACE_STATE isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DOT11_SSID
    {
        public UInt32 uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public DOT11_SSID dot11Ssid;
        public DOT11_BSS_TYPE dot11BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] dot11Bssid;
        public DOT11_PHY_TYPE dot11PhyType;
        public UInt32 uDot11PhyIndex;
        public UInt32 wlanSignalQuality;
        public UInt32 ulRxRate;
        public UInt32 ulTxRate;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_SECURITY_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Bool)] public bool bSecurityEnabled;
        [MarshalAs(UnmanagedType.Bool)] public bool bOneXEnabled;
        public UInt32 dot11AuthAlgorithm;
        public UInt32 dot11CipherAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_CONNECTION_ATTRIBUTES
    {
        public WLAN_INTERFACE_STATE isState;
        public WLAN_CONNECTION_MODE wlanConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strProfileName;
        public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_RATE_SET
    {
        public UInt32 uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)] public UInt16[] usRateSet;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_BSS_ENTRY
    {
        public DOT11_SSID dot11Ssid;
        public UInt32 uPhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] dot11Bssid;
        public DOT11_BSS_TYPE dot11BssType;
        public DOT11_PHY_TYPE dot11BssPhyType;
        public Int32 lRssi;
        public UInt32 uLinkQuality;
        [MarshalAs(UnmanagedType.Bool)] public bool bInRegDomain;
        public UInt16 usBeaconPeriod;
        public UInt64 ullTimestamp;
        public UInt64 ullHostTimestamp;
        public UInt16 usCapabilityInformation;
        public UInt32 ulChCenterFrequency;
        public WLAN_RATE_SET wlanRateSet;
        public UInt32 ulIeOffset;
        public UInt32 ulIeSize;
    }

    [DllImport("wlanapi.dll", SetLastError = true)]
    private static extern int WlanOpenHandle(UInt32 dwClientVersion, IntPtr pReserved, out UInt32 pdwNegotiatedVersion, out IntPtr phClientHandle);

    [DllImport("wlanapi.dll", SetLastError = true)]
    private static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    private static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    private static extern int WlanQueryInterface(IntPtr hClientHandle, ref Guid pInterfaceGuid, Int32 OpCode, IntPtr pReserved, out UInt32 pdwDataSize, out IntPtr ppData, out WLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType);

    [DllImport("wlanapi.dll", SetLastError = true)]
    private static extern int WlanGetNetworkBssList(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, DOT11_BSS_TYPE dot11BssType, bool bSecurityEnabled, IntPtr pReserved, out IntPtr ppWlanBssList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    private static extern void WlanFreeMemory(IntPtr pMemory);

    public static WlanConnectionInfo[] GetInterfaces()
    {
        List<WlanConnectionInfo> result = new List<WlanConnectionInfo>();
        IntPtr clientHandle = IntPtr.Zero;
        UInt32 negotiatedVersion;
        int ret = WlanOpenHandle(WLAN_CLIENT_VERSION_LONGHORN, IntPtr.Zero, out negotiatedVersion, out clientHandle);
        if (ret != 0)
        {
            ret = WlanOpenHandle(WLAN_CLIENT_VERSION_XP_SP2, IntPtr.Zero, out negotiatedVersion, out clientHandle);
            if (ret != 0) throw new InvalidOperationException("WlanOpenHandle failed. Win32 error: " + ret.ToString());
        }

        IntPtr ifList = IntPtr.Zero;
        try
        {
            ret = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out ifList);
            if (ret != 0) throw new InvalidOperationException("WlanEnumInterfaces failed. Win32 error: " + ret.ToString());

            int numberOfItems = Marshal.ReadInt32(ifList, 0);
            long listIterator = ifList.ToInt64() + 8;
            int itemSize = Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));

            for (int i = 0; i < numberOfItems; i++)
            {
                IntPtr itemPtr = new IntPtr(listIterator);
                WLAN_INTERFACE_INFO iface = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(itemPtr, typeof(WLAN_INTERFACE_INFO));
                listIterator += itemSize;

                WlanConnectionInfo info = new WlanConnectionInfo();
                info.Name = iface.strInterfaceDescription;
                info.Description = iface.strInterfaceDescription;
                info.GUID = iface.InterfaceGuid.ToString();
                info.State = StateToString(iface.isState);
                info.Channel = -1;
                info.FrequencyMHz = -1;
                info.SignalPercent = -1;
                info.EstimatedRSSI_dBm = -999;
                info.RxMbps = -1;
                info.TxMbps = -1;
                info.DataSource = "NativeWlanApi";
                info.DetectionStatus = "Interface enumerated through Native WLAN API";

                IntPtr data = IntPtr.Zero;
                UInt32 dataSize;
                WLAN_OPCODE_VALUE_TYPE opcodeType;
                int qret = WlanQueryInterface(clientHandle, ref iface.InterfaceGuid, WLAN_INTF_OPCODE_CURRENT_CONNECTION, IntPtr.Zero, out dataSize, out data, out opcodeType);
                try
                {
                    if (qret == 0 && data != IntPtr.Zero)
                    {
                        WLAN_CONNECTION_ATTRIBUTES attr = (WLAN_CONNECTION_ATTRIBUTES)Marshal.PtrToStructure(data, typeof(WLAN_CONNECTION_ATTRIBUTES));
                        info.State = StateToString(attr.isState);
                        info.Profile = attr.strProfileName;
                        info.ConnectionMode = ConnectionModeToString(attr.wlanConnectionMode);

                        if (attr.isState == WLAN_INTERFACE_STATE.Connected)
                        {
                            info.SSID = DecodeSsid(attr.wlanAssociationAttributes.dot11Ssid);
                            info.BSSID = FormatMac(attr.wlanAssociationAttributes.dot11Bssid);
                            info.RadioType = PhyTypeToString(attr.wlanAssociationAttributes.dot11PhyType);
                            info.SignalPercent = SafeSignal(attr.wlanAssociationAttributes.wlanSignalQuality);
                            info.EstimatedRSSI_dBm = (int)Math.Round((info.SignalPercent / 2.0) - 100.0);
                            info.RxMbps = RateToMbps(attr.wlanAssociationAttributes.ulRxRate);
                            info.TxMbps = RateToMbps(attr.wlanAssociationAttributes.ulTxRate);
                            info.Authentication = AuthToString(attr.wlanSecurityAttributes.dot11AuthAlgorithm);
                            info.Cipher = CipherToString(attr.wlanSecurityAttributes.dot11CipherAlgorithm);

                            int freq;
                            int ch = TryGetChannel(clientHandle, iface.InterfaceGuid, attr.wlanAssociationAttributes.dot11Bssid, out freq);
                            info.Channel = ch;
                            info.FrequencyMHz = freq;
                            info.Band = BandFromFrequencyOrChannel(freq, ch);
                            info.DetectionStatus = "Connected interface read through Native WLAN API";
                        }
                    }
                    else
                    {
                        info.DetectionStatus = "Native WLAN API current connection query returned Win32 error " + qret.ToString();
                    }
                }
                finally
                {
                    if (data != IntPtr.Zero) WlanFreeMemory(data);
                }

                result.Add(info);
            }
        }
        finally
        {
            if (ifList != IntPtr.Zero) WlanFreeMemory(ifList);
            if (clientHandle != IntPtr.Zero) WlanCloseHandle(clientHandle, IntPtr.Zero);
        }

        return result.ToArray();
    }

    private static string DecodeSsid(DOT11_SSID ssid)
    {
        if (ssid.ucSSID == null || ssid.uSSIDLength == 0) return null;
        int len = (int)Math.Min(ssid.uSSIDLength, 32);
        return Encoding.UTF8.GetString(ssid.ucSSID, 0, len).TrimEnd('\0');
    }

    private static string FormatMac(byte[] bytes)
    {
        if (bytes == null || bytes.Length < 6) return null;
        return BitConverter.ToString(bytes, 0, 6).Replace("-", ":").ToLowerInvariant();
    }

    private static bool SameMac(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length < 6 || b.Length < 6) return false;
        for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
        return true;
    }

    private static int SafeSignal(UInt32 quality)
    {
        if (quality > 100) return 100;
        return (int)quality;
    }

    private static double RateToMbps(UInt32 rawRate)
    {
        if (rawRate == 0) return -1;
        double v = rawRate;
        if (v > 1000000.0) return Math.Round(v / 1000000.0, 2);
        if (v > 1000.0) return Math.Round(v / 1000.0, 2);
        return Math.Round(v, 2);
    }

    private static int TryGetChannel(IntPtr clientHandle, Guid interfaceGuid, byte[] bssid, out int frequencyMHz)
    {
        frequencyMHz = -1;
        IntPtr listPtr = IntPtr.Zero;
        try
        {
            int ret = WlanGetNetworkBssList(clientHandle, ref interfaceGuid, IntPtr.Zero, DOT11_BSS_TYPE.Any, false, IntPtr.Zero, out listPtr);
            if (ret != 0 || listPtr == IntPtr.Zero) return -1;

            int count = Marshal.ReadInt32(listPtr, 4);
            long entryPtrValue = listPtr.ToInt64() + 8;
            int entrySize = Marshal.SizeOf(typeof(WLAN_BSS_ENTRY));
            for (int i = 0; i < count; i++)
            {
                IntPtr entryPtr = new IntPtr(entryPtrValue);
                WLAN_BSS_ENTRY entry = (WLAN_BSS_ENTRY)Marshal.PtrToStructure(entryPtr, typeof(WLAN_BSS_ENTRY));
                if (SameMac(entry.dot11Bssid, bssid))
                {
                    frequencyMHz = (int)(entry.ulChCenterFrequency / 1000);
                    return FrequencyToChannel(frequencyMHz);
                }
                entryPtrValue += entrySize;
            }
        }
        catch { return -1; }
        finally { if (listPtr != IntPtr.Zero) WlanFreeMemory(listPtr); }
        return -1;
    }

    private static int FrequencyToChannel(int freqMHz)
    {
        if (freqMHz == 2484) return 14;
        if (freqMHz >= 2412 && freqMHz <= 2472) return (freqMHz - 2407) / 5;
        if (freqMHz >= 5000 && freqMHz <= 5895) return (freqMHz - 5000) / 5;
        if (freqMHz >= 5955 && freqMHz <= 7115) return (freqMHz - 5950) / 5;
        return -1;
    }

    private static string BandFromFrequencyOrChannel(int freqMHz, int channel)
    {
        if (freqMHz >= 2400 && freqMHz < 2500) return "2.4 GHz";
        if (freqMHz >= 5000 && freqMHz < 5925) return "5 GHz";
        if (freqMHz >= 5925 && freqMHz <= 7125) return "6 GHz";
        if (channel >= 1 && channel <= 14) return "2.4 GHz";
        if (channel >= 32 && channel <= 177) return "5 GHz";
        if (channel > 177) return "6 GHz";
        return null;
    }

    private static string StateToString(WLAN_INTERFACE_STATE state) { return state.ToString(); }
    private static string ConnectionModeToString(WLAN_CONNECTION_MODE mode) { return mode.ToString(); }

    private static string PhyTypeToString(DOT11_PHY_TYPE phy)
    {
        switch (phy)
        {
            case DOT11_PHY_TYPE.HT: return "802.11n / HT";
            case DOT11_PHY_TYPE.VHT: return "802.11ac / VHT";
            case DOT11_PHY_TYPE.HE: return "802.11ax / HE";
            case DOT11_PHY_TYPE.EHT: return "802.11be / EHT";
            case DOT11_PHY_TYPE.OFDM: return "802.11a/g / OFDM";
            case DOT11_PHY_TYPE.ERP: return "802.11g / ERP";
            case DOT11_PHY_TYPE.HRDSSS: return "802.11b / HR-DSSS";
            default: return phy.ToString();
        }
    }

    private static string AuthToString(UInt32 alg)
    {
        switch (alg)
        {
            case 1: return "Open";
            case 2: return "Shared";
            case 3: return "WPA-Enterprise";
            case 4: return "WPA-Personal";
            case 5: return "WPA-None";
            case 6: return "WPA2-Enterprise / RSNA";
            case 7: return "WPA2-Personal / RSNA-PSK";
            case 8: return "WPA3-Enterprise";
            case 9: return "WPA3-Personal / SAE";
            case 10: return "WPA3-Enterprise 192-bit";
            default: return "AuthAlgorithm " + alg.ToString();
        }
    }

    private static string CipherToString(UInt32 alg)
    {
        switch (alg)
        {
            case 0x00: return "None";
            case 0x01: return "WEP40";
            case 0x02: return "TKIP";
            case 0x04: return "AES-CCMP";
            case 0x05: return "WEP104";
            case 0x06: return "BIP";
            case 0x08: return "GCMP";
            case 0x09: return "GCMP-256";
            case 0x0A: return "CCMP-256";
            default: return "CipherAlgorithm " + alg.ToString();
        }
    }
}
"@

    try {
        Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop
        $script:NativeWlanApiReady = $true
        return $true
    } catch {
        $script:NativeWlanApiFailed = $true
        $script:NativeWlanApiError = $_.Exception.Message
        return $false
    }
}

function Get-WlanInterfaceInfoNative {
    if (-not (Initialize-NativeWlanApi)) { return $null }
    try {
        $items = @([WlanNativeHelper]::GetInterfaces())
        if (@($items).Count -eq 0) { return $null }

        $selected = @($items | Where-Object { $_.SSID -and $_.BSSID } | Select-Object -First 1)
        if (@($selected).Count -eq 0) { $selected = @($items | Select-Object -First 1) }
        if (@($selected).Count -eq 0) { return $null }

        $n = $selected[0]
        $adapter = $null
        try {
            $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { [string]$_.InterfaceGuid -eq [string]$n.GUID } | Select-Object -First 1
            if (($null -eq $adapter) -and $n.Description) {
                $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -eq $n.Description } | Select-Object -First 1
            }
        } catch {}

        $alias = $n.Name
        $desc = $n.Description
        $mac = $null
        if ($adapter) {
            $alias = $adapter.Name
            $desc = $adapter.InterfaceDescription
            $mac = $adapter.MacAddress
        }

        $channel = $null
        $freq = $null
        $signal = $null
        $rssi = $null
        $rx = $null
        $tx = $null
        if ($n.Channel -ge 0) { $channel = $n.Channel }
        if ($n.FrequencyMHz -ge 0) { $freq = $n.FrequencyMHz }
        if ($n.SignalPercent -ge 0) { $signal = $n.SignalPercent }
        if ($n.EstimatedRSSI_dBm -gt -900) { $rssi = $n.EstimatedRSSI_dBm }
        if ($n.RxMbps -ge 0) { $rx = $n.RxMbps }
        if ($n.TxMbps -ge 0) { $tx = $n.TxMbps }

        $bandValue = $n.Band
        if ([string]::IsNullOrWhiteSpace($bandValue)) {
            $bandValue = Convert-ChannelToBand -Channel $channel -BandFromNetsh $null
        }
        $rssiValue = $rssi
        if ($null -eq $rssiValue) { $rssiValue = Convert-SignalPercentToEstimatedRssiDbm $signal }

        return [pscustomobject]@{
            Name = $alias
            Description = $desc
            GUID = $n.GUID
            PhysicalAddress = $mac
            State = $n.State
            SSID = $n.SSID
            BSSID = $n.BSSID
            RadioType = $n.RadioType
            Authentication = $n.Authentication
            Cipher = $n.Cipher
            Profile = $n.Profile
            ConnectionMode = $n.ConnectionMode
            Channel = $channel
            FrequencyMHz = $freq
            Band = $bandValue
            RxMbps = $rx
            TxMbps = $tx
            SignalPercent = $signal
            EstimatedRSSI_dBm = $rssiValue
            DataSource = 'NativeWlanApi'
            DetectionStatus = $n.DetectionStatus
            Raw = $null
        }
    } catch {
        $script:NativeWlanApiError = $_.Exception.Message
        return $null
    }
}


function Get-NetshValueRegex {
    param(
        [string]$Text,
        [string[]]$LabelPatterns
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    foreach ($labelPattern in $LabelPatterns) {
        # An empty value must not consume the next line's label.
        $pattern = "(?im)^[ \t]*(?:$labelPattern)[ \t]*:[ \t]*([^\r\n]*?)[ \t]*\r?$"
        $match = [regex]::Match($Text, $pattern)
        if ($match.Success) {
            $value = $match.Groups[1].Value.Trim()
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
            return ''
        }
    }
    return $null
}

function Get-WlanInterfaceInfoNetsh {
    $raw = ''
    try { $raw = netsh wlan show interfaces 2>&1 | Out-String } catch { $raw = "ERROR: $($_.Exception.Message)" }

    # Netsh output is localized, so this parser avoids non-ASCII source text.
    # It uses regex wildcards for labels with Polish diacritics, e.g. Kanal/Kana. and Sygnal/Sygna.
    $blocks = @()
    $split = $raw -split "(\r?\n){2,}"
    foreach ($part in $split) {
        if ($part -match '(?im)^\s*(?:Name|Nazwa|Interface name)\s*:') { $blocks += $part }
    }
    if (@($blocks).Count -eq 0) { $blocks = @($raw) }

    $items = @()
    foreach ($block in $blocks) {
        $name = Get-NetshValueRegex -Text $block -LabelPatterns @('Name','Nazwa','Interface name')
        $description = Get-NetshValueRegex -Text $block -LabelPatterns @('Description','Opis')
        $guid = Get-NetshValueRegex -Text $block -LabelPatterns @('GUID')
        $mac = Get-NetshValueRegex -Text $block -LabelPatterns @('Physical address','Adres fizyczny','Adres MAC')
        $state = Get-NetshValueRegex -Text $block -LabelPatterns @('State','Stan')
        $ssid = Get-NetshValueRegex -Text $block -LabelPatterns @('SSID','Identyfikator\s+SSID')
        $bssid = Get-NetshValueRegex -Text $block -LabelPatterns @('BSSID')
        $radio = Get-NetshValueRegex -Text $block -LabelPatterns @('Radio type','Typ radia')
        $auth = Get-NetshValueRegex -Text $block -LabelPatterns @('Authentication','Uwierzytelnianie')
        $cipher = Get-NetshValueRegex -Text $block -LabelPatterns @('Cipher','Szyfrowanie')
        $wlanProfile = Get-NetshValueRegex -Text $block -LabelPatterns @('Profile','Profil')
        $connectionMode = Get-NetshValueRegex -Text $block -LabelPatterns @('Connection mode','Tryb po..czenia','Tryb polaczenia')
        $channel = Get-NetshValueRegex -Text $block -LabelPatterns @('Channel','Kana.','Kanal')
        $bandFromNetsh = Get-NetshValueRegex -Text $block -LabelPatterns @('Band','Pasmo')
        $rxRate = Get-NetshValueRegex -Text $block -LabelPatterns @('Receive rate \(Mbps\)','Receive rate \(Mb/s\)','Szybko.. odbierania.*','Szybkosc odbierania.*')
        $txRate = Get-NetshValueRegex -Text $block -LabelPatterns @('Transmit rate \(Mbps\)','Transmit rate \(Mb/s\)','Szybko.. transmisji.*','Szybkosc transmisji.*')
        $signal = Get-NetshValueRegex -Text $block -LabelPatterns @('Signal','Sygna.','Sygnal')
        $signalPercent = Convert-ToNumberSafe $signal
        $bandValue = Convert-ChannelToBand -Channel $channel -BandFromNetsh $bandFromNetsh
        $rssiValue = Convert-SignalPercentToEstimatedRssiDbm $signalPercent

        $statusText = 'Parsed from netsh wlan show interfaces using regex fallback output'
        if ([string]::IsNullOrWhiteSpace($ssid) -or [string]::IsNullOrWhiteSpace($bssid)) {
            $statusText = 'Netsh fallback ran, but SSID/BSSID were not parsed. Review Raw/netsh_wlan_interfaces_start.txt.'
        }

        $items += [pscustomobject]@{
            Name = $name
            Description = $description
            GUID = $guid
            PhysicalAddress = $mac
            State = $state
            SSID = $ssid
            BSSID = $bssid
            RadioType = $radio
            Authentication = $auth
            Cipher = $cipher
            Profile = $wlanProfile
            ConnectionMode = $connectionMode
            Channel = $channel
            FrequencyMHz = $null
            Band = $bandValue
            RxMbps = (Convert-ToNumberSafe $rxRate)
            TxMbps = (Convert-ToNumberSafe $txRate)
            SignalPercent = $signalPercent
            EstimatedRSSI_dBm = $rssiValue
            DataSource = 'NetshRegexFallback'
            DetectionStatus = $statusText
            Raw = $block
        }
    }

    $connected = @($items | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.BSSID) -and -not [string]::IsNullOrWhiteSpace([string]$_.SSID) } | Select-Object -First 1)
    if (@($connected).Count -gt 0) { return $connected[0] }
    $first = @($items | Select-Object -First 1)
    if (@($first).Count -gt 0) { return $first[0] }
    return $null
}

function Test-WlanInfoHasConnectedData {
    param([object]$Info)
    if ($null -eq $Info) { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Info.SSID) -and -not [string]::IsNullOrWhiteSpace([string]$Info.BSSID)) {
        return $true
    }
    return $false
}

function Get-WlanInterfaceInfo {
    $native = Get-WlanInterfaceInfoNative
    if (Test-WlanInfoHasConnectedData -Info $native) {
        return $native
    }

    $netsh = Get-WlanInterfaceInfoNetsh
    if (Test-WlanInfoHasConnectedData -Info $netsh) {
        if ($null -ne $native) {
            $nativeStatus = [string]$native.DetectionStatus
            if ([string]::IsNullOrWhiteSpace($nativeStatus)) { $nativeStatus = 'Native WLAN API did not return connected SSID/BSSID data.' }
            $netsh.DetectionStatus = "Native WLAN API did not return connected data ($nativeStatus). Using netsh fallback."
        } elseif ($script:NativeWlanApiError) {
            $netsh.DetectionStatus = "Native WLAN API unavailable or failed: $($script:NativeWlanApiError). Using netsh fallback."
        }
        return $netsh
    }

    if ($null -ne $native) {
        return $native
    }
    if ($null -ne $netsh) {
        return $netsh
    }
    return $null
}

function Get-EndpointInventorySummary {
    $os = $null
    $cs = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue } catch { try { $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue } catch {} }
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue } catch { try { $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue } catch {} }

    $systemLocale = $null
    $uiLanguage = $null
    try { $systemLocale = (Get-Culture).Name } catch {}
    try { $uiLanguage = (Get-UICulture).Name } catch {}

    return [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        OSCaption = $(if ($os) { $os.Caption } else { $null })
        OSVersion = $(if ($os) { $os.Version } else { $null })
        OSBuildNumber = $(if ($os) { $os.BuildNumber } else { $null })
        OSArchitecture = $(if ($os) { $os.OSArchitecture } else { $null })
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        SystemLocale = $systemLocale
        UILanguage = $uiLanguage
        ComputerManufacturer = $(if ($cs) { $cs.Manufacturer } else { $null })
        ComputerModel = $(if ($cs) { $cs.Model } else { $null })
        DomainOrWorkgroup = $(if ($cs) { $cs.Domain } else { $null })
    }
}

function Get-WifiAdapterDriverInventory {
    $results = @()
    $wifiPattern = 'Wi-Fi|Wireless|WLAN|802\.11|Realtek|Qualcomm|MediaTek|Broadcom|Intel.*Wireless|AX2|AX20|AX21'

    try {
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match $wifiPattern })
        foreach ($a in $adapters) {
            $drv = $null
            try {
                $drv = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object {
                    $_.DeviceName -eq $a.InterfaceDescription -or $_.FriendlyName -eq $a.InterfaceDescription -or $_.DeviceName -match [regex]::Escape($a.InterfaceDescription)
                } | Select-Object -First 1
            } catch {}
            $results += [pscustomobject]@{
                Name = $a.Name
                InterfaceDescription = $a.InterfaceDescription
                Status = $a.Status
                LinkSpeed = $a.LinkSpeed
                MacAddress = $a.MacAddress
                InterfaceGuid = $a.InterfaceGuid
                DriverProviderName = $(if ($drv) { $drv.DriverProviderName } else { $null })
                DriverVersion = $(if ($drv) { $drv.DriverVersion } else { $null })
                DriverDate = $(if ($drv) { $drv.DriverDate } else { $null })
                DeviceID = $(if ($drv) { $drv.DeviceID } else { $null })
            }
        }
    } catch {}

    if (@($results).Count -eq 0) {
        try {
            $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceClass -eq 'NET' -and $_.DeviceName -match $wifiPattern })
            foreach ($d in $drivers) {
                $results += [pscustomobject]@{
                    Name = $null
                    InterfaceDescription = $d.DeviceName
                    Status = $null
                    LinkSpeed = $null
                    MacAddress = $null
                    InterfaceGuid = $null
                    DriverProviderName = $d.DriverProviderName
                    DriverVersion = $d.DriverVersion
                    DriverDate = $d.DriverDate
                    DeviceID = $d.DeviceID
                }
            }
        } catch {}
    }
    return @($results)
}

function Get-PrimaryWifiDriverText {
    param([object[]]$Drivers)
    $d = @($Drivers | Select-Object -First 1)
    if (@($d).Count -eq 0) { return $null }
    $x = $d[0]
    $parts = @($x.InterfaceDescription, $x.DriverVersion, $x.DriverDate) | Where-Object { $_ }
    return ($parts -join ' | ')
}

function Get-IpInfoForInterface {
    param([string]$InterfaceAlias)
    $ip = $null
    $gateway = $null
    $prefix = $null
    $dns = @()
    try {
        $cfg = $null
        if (-not [string]::IsNullOrWhiteSpace($InterfaceAlias)) {
            $cfg = Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue
        }
        if (-not $cfg) {
            $cfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Address -and $_.IPv4DefaultGateway } | Select-Object -First 1
        }
        if ($cfg) {
            if ($cfg.IPv4Address) {
                $ipObj = $cfg.IPv4Address | Select-Object -First 1
                $ip = $ipObj.IPAddress
                $prefix = $ipObj.PrefixLength
            }
            if ($cfg.IPv4DefaultGateway) { $gateway = ($cfg.IPv4DefaultGateway | Select-Object -First 1).NextHop }
        }

        $dnsCfg = $null
        if (-not [string]::IsNullOrWhiteSpace($InterfaceAlias)) {
            $dnsCfg = Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue
        }
        if (-not $dnsCfg) {
            $dnsCfg = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { @($_.ServerAddresses).Count -gt 0 } | Select-Object -First 1
        }
        if ($dnsCfg -and $dnsCfg.ServerAddresses) { $dns = @($dnsCfg.ServerAddresses) }
    } catch {}
    return [pscustomobject]@{ IPv4 = $ip; PrefixLength = $prefix; Gateway = $gateway; DnsServers = $dns }
}

function Test-PingOnce {
    param(
        [string]$Target,
        [int]$TimeoutMs = 1000
    )
    $ping = $null
    if ([string]::IsNullOrWhiteSpace($Target)) {
        return [pscustomobject]@{ Target = $Target; Ok = $false; Ms = $null; Error = 'empty target' }
    }
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($Target, $TimeoutMs)
        if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            return [pscustomobject]@{ Target = $Target; Ok = $true; Ms = [int]$reply.RoundtripTime; Error = $null }
        }
        $status = 'NoReply'
        if ($reply) { $status = [string]$reply.Status }
        return [pscustomobject]@{ Target = $Target; Ok = $false; Ms = $null; Error = $status }
    } catch {
        return [pscustomobject]@{ Target = $Target; Ok = $false; Ms = $null; Error = $_.Exception.Message }
    } finally {
        if ($ping) { $ping.Dispose() }
    }
}

function Export-ObjectCsvAppend {
    param([object]$Object, [string]$Path)
    if (-not (Test-Path $Path)) {
        $Object | Export-Csv -Path $Path -NoTypeInformation -Delimiter ';' -Encoding UTF8
    } else {
        $Object | Export-Csv -Path $Path -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Append
    }
}

function Save-CommandOutput {
    param([scriptblock]$Command, [string]$Path)
    try { & $Command 2>&1 | Out-File -FilePath $Path -Encoding UTF8 } catch { "ERROR: $($_.Exception.Message)" | Out-File -FilePath $Path -Encoding UTF8 }
}

function Write-LogLine {
    param([string]$Message)
    if (-not $script:QuietMode) { Write-Host $Message }
    if ($script:runtimeLog) { $Message | Out-File -FilePath $script:runtimeLog -Append -Encoding UTF8 }
}

function HtmlEncode {
    param([object]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-PropertyValueSafe {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-PercentLossText {
    param([object[]]$Rows, [string]$OkColumn)
    $valid = @($Rows | Where-Object { $v = Get-PropertyValueSafe $_ $OkColumn; $null -ne $v -and [string]$v -ne '' })
    $total = @($valid).Count
    if ($total -eq 0) { return 'n/a' }
    $fail = @($valid | Where-Object { [string](Get-PropertyValueSafe $_ $OkColumn) -eq 'False' }).Count
    $loss = [math]::Round(($fail / $total) * 100, 2)
    return "$loss% ($fail/$total failed)"
}

function Get-AvgText {
    param([object[]]$Rows, [string]$Column)
    $values = @($Rows | ForEach-Object { Convert-ToNumberSafe (Get-PropertyValueSafe $_ $Column) } | Where-Object { $null -ne $_ })
    if (@($values).Count -eq 0) { return 'n/a' }
    return [math]::Round(($values | Measure-Object -Average).Average, 2)
}

function Get-MinAvgMaxText {
    param([object[]]$Rows, [string]$Column)
    $values = @($Rows | ForEach-Object { Convert-ToNumberSafe (Get-PropertyValueSafe $_ $Column) } | Where-Object { $null -ne $_ })
    if (@($values).Count -eq 0) { return 'n/a / n/a / n/a' }
    $min = [math]::Round(($values | Measure-Object -Minimum).Minimum, 2)
    $avg = [math]::Round(($values | Measure-Object -Average).Average, 2)
    $max = [math]::Round(($values | Measure-Object -Maximum).Maximum, 2)
    return "$min / $avg / $max"
}

function New-SvgLineChart {
    param(
        [object[]]$Rows,
        [string]$Column,
        [string]$Title,
        [string]$YLabel,
        [string]$ValueSuffix = '',
        [object]$FixedMin = $null,
        [object]$FixedMax = $null,
        [int]$Width = 980,
        [int]$Height = 280
    )
    $rowsArr = @($Rows)
    if ($rowsArr.Count -eq 0) { return "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><p>No samples available.</p></div>" }

    $pointsData = @()
    for ($i = 0; $i -lt $rowsArr.Count; $i++) {
        $v = Convert-ToNumberSafe (Get-PropertyValueSafe $rowsArr[$i] $Column)
        if ($null -ne $v) { $pointsData += [pscustomobject]@{ Index = $i; Value = [double]$v; Time = $rowsArr[$i].Time } }
    }
    if (@($pointsData).Count -eq 0) { return "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><p>No numeric values available for $(HtmlEncode $Column).</p></div>" }

    if ($null -ne $FixedMin) { $minVal = [double]$FixedMin } else { $minVal = [double](($pointsData.Value | Measure-Object -Minimum).Minimum) }
    if ($null -ne $FixedMax) { $maxVal = [double]$FixedMax } else { $maxVal = [double](($pointsData.Value | Measure-Object -Maximum).Maximum) }
    if ($minVal -eq $maxVal) { $minVal = $minVal - 1; $maxVal = $maxVal + 1 }
    if ($null -eq $FixedMin -or $null -eq $FixedMax) {
        $pad = [math]::Max(1, ($maxVal - $minVal) * 0.10)
        if ($null -eq $FixedMin) { $minVal = $minVal - $pad }
        if ($null -eq $FixedMax) { $maxVal = $maxVal + $pad }
    }

    $left = 64; $right = 22; $top = 28; $bottom = 48
    $plotW = $Width - $left - $right
    $plotH = $Height - $top - $bottom
    $total = [math]::Max(1, $rowsArr.Count - 1)
    $range = $maxVal - $minVal
    $rightX = $Width - $right
    $bottomY = $top + $plotH
    $axisMidY = [math]::Round($top + ($plotH / 2), 2)

    $polyPoints = @()
    foreach ($p in $pointsData) {
        $x = $left + (($p.Index / $total) * $plotW)
        $y = $top + (($maxVal - $p.Value) / $range) * $plotH
        $polyPoints += ("{0},{1}" -f [math]::Round($x, 2), [math]::Round($y, 2))
    }
    $pointsText = [string]::Join(' ', [string[]]$polyPoints)

    $svg = @()
    $svg += "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><svg class='chart' viewBox='0 0 $Width $Height' role='img' aria-label='$(HtmlEncode $Title)'>"
    $svg += "<rect x='0' y='0' width='$Width' height='$Height' fill='#ffffff'/>"
    for ($g = 0; $g -le 4; $g++) {
        $y = $top + ($g / 4.0) * $plotH
        $val = $maxVal - ($g / 4.0) * $range
        $yr = [math]::Round($y, 2)
        $labelValue = [math]::Round($val, 1)
        $svg += "<line x1='$left' y1='$yr' x2='$rightX' y2='$yr' stroke='#e6e8eb' stroke-width='1'/>"
        $svg += "<text x='$($left-10)' y='$([math]::Round($y+4,2))' text-anchor='end' font-size='11' fill='#4b5563'>$labelValue$ValueSuffix</text>"
    }
    $svg += "<line x1='$left' y1='$top' x2='$left' y2='$bottomY' stroke='#9ca3af' stroke-width='1'/>"
    $svg += "<line x1='$left' y1='$bottomY' x2='$rightX' y2='$bottomY' stroke='#9ca3af' stroke-width='1'/>"
    $svg += "<polyline points='$pointsText' fill='none' stroke='#2563eb' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/>"
    $firstTime = HtmlEncode $rowsArr[0].Time
    $lastTime = HtmlEncode $rowsArr[$rowsArr.Count - 1].Time
    $svg += "<text x='$left' y='$($Height-16)' text-anchor='start' font-size='11' fill='#4b5563'>$firstTime</text>"
    $svg += "<text x='$rightX' y='$($Height-16)' text-anchor='end' font-size='11' fill='#4b5563'>$lastTime</text>"
    $svg += "<text x='16' y='$axisMidY' transform='rotate(-90 16 $axisMidY)' text-anchor='middle' font-size='11' fill='#4b5563'>$(HtmlEncode $YLabel)</text>"
    $svg += '</svg></div>'
    return ($svg -join "`n")
}

function New-SvgStatusTimeline {
    param([object[]]$Rows, [string]$Title, [int]$Width = 980, [int]$Height = 140)
    $rowsArr = @($Rows)
    if ($rowsArr.Count -eq 0) { return "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><p>No samples available.</p></div>" }

    $left = 64; $right = 22; $top = 28; $bottom = 40
    $plotW = $Width - $left - $right
    $plotH = $Height - $top - $bottom
    $step = $plotW / [math]::Max(1, $rowsArr.Count)
    $rightX = $Width - $right
    $axisY = $top + $plotH
    $svg = @()
    $svg += "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><svg class='chart' viewBox='0 0 $Width $Height' role='img' aria-label='$(HtmlEncode $Title)'>"
    $svg += "<rect x='0' y='0' width='$Width' height='$Height' fill='#ffffff'/>"
    $svg += "<text x='$($left-10)' y='$($top+22)' text-anchor='end' font-size='11' fill='#4b5563'>Connected</text>"
    $svg += "<text x='$($left-10)' y='$($top+54)' text-anchor='end' font-size='11' fill='#4b5563'>Disconnected</text>"
    for ($i = 0; $i -lt $rowsArr.Count; $i++) {
        $ok = ([string]$rowsArr[$i].WiFiConnected -eq 'True')
        $x = $left + ($i * $step)
        if ($ok) { $y = $top + 8; $fill = '#16a34a' } else { $y = $top + 40; $fill = '#dc2626' }
        $w = [math]::Max(1, [math]::Ceiling($step))
        $svg += "<rect x='$([math]::Round($x,2))' y='$y' width='$w' height='22' fill='$fill' opacity='0.9'/>"
    }
    $firstTime = HtmlEncode $rowsArr[0].Time
    $lastTime = HtmlEncode $rowsArr[$rowsArr.Count - 1].Time
    $svg += "<line x1='$left' y1='$axisY' x2='$rightX' y2='$axisY' stroke='#9ca3af' stroke-width='1'/>"
    $svg += "<text x='$left' y='$($Height-14)' text-anchor='start' font-size='11' fill='#4b5563'>$firstTime</text>"
    $svg += "<text x='$rightX' y='$($Height-14)' text-anchor='end' font-size='11' fill='#4b5563'>$lastTime</text>"
    $svg += '</svg><div class="legend"><span class="dot ok"></span>Connected <span class="dot bad"></span>Disconnected</div></div>'
    return ($svg -join "`n")
}

function New-SvgBarChartFromGroups {
    param([object[]]$Groups, [string]$Title, [string]$LabelName = 'Item', [int]$Top = 15, [int]$Width = 980)
    $groupsArr = @($Groups | Select-Object -First $Top)
    if ($groupsArr.Count -eq 0) { return "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><p>No data available.</p></div>" }
    $rowH = 28; $topPad = 32; $bottomPad = 20; $left = 220; $right = 30
    $height = $topPad + $bottomPad + ($groupsArr.Count * $rowH)
    $plotW = $Width - $left - $right
    $maxCount = [math]::Max(1, (($groupsArr | Measure-Object -Property Count -Maximum).Maximum))
    $svg = @()
    $svg += "<div class='chart-card'><h3>$(HtmlEncode $Title)</h3><svg class='chart' viewBox='0 0 $Width $height' role='img' aria-label='$(HtmlEncode $Title)'>"
    $svg += "<rect x='0' y='0' width='$Width' height='$height' fill='#ffffff'/>"
    for ($i = 0; $i -lt $groupsArr.Count; $i++) {
        $g = $groupsArr[$i]
        $label = HtmlEncode $g.Name
        if ([string]::IsNullOrWhiteSpace($label)) { $label = '(empty)' }
        $y = $topPad + ($i * $rowH)
        $barW = [math]::Round(($g.Count / $maxCount) * $plotW, 2)
        $textX = [math]::Min($Width - $right, $left + $barW + 8)
        $svg += "<text x='$($left-10)' y='$($y+17)' text-anchor='end' font-size='11' fill='#374151'>$label</text>"
        $svg += "<rect x='$left' y='$($y+5)' width='$barW' height='16' rx='3' fill='#2563eb' opacity='0.88'/>"
        $svg += "<text x='$textX' y='$($y+17)' font-size='11' fill='#374151'>$($g.Count)</text>"
    }
    $svg += "<text x='$left' y='18' font-size='11' fill='#4b5563'>$LabelName / samples</text>"
    $svg += '</svg></div>'
    return ($svg -join "`n")
}

function New-SummaryReport {
    param([string]$SamplesCsv, [string]$SummaryTxt, [string]$SummaryHtml, [datetime]$StartTime, [datetime]$EndTime, [string]$RunFolder)
    $rows = @()
    if (Test-Path $SamplesCsv) { $rows = @(Import-Csv -Path $SamplesCsv -Delimiter ';') }
    $total = @($rows).Count
    $connected = @($rows | Where-Object { [string]$_.WiFiConnected -eq 'True' })
    $disconnected = $total - @($connected).Count
    $roams = @($rows | Where-Object { $_.RoamingEvent -eq 'BSSID_CHANGE' })
    $ssidGroups = @($rows | Where-Object { $_.SSID } | Group-Object SSID | Sort-Object Count -Descending)
    $bssidGroups = @($rows | Where-Object { $_.BSSID } | Group-Object BSSID | Sort-Object Count -Descending)
    $bandGroups = @($rows | Where-Object { $_.Band } | Group-Object Band | Sort-Object Count -Descending)
    $channelGroups = @($rows | Where-Object { $_.Channel } | Group-Object Channel | Sort-Object Count -Descending)
    $dataSourceGroups = @($rows | Where-Object { $_.WiFiDataSource } | Group-Object WiFiDataSource | Sort-Object Count -Descending)
    $detectionStatusGroups = @($rows | Where-Object { $_.WiFiDetectionStatus } | Group-Object WiFiDetectionStatus | Sort-Object Count -Descending)

    $signalStats = Get-MinAvgMaxText -Rows $rows -Column 'SignalPercent'
    $rssiStats = Get-MinAvgMaxText -Rows $rows -Column 'EstimatedRSSI_dBm'
    $gatewayLoss = Get-PercentLossText -Rows $rows -OkColumn 'GatewayPingOk'
    $dnsLoss = Get-PercentLossText -Rows $rows -OkColumn 'DnsPingOk'
    $internet1Loss = Get-PercentLossText -Rows $rows -OkColumn 'Internet1PingOk'
    $internet2Loss = Get-PercentLossText -Rows $rows -OkColumn 'Internet2PingOk'
    $gatewayAvgMs = Get-AvgText -Rows $rows -Column 'GatewayPingMs'
    $dnsAvgMs = Get-AvgText -Rows $rows -Column 'DnsPingMs'
    $internet1AvgMs = Get-AvgText -Rows $rows -Column 'Internet1PingMs'
    $internet2AvgMs = Get-AvgText -Rows $rows -Column 'Internet2PingMs'

    $lines = @()
    $lines += 'Wi-Fi diagnostics summary'
    $lines += '==========================='
    $lines += 'Version: v1.5.6-netsh-regex-fallback'
    $lines += "Computer: $env:COMPUTERNAME"
    $lines += "User: $env:USERNAME"
    $lines += "Started: $StartTime"
    $lines += "Finished: $EndTime"
    $lines += "Run folder: $RunFolder"
    $lines += ''
    $lines += "Samples: $total"
    $lines += "Connected samples: $(@($connected).Count)"
    $lines += "Disconnected samples: $disconnected"
    $lines += "BSSID changes / roaming events detected: $(@($roams).Count)"
    $lines += "Signal percent min/avg/max: $signalStats"
    $lines += "Estimated RSSI dBm min/avg/max: $rssiStats"
    $lines += ''
    $lines += 'Packet loss:'
    $lines += "- Gateway: $gatewayLoss"
    $lines += "- DNS: $dnsLoss"
    $lines += "- Internet target 1: $internet1Loss"
    $lines += "- Internet target 2: $internet2Loss"
    $lines += ''
    $lines += 'Average latency:'
    $lines += "- Gateway avg ms: $gatewayAvgMs"
    $lines += "- DNS avg ms: $dnsAvgMs"
    $lines += "- Internet target 1 avg ms: $internet1AvgMs"
    $lines += "- Internet target 2 avg ms: $internet2AvgMs"
    $lines += ''
    $lines += 'BSSID/AP distribution:'
    foreach ($g in $bssidGroups) { $lines += "- $($g.Name): $($g.Count) samples" }
    $lines += ''
    $lines += 'Band distribution:'
    foreach ($g in $bandGroups) { $lines += "- $($g.Name): $($g.Count) samples" }
    $lines += ''
    $lines += 'Channel distribution:'
    foreach ($g in $channelGroups) { $lines += "- Channel $($g.Name): $($g.Count) samples" }
    $lines += ''
    $lines += 'Wi-Fi data source distribution:'
    foreach ($g in $dataSourceGroups) { $lines += "- $($g.Name): $($g.Count) samples" }
    $lines += ''
    $lines += 'Interpretation hints:'
    $lines += '- Packet loss to gateway usually points to Wi-Fi/AP/local LAN problem.'
    $lines += '- Gateway OK but internet target loss points to WAN/routing/provider/firewall path.'
    $lines += '- Frequent BSSID changes can indicate roaming, weak signal, band steering, mesh changes, or unstable AP coverage.'
    $lines += '- NativeWlanApi is preferred because it is independent of Windows display language.'
    $lines += '- NetworkOnly means Wi-Fi details were unavailable, but IP/gateway/DNS/internet diagnostics continued.'
    $lines += '- EstimatedRSSI_dBm is derived from Windows signal percentage; it is not a direct AP/controller RSSI reading.'
    $lines | Out-File -FilePath $SummaryTxt -Encoding UTF8

    $htmlRows = @()
    $htmlRows += [pscustomobject]@{ Metric = 'Version'; Value = 'v1.5.6-netsh-regex-fallback' }
    $htmlRows += [pscustomobject]@{ Metric = 'Computer'; Value = $env:COMPUTERNAME }
    $htmlRows += [pscustomobject]@{ Metric = 'Started'; Value = $StartTime }
    $htmlRows += [pscustomobject]@{ Metric = 'Finished'; Value = $EndTime }
    $htmlRows += [pscustomobject]@{ Metric = 'Samples'; Value = $total }
    $htmlRows += [pscustomobject]@{ Metric = 'Connected samples'; Value = @($connected).Count }
    $htmlRows += [pscustomobject]@{ Metric = 'Disconnected samples'; Value = $disconnected }
    $htmlRows += [pscustomobject]@{ Metric = 'BSSID changes / roaming'; Value = @($roams).Count }
    $htmlRows += [pscustomobject]@{ Metric = 'Signal min/avg/max percent'; Value = $signalStats }
    $htmlRows += [pscustomobject]@{ Metric = 'Estimated RSSI min/avg/max dBm'; Value = $rssiStats }
    $htmlRows += [pscustomobject]@{ Metric = 'Gateway packet loss'; Value = $gatewayLoss }
    $htmlRows += [pscustomobject]@{ Metric = 'DNS packet loss'; Value = $dnsLoss }
    $htmlRows += [pscustomobject]@{ Metric = 'Internet target 1 packet loss'; Value = $internet1Loss }
    $htmlRows += [pscustomobject]@{ Metric = 'Internet target 2 packet loss'; Value = $internet2Loss }
    $htmlRows += [pscustomobject]@{ Metric = 'Gateway avg latency ms'; Value = $gatewayAvgMs }
    $htmlRows += [pscustomobject]@{ Metric = 'DNS avg latency ms'; Value = $dnsAvgMs }
    $htmlRows += [pscustomobject]@{ Metric = 'Internet target 1 avg latency ms'; Value = $internet1AvgMs }
    $htmlRows += [pscustomobject]@{ Metric = 'Internet target 2 avg latency ms'; Value = $internet2AvgMs }
    $primarySource = ''
    $primarySourceGroup = @($dataSourceGroups | Select-Object -First 1)
    if (@($primarySourceGroup).Count -gt 0) { $primarySource = $primarySourceGroup[0].Name }
    $htmlRows += [pscustomobject]@{ Metric = 'Primary Wi-Fi data source'; Value = $primarySource }

    $style = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #111827; background: #f8fafc; }
h1 { margin-bottom: 4px; }
h2 { margin-top: 30px; border-bottom: 1px solid #d1d5db; padding-bottom: 6px; }
h3 { margin: 0 0 10px 0; font-size: 16px; }
p, li { line-height: 1.45; }
table { border-collapse: collapse; margin-bottom: 24px; background: #fff; width: auto; max-width: 100%; }
th, td { border: 1px solid #d1d5db; padding: 6px 10px; text-align: left; vertical-align: top; }
th { background: #eef2f7; }
code { background: #f3f4f6; padding: 2px 4px; border-radius: 3px; }
.small { color: #4b5563; font-size: 12px; }
.chart-grid { display: block; max-width: 1040px; }
.chart-card { background: #fff; border: 1px solid #d1d5db; border-radius: 8px; padding: 14px; margin: 14px 0 20px 0; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.chart { width: 100%; height: auto; display: block; }
.legend { font-size: 12px; color: #374151; margin-top: 6px; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 999px; margin: 0 5px 0 12px; vertical-align: middle; }
.dot.ok { background: #16a34a; }
.dot.bad { background: #dc2626; }
</style>
"@

    $body = "<h1>Wi-Fi diagnostics summary</h1><p class='small'>Offline HTML charts are embedded as SVG. No Internet, CDN, JavaScript, Excel, or external PowerShell modules are required.</p>"
    $body += ($htmlRows | ConvertTo-Html -Fragment)
    $body += '<h2>Offline charts</h2><div class="chart-grid">'
    $body += (New-SvgStatusTimeline -Rows $rows -Title 'Wi-Fi connection timeline')
    $body += (New-SvgLineChart -Rows $rows -Column 'SignalPercent' -Title 'Signal percentage over time' -YLabel 'Signal' -ValueSuffix '%' -FixedMin 0 -FixedMax 100)
    $body += (New-SvgLineChart -Rows $rows -Column 'EstimatedRSSI_dBm' -Title 'Estimated RSSI over time' -YLabel 'Estimated RSSI dBm' -ValueSuffix ' dBm' -FixedMin -100 -FixedMax -40)
    $body += (New-SvgLineChart -Rows $rows -Column 'GatewayPingMs' -Title 'Gateway latency over time' -YLabel 'Latency ms' -ValueSuffix ' ms')
    $body += (New-SvgLineChart -Rows $rows -Column 'Internet1PingMs' -Title 'Internet target 1 latency over time' -YLabel 'Latency ms' -ValueSuffix ' ms')
    $body += (New-SvgBarChartFromGroups -Groups $bssidGroups -Title 'Top BSSID / AP distribution' -LabelName 'BSSID')
    $body += (New-SvgBarChartFromGroups -Groups $bandGroups -Title 'Band distribution' -LabelName 'Band')
    $body += (New-SvgBarChartFromGroups -Groups $channelGroups -Title 'Channel distribution' -LabelName 'Channel')
    $body += (New-SvgBarChartFromGroups -Groups $dataSourceGroups -Title 'Wi-Fi data source distribution' -LabelName 'Data source')
    $body += '</div>'
    $body += '<h2>Wi-Fi detection status distribution</h2>'
    $body += (($detectionStatusGroups | Select-Object @{Name='WiFiDetectionStatus';Expression={$_.Name}}, Count) | ConvertTo-Html -Fragment)
    $body += '<h2>Interpretation hints</h2><ul>'
    $body += '<li>Packet loss to gateway usually points to Wi-Fi/AP/local LAN problem.</li>'
    $body += '<li>Gateway OK but internet target loss points to WAN/routing/provider/firewall path.</li>'
    $body += '<li>Frequent BSSID changes can indicate roaming, weak signal, band steering, mesh changes, or unstable AP coverage.</li>'
    $body += '<li><code>NativeWlanApi</code> is preferred because it is independent of Windows display language.</li>'
    $body += '<li><code>NetworkOnly</code> means Wi-Fi details were unavailable, but IP/gateway/DNS/internet diagnostics continued.</li>'
    $body += '<li><code>EstimatedRSSI_dBm</code> is derived from Windows signal percentage. It is not a direct AP/controller RSSI reading.</li>'
    $body += '</ul>'

    ConvertTo-Html -Head $style -Body $body -Title 'Wi-Fi diagnostics summary' | Out-File -FilePath $SummaryHtml -Encoding UTF8
}

# ------------------------- main -------------------------

if ($DurationMinutes -lt 1) { $DurationMinutes = 1 }
if ($IntervalSeconds -lt 1) { $IntervalSeconds = 1 }
if ($PingTimeoutMs -lt 100) { $PingTimeoutMs = 100 }
if ($NearbyScanIntervalSeconds -lt 10) { $NearbyScanIntervalSeconds = 10 }

$scriptRoot = Get-ScriptRootSafe
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runFolder = Join-Path $scriptRoot ("WiFiDiag_{0}_{1}" -f $env:COMPUTERNAME, $timestamp)
$rawFolder = Join-Path $runFolder 'Raw'
$nearbyFolder = Join-Path $runFolder 'NearbyNetworks'
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null
New-Item -ItemType Directory -Path $rawFolder -Force | Out-Null
New-Item -ItemType Directory -Path $nearbyFolder -Force | Out-Null

$samplesCsv = Join-Path $runFolder 'wifi_samples.csv'
$roamingCsv = Join-Path $runFolder 'wifi_roaming_events.csv'
$eventsCsv = Join-Path $runFolder 'wlan_autoconfig_events.csv'
$systemEventsCsv = Join-Path $runFolder 'network_system_events.csv'
$summaryTxt = Join-Path $runFolder 'summary.txt'
$summaryHtml = Join-Path $runFolder 'summary.html'
$inventoryCsv = Join-Path $runFolder 'endpoint_inventory.csv'
$wifiDriversCsv = Join-Path $runFolder 'wifi_adapter_drivers.csv'
$script:runtimeLog = Join-Path $runFolder 'runtime.log'

$startTime = Get-Date
$endTime = $startTime.AddMinutes($DurationMinutes)
$isAdmin = Test-IsAdmin
$endpointInventory = Get-EndpointInventorySummary
$wifiDriverInventory = @(Get-WifiAdapterDriverInventory)
$primaryWifiDriver = Get-PrimaryWifiDriverText -Drivers $wifiDriverInventory

try { $endpointInventory | Export-Csv -Path $inventoryCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8 } catch {}
try { $wifiDriverInventory | Export-Csv -Path $wifiDriversCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8 } catch {}
try { $endpointInventory | Format-List * | Out-File -FilePath (Join-Path $rawFolder 'endpoint_inventory.txt') -Encoding UTF8 } catch {}
try { $wifiDriverInventory | Format-List * | Out-File -FilePath (Join-Path $rawFolder 'wifi_adapter_drivers.txt') -Encoding UTF8 } catch {}

Write-LogLine "Wi-Fi diagnostics v1.5.6-netsh-regex-fallback started: $startTime"
Write-LogLine "Run folder: $runFolder"
Write-LogLine "Admin: $isAdmin"
Write-LogLine "OS: $($endpointInventory.OSCaption) $($endpointInventory.OSVersion) build $($endpointInventory.OSBuildNumber)"
Write-LogLine "Locale/UI: $($endpointInventory.SystemLocale) / $($endpointInventory.UILanguage)"
Write-LogLine "Computer model: $($endpointInventory.ComputerManufacturer) $($endpointInventory.ComputerModel)"
Write-LogLine "Primary Wi-Fi driver: $primaryWifiDriver"

Save-CommandOutput -Command { ipconfig /all } -Path (Join-Path $rawFolder 'ipconfig_all_start.txt')
Save-CommandOutput -Command { route print } -Path (Join-Path $rawFolder 'route_print_start.txt')
Save-CommandOutput -Command { netsh wlan show interfaces } -Path (Join-Path $rawFolder 'netsh_wlan_interfaces_start.txt')
Save-CommandOutput -Command { netsh wlan show drivers } -Path (Join-Path $rawFolder 'netsh_wlan_drivers_start.txt')
try { Get-NetAdapter | Format-Table -AutoSize | Out-File -FilePath (Join-Path $rawFolder 'get_netadapter_start.txt') -Encoding UTF8 } catch {}

$sampleIndex = 0
$previousBssid = $null
$previousSsid = $null
$nextNearbyScan = $startTime

while ((Get-Date) -lt $endTime) {
    $cycleStart = Get-Date
    $sampleIndex++
    $now = Get-Date
    $progressPercent = [math]::Min(100, [math]::Round((($now - $startTime).TotalSeconds / [math]::Max(1, ($DurationMinutes * 60))) * 100, 0))
    if (-not $Quiet) { Write-Progress -Activity 'Wi-Fi diagnostics running' -Status "Sample $sampleIndex" -PercentComplete $progressPercent }

    $wlan = Get-WlanInterfaceInfo
    $wifiPresent = $false
    $wifiConnected = $false
    $wifiDataSource = 'NetworkOnly'
    $wifiDetectionStatus = 'Wi-Fi details unavailable; network diagnostics continued'

    $interfaceName = $null
    $description = $null
    $ssid = $null
    $bssid = $null
    $state = $null
    $radioType = $null
    $auth = $null
    $cipher = $null
    $wlanProfile = $null
    $connectionMode = $null
    $channel = $null
    $freq = $null
    $band = $null
    $rxMbps = $null
    $txMbps = $null
    $signalPercent = $null
    $estimatedRssi = $null

    if ($null -ne $wlan) {
        $wifiPresent = $true
        $interfaceName = $wlan.Name
        $description = $wlan.Description
        $ssid = $wlan.SSID
        $bssid = $wlan.BSSID
        $state = $wlan.State
        $radioType = $wlan.RadioType
        $auth = $wlan.Authentication
        $cipher = $wlan.Cipher
        $wlanProfile = $wlan.Profile
        $connectionMode = $wlan.ConnectionMode
        $channel = $wlan.Channel
        $freq = $wlan.FrequencyMHz
        $band = $wlan.Band
        $rxMbps = $wlan.RxMbps
        $txMbps = $wlan.TxMbps
        $signalPercent = $wlan.SignalPercent
        $estimatedRssi = $wlan.EstimatedRSSI_dBm
        $wifiDataSource = $wlan.DataSource
        $wifiDetectionStatus = $wlan.DetectionStatus
        if (-not [string]::IsNullOrWhiteSpace($ssid) -and -not [string]::IsNullOrWhiteSpace($bssid)) { $wifiConnected = $true }
        # Match the complete English or Polish state, including when metadata is unavailable.
        elseif ($state -match '^(?:Connected|Po\u0142\u0105czono)$') { $wifiConnected = $true }
    }

    $ipInfo = Get-IpInfoForInterface -InterfaceAlias $interfaceName
    $dnsServer = $null
    if ($ipInfo.DnsServers -and @($ipInfo.DnsServers).Count -gt 0) { $dnsServer = @($ipInfo.DnsServers)[0] }

    $gatewayPing = Test-PingOnce -Target $ipInfo.Gateway -TimeoutMs $PingTimeoutMs
    $dnsPing = Test-PingOnce -Target $dnsServer -TimeoutMs $PingTimeoutMs
    $internet1Target = $null
    $internet2Target = $null
    if (@($InternetTargets).Count -ge 1) { $internet1Target = $InternetTargets[0] }
    if (@($InternetTargets).Count -ge 2) { $internet2Target = $InternetTargets[1] }
    $internet1Ping = Test-PingOnce -Target $internet1Target -TimeoutMs $PingTimeoutMs
    $internet2Ping = Test-PingOnce -Target $internet2Target -TimeoutMs $PingTimeoutMs

    $roamingEvent = $null
    if (-not [string]::IsNullOrWhiteSpace($bssid)) {
        if (-not [string]::IsNullOrWhiteSpace($previousBssid) -and ($previousBssid -ne $bssid)) {
            $roamingEvent = 'BSSID_CHANGE'
            $roamRow = [pscustomobject]@{
                Time = $now.ToString('yyyy-MM-dd HH:mm:ss')
                PreviousSSID = $previousSsid
                CurrentSSID = $ssid
                PreviousBSSID = $previousBssid
                CurrentBSSID = $bssid
                CurrentBand = $band
                CurrentChannel = $channel
                SignalPercent = $signalPercent
                EstimatedRSSI_dBm = $estimatedRssi
                WiFiDataSource = $wifiDataSource
            }
            Export-ObjectCsvAppend -Object $roamRow -Path $roamingCsv
            Write-LogLine "[$($now.ToString('HH:mm:ss'))] BSSID changed: $previousBssid -> $bssid"
        }
        $previousBssid = $bssid
        $previousSsid = $ssid
    }

    $row = [pscustomobject]@{
        Time = $now.ToString('yyyy-MM-dd HH:mm:ss')
        SampleIndex = $sampleIndex
        WiFiPresent = $wifiPresent
        WiFiConnected = $wifiConnected
        WiFiDataSource = $wifiDataSource
        WiFiDetectionStatus = $wifiDetectionStatus
        InterfaceName = $interfaceName
        InterfaceDescription = $description
        State = $state
        SSID = $ssid
        BSSID = $bssid
        RadioType = $radioType
        Authentication = $auth
        Cipher = $cipher
        Profile = $wlanProfile
        ConnectionMode = $connectionMode
        Channel = $channel
        FrequencyMHz = $freq
        Band = $band
        SignalPercent = $signalPercent
        EstimatedRSSI_dBm = $estimatedRssi
        RxMbps = $rxMbps
        TxMbps = $txMbps
        IPv4 = $ipInfo.IPv4
        PrefixLength = $ipInfo.PrefixLength
        Gateway = $ipInfo.Gateway
        DnsServers = ($ipInfo.DnsServers -join ',')
        GatewayPingOk = $gatewayPing.Ok
        GatewayPingMs = $gatewayPing.Ms
        GatewayPingError = $gatewayPing.Error
        DnsTarget = $dnsServer
        DnsPingOk = $dnsPing.Ok
        DnsPingMs = $dnsPing.Ms
        DnsPingError = $dnsPing.Error
        Internet1Target = $internet1Target
        Internet1PingOk = $internet1Ping.Ok
        Internet1PingMs = $internet1Ping.Ms
        Internet1PingError = $internet1Ping.Error
        Internet2Target = $internet2Target
        Internet2PingOk = $internet2Ping.Ok
        Internet2PingMs = $internet2Ping.Ms
        Internet2PingError = $internet2Ping.Error
        RoamingEvent = $roamingEvent
        OSCaption = $endpointInventory.OSCaption
        OSVersion = $endpointInventory.OSVersion
        PowerShellVersion = $endpointInventory.PowerShellVersion
        SystemLocale = $endpointInventory.SystemLocale
        UILanguage = $endpointInventory.UILanguage
        ComputerManufacturer = $endpointInventory.ComputerManufacturer
        ComputerModel = $endpointInventory.ComputerModel
        PrimaryWiFiDriver = $primaryWifiDriver
    }
    Export-ObjectCsvAppend -Object $row -Path $samplesCsv

    if (-not $Quiet) {
        $gwText = "GW=$($gatewayPing.Ok)/$($gatewayPing.Ms)ms"
        $i1Text = "INT1=$($internet1Ping.Ok)/$($internet1Ping.Ms)ms"
        Write-Host ("[{0}] WiFi={1} SSID={2} BSSID={3} Signal={4}% RSSI={5}dBm Ch={6} Band={7} {8} {9} Source={10}" -f $now.ToString('HH:mm:ss'), $wifiConnected, $ssid, $bssid, $signalPercent, $estimatedRssi, $channel, $band, $gwText, $i1Text, $wifiDataSource)
    }

    if (-not $NoNearbyScan -and $now -ge $nextNearbyScan) {
        $scanPath = Join-Path $nearbyFolder ("nearby_networks_{0}.txt" -f $now.ToString('yyyyMMdd_HHmmss'))
        Save-CommandOutput -Command { netsh wlan show networks mode=bssid } -Path $scanPath
        $nextNearbyScan = $now.AddSeconds($NearbyScanIntervalSeconds)
    }

    $elapsed = ((Get-Date) - $cycleStart).TotalSeconds
    $sleepSeconds = [math]::Max(0, $IntervalSeconds - [math]::Floor($elapsed))
    if ($sleepSeconds -gt 0) { Start-Sleep -Seconds $sleepSeconds }
}

if (-not $Quiet) { Write-Progress -Activity 'Wi-Fi diagnostics running' -Completed }
$finishTime = Get-Date
Write-LogLine "Monitoring finished: $finishTime"
Write-LogLine 'Collecting event logs and final raw snapshots...'

Save-CommandOutput -Command { ipconfig /all } -Path (Join-Path $rawFolder 'ipconfig_all_end.txt')
Save-CommandOutput -Command { route print } -Path (Join-Path $rawFolder 'route_print_end.txt')
Save-CommandOutput -Command { netsh wlan show interfaces } -Path (Join-Path $rawFolder 'netsh_wlan_interfaces_end.txt')
Save-CommandOutput -Command { netsh wlan show drivers } -Path (Join-Path $rawFolder 'netsh_wlan_drivers_end.txt')

$eventStart = $startTime.AddHours(-1 * $EventLookbackHours)
try {
    $wlanEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime = $eventStart } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    if (@($wlanEvents).Count -gt 0) { $wlanEvents | Export-Csv -Path $eventsCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
} catch { "ERROR: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $rawFolder 'wlan_events_error.txt') -Encoding UTF8 }

try {
    $systemEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $eventStart } -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'Tcpip|Dhcp|DNS|Netwtw|WLAN|NDIS|e1|rtwlane|NetAdapter' } | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    if (@($systemEvents).Count -gt 0) { $systemEvents | Export-Csv -Path $systemEventsCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
} catch { "ERROR: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $rawFolder 'system_events_error.txt') -Encoding UTF8 }

New-SummaryReport -SamplesCsv $samplesCsv -SummaryTxt $summaryTxt -SummaryHtml $summaryHtml -StartTime $startTime -EndTime $finishTime -RunFolder $runFolder
Write-LogLine "Summary created: $summaryHtml"

Write-Host ""
Write-Host "Done. Report folder: $runFolder" -ForegroundColor Green
if ($OpenReportFolder) { Start-Process explorer.exe $runFolder }
