param([string]$ScriptPath = (Join-Path $PSScriptRoot '../WiFi-Diag-Monitor.ps1'))

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $ScriptPath).Path, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -gt 0) { throw ($parseErrors.Message -join "`n") }

# Load function definitions only. Never execute the monitoring loop or native APIs.
$functions = $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
}, $false)
foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

# Exercise the actual main-loop mapping with synthetic WLAN objects.
$sampleMapping = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.WhileStatementAst]
})[0].Body.Statements | Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and
    $_.Extent.Text.StartsWith('if ($null -ne $wlan)')
} | Select-Object -First 1
if ($null -eq $sampleMapping) { throw 'Could not locate WLAN sample mapping.' }
$mapSample = [scriptblock]::Create($sampleMapping.Extent.Text)

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -cne $Expected) {
        throw "$Message -- expected '$Expected', got '$Actual'"
    }
    Write-Host "PASS: $Message"
}

function Test-SampleState {
    param([string]$State, [bool]$Expected, [string]$SSID = '', [string]$BSSID = '')
    $fields = @{}
    foreach ($name in @('Name', 'Description', 'SSID', 'BSSID', 'State', 'RadioType',
        'Authentication', 'Cipher', 'Profile', 'ConnectionMode', 'Channel',
        'FrequencyMHz', 'Band', 'RxMbps', 'TxMbps', 'SignalPercent',
        'EstimatedRSSI_dBm', 'DataSource', 'DetectionStatus')) {
        $fields[$name] = $null
    }
    $fields.State = $State
    $fields.SSID = $SSID
    $fields.BSSID = $BSSID
    $wlan = [pscustomobject]$fields
    $wifiConnected = $false
    . $mapSample
    Assert-Equal $wifiConnected $Expected "Connection state: $State (SSID='$SSID')"
}

Test-SampleState 'Disconnected' $false
Test-SampleState 'Connected' $true
Test-SampleState 'Disconnecting' $false
Test-SampleState 'NotReady' $false
Test-SampleState 'Authenticating' $false
Test-SampleState '' $false
Test-SampleState 'unknown' $true 'Test WLAN' 'aa:bb:cc:dd:ee:ff'
# Keep this test file ASCII-safe for Windows PowerShell 5.1.
$polishConnected = 'po' + [char]0x0142 + [char]0x0105 + 'czono'
$polishDisconnected = 'roz' + [char]0x0142 + [char]0x0105 + 'czono'
Test-SampleState $polishConnected $true
Test-SampleState $polishDisconnected $false

foreach ($newline in @("`n", "`r`n")) {
    $text = '    SSID : ' + $newline + '    BSSID : aa:bb:cc:dd:ee:ff'
    Assert-Equal (Get-NetshValueRegex $text @('SSID')) '' 'Empty SSID stays empty'
    Assert-Equal (Get-NetshValueRegex $text @('BSSID')) 'aa:bb:cc:dd:ee:ff' 'BSSID remains separate'
    $text = '    SSID : ' + $newline + $newline + '    BSSID : aa:bb:cc:dd:ee:ff'
    Assert-Equal (Get-NetshValueRegex $text @('SSID')) '' 'Empty SSID does not cross a blank line'
    $text = '    SSID : Cafe: guest network  ' + $newline + '    BSSID : aa:bb:cc:dd:ee:ff'
    Assert-Equal (Get-NetshValueRegex $text @('SSID')) 'Cafe: guest network' 'SSID preserves spaces and colons'
    Assert-Equal (Get-NetshValueRegex $text @('Channel')) $null 'Missing label stays null'
}

# Mock netsh; this also checks interface selection and numeric conversion.
function netsh {
    @'
    Name : Wi-Fi disconnected
    State : disconnected

    Name : Wi-Fi connected
    State : connected
    SSID : Guest network
    BSSID : aa:bb:cc:dd:ee:ff
    Channel : 36
    Band : 5 GHz
    Signal : 80%
    Receive rate (Mbps) : 120,5
    Transmit rate (Mbps) : 100.5
'@
}
$info = Get-WlanInterfaceInfoNetsh
Assert-Equal $info.Name 'Wi-Fi connected' 'Select connected interface after disconnected one'
Assert-Equal $info.SSID 'Guest network' 'Parse selected SSID'
Assert-Equal $info.SignalPercent 80 'Parse signal percentage'
Assert-Equal $info.RxMbps 120.5 'Parse decimal-comma receive rate'
Assert-Equal $info.TxMbps 100.5 'Parse decimal-point transmit rate'
Assert-Equal $info.DataSource 'NetshRegexFallback' 'Preserve fallback data source'
Write-Host 'All offline regression tests passed.'
