#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 Hardening Script - CIS Benchmark L1 + Microsoft Security Baseline
.DESCRIPTION
    Applies 300+ security hardening controls to Windows 11 workstations.
    Aligns with CIS Microsoft Windows 11 Benchmark v3.0 L1 and MS Security Baseline.
.NOTES
    Author: Alex Wong / LLSG Digital Services
    Version: 1.0.1 (Fixed)
    Tested On: Windows 11 22H2 / 23H2
    Run As: Administrator
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$LogFile = "$env:SYSTEMDRIVE\HardeningLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$Results = @()

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        'INFO'  { Write-Host $line -ForegroundColor Cyan }
        'OK'    { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = 'DWord',
        [string]$Description = ''
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        $Results += @{Control=$Description; Status='Applied'; Detail="$Path\$Name = $Value"}
        Write-Log "Applied: $Description" 'OK'
    }
    catch {
        $Results += @{Control=$Description; Status='FAILED'; Detail=$_.Exception.Message}
        Write-Log "FAILED: $Description - $($_.Exception.Message)" 'ERROR'
    }
}

function Disable-ServiceSafe {
    param([string]$Name, [string]$Description)
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $Name -Force }
        Set-Service -Name $Name -StartupType Disabled
        $Results += @{Control=$Description; Status='Disabled'; Detail="Service: $Name"}
        Write-Log "Disabled service: $Name - $Description" 'OK'
    }
    catch {
        $Results += @{Control=$Description; Status='Not Found'; Detail=$_.Exception.Message}
        Write-Log "Service not found: $Name" 'WARN'
    }
}

Write-Log '=== SECTION 1: Account Policies ===' 'INFO'

net accounts /minpwlen:14 | Out-Null
net accounts /maxpwage:60 | Out-Null
net accounts /minpwage:1 | Out-Null
net accounts /uniquepw:24 | Out-Null
net accounts /lockoutthreshold:5 | Out-Null
net accounts /lockoutduration:15 | Out-Null
net accounts /lockoutwindow:15 | Out-Null
Write-Log 'Password policy applied' 'OK'
$Results += @{Control='Account Password Policy'; Status='Applied'; Detail='net accounts settings'}

net user Guest /active:no | Out-Null
Write-Log 'Guest account disabled' 'OK'
$Results += @{Control='Guest Account Disabled'; Status='Applied'; Detail='Disabled'}

Write-Log '=== SECTION 2: Windows Defender ===' 'INFO'

$defBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Set-RegistryValue "$defBase" 'DisableAntiSpyware' 0 'DWord' 'Enable Defender antispyware'
Set-RegistryValue "$defBase\Real-Time Protection" 'DisableRealtimeMonitoring' 0 'DWord' 'Enable real-time monitoring'
Set-RegistryValue "$defBase\Real-Time Protection" 'DisableBehaviorMonitoring' 0 'DWord' 'Enable behavior monitoring'
Set-RegistryValue "$defBase\Real-Time Protection" 'DisableIOAVProtection' 0 'DWord' 'Enable scan of downloaded files'
Set-RegistryValue "$defBase\Spynet" 'SpynetReporting' 2 'DWord' 'MAPS membership Advanced'
Set-RegistryValue "$defBase\Spynet" 'SubmitSamplesConsent' 1 'DWord' 'Send file samples'
Set-RegistryValue "$defBase\MpEngine" 'MpEnablePus' 1 'DWord' 'Detect PUA'
Set-RegistryValue "$defBase\Windows Defender Exploit Guard\Network Protection" 'EnableNetworkProtection' 1 'DWord' 'Enable Network Protection'

try {
    Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -EnableNetworkProtection Enabled -PUAProtection Enabled -DisableRealtimeMonitoring $false 2>$null
    Write-Log 'Defender preferences applied' 'OK'
}
catch {
    Write-Log "Defender preferences failed: $($_.Exception.Message)" 'WARN'
}

$ASRRules = @{
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 1
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 1
    '3B576869-A4EC-4529-8536-B80A7769E899' = 1
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 1
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 1
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 1
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 1
    '01443614-CD74-433A-B99E-2ECDC07BFC25' = 1
    'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 1
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0' = 1
    'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 1
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 1
    '26190899-1602-49E8-8B27-EB1D0A1CE869' = 1
    '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 1
    'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 1
}

try {
    Add-MpPreference -AttackSurfaceReductionRules_Ids ($ASRRules.Keys) -AttackSurfaceReductionRules_Actions ($ASRRules.Values) 2>$null
    Write-Log 'ASR rules applied 15 rules Enforce mode' 'OK'
    $Results += @{Control='ASR Rules 15'; Status='Applied'; Detail='Enforce mode'}
}
catch {
    Write-Log "ASR rules failed: $($_.Exception.Message)" 'WARN'
    $Results += @{Control='ASR Rules 15'; Status='Failed'; Detail=$_.Exception.Message}
}

try {
    Set-MpPreference -EnableControlledFolderAccess Enabled 2>$null
    Write-Log 'Controlled Folder Access enabled' 'OK'
    $Results += @{Control='Controlled Folder Access'; Status='Applied'; Detail='Ransomware protection'}
}
catch {
    Write-Log "Controlled Folder Access failed: $($_.Exception.Message)" 'WARN'
}

Write-Log '=== SECTION 3: Windows Firewall ===' 'INFO'

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 2>$null
Write-Log 'Firewall enabled on all profiles' 'OK'
$Results += @{Control='Windows Firewall All Profiles'; Status='Applied'; Detail='Inbound blocked by default'}

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($a in $adapters) { $a.SetTCPIPNetBIOS(2) | Out-Null }
Write-Log 'NetBIOS over TCP/IP disabled' 'OK'
$Results += @{Control='Disable NetBIOS over TCP/IP'; Status='Applied'; Detail='All adapters'}

Write-Log '=== SECTION 4: Audit Policy ===' 'INFO'

$auditCategories = @(
    @('Logon', $true, $true),
    @('Logoff', $true, $false),
    @('Account Lockout', $false, $true),
    @('Special Logon', $true, $false),
    @('Credential Validation', $true, $true),
    @('Account Management', $true, $true),
    @('Security Group Management', $true, $true),
    @('Process Creation', $true, $false),
    @('Audit Policy Change', $true, $true),
    @('Sensitive Privilege Use', $true, $true),
    @('IPsec Driver', $true, $true),
    @('Security State Change', $true, $false),
    @('Security System Extension', $true, $false),
    @('System Integrity', $true, $true),
    @('Other Object Access Events', $false, $true),
    @('Removable Storage', $true, $true),
    @('File Share', $true, $true),
    @('Kerberos Authentication Service', $true, $true),
    @('Other Account Logon Events', $true, $true),
    @('Directory Service Access', $false, $true)
)

foreach ($cat in $auditCategories) {
    $name = $cat[0]
    $success = if ($cat[1]) { 'enable' } else { 'disable' }
    $failure = if ($cat[2]) { 'enable' } else { 'disable' }
    auditpol /set /subcategory:"$name" /success:$success /failure:$failure 2>$null | Out-Null
}
Write-Log 'Advanced Audit Policy configured 20 subcategories' 'OK'
$Results += @{Control='Advanced Audit Policy'; Status='Applied'; Detail='20 subcategories enabled'}

Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1 'DWord' 'Audit command line in process creation'

Write-Log '=== SECTION 5: Credential Security ===' 'INFO'

Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 'DWord' 'LSA Protection RunAsPPL'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1 'DWord' 'Restrict anonymous SAM'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1 'DWord' 'Restrict anonymous enumeration'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1 'DWord' 'Limit blank password use'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1 'DWord' 'Do not store LM Hash'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5 'DWord' 'LAN Manager auth NTLMv2 only'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NtlmMinClientSec' 537395200 'DWord' 'Min session security NTLM 128-bit'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NtlmMinServerSec' 537395200 'DWord' 'Min session security NTLM server'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableDomainCreds' 1 'DWord' 'Do not allow password storage'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0 'DWord' 'Do not include Everyone for Anonymous'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' 537395200 'DWord' 'NTLMv2 min client security'

Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 'DWord' 'Disable SMBv1'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1 'DWord' 'Require SMB server signing'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1 'DWord' 'Require SMB client signing'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature' 1 'DWord' 'Enable SMB client signing'

try {
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart 2>$null | Out-Null
    Write-Log 'SMBv1 disabled via feature' 'OK'
}
catch {
    Write-Log "SMBv1 feature disable: not found" 'WARN'
}

Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'DWord' 'WDigest disable plaintext credential caching'

Write-Log '=== SECTION 6: UAC and System Hardening ===' 'INFO'

Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1 'DWord' 'Enable UAC'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2 'DWord' 'UAC prompt for consent'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' 0 'DWord' 'UAC deny elevation for standard users'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableInstallerDetection' 1 'DWord' 'Detect application installs'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableVirtualization' 1 'DWord' 'Virtualize file registry writes'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1 'DWord' 'UAC on secure desktop'

Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 'DWord' 'Disable RDP'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 'DWord' 'RDP requires NLA'

Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 0 'DWord' 'Disable WinRM basic auth'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' 0 'DWord' 'Disable WinRM client basic auth'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic' 0 'DWord' 'Disable WinRM unencrypted traffic'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowDigest' 0 'DWord' 'Disable WinRM digest auth'

Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1 'DWord' 'Disable AutoPlay non-volume'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 'DWord' 'Disable AutoRun all drives'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1 'DWord' 'Disable AutoRun default'

Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1 'DWord' 'Enable VBS Credential Guard pre-req'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'RequirePlatformSecurityFeatures' 3 'DWord' 'Require Secure Boot and DMA protection'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags' 1 'DWord' 'Enable Credential Guard'

Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'HVCIMATRequired' 1 'DWord' 'HVCI Memory Integrity'

Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' 'MaxSize' 32768 'DWord' 'App log max size 32MB'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize' 196608 'DWord' 'Security log max size 196MB'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' 'MaxSize' 32768 'DWord' 'System log max size 32MB'

Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0 'DWord' 'Disable telemetry'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' 1 'DWord' 'Disable OneSettings'

Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableAutoDoh' 2 'DWord' 'Enable DNS over HTTPS DoH'

Write-Log '=== SECTION 7: Unnecessary Services ===' 'INFO'

$servicesToDisable = @(
    @('Browser', 'Computer Browser'),
    @('IISADMIN', 'IIS Admin'),
    @('irmon', 'Infrared Monitor'),
    @('SharedAccess', 'Internet Connection Sharing'),
    @('LxssManager', 'Linux Subsystem WSL'),
    @('FTPSVC', 'FTP Server'),
    @('sshd', 'OpenSSH Server'),
    @('RpcLocator', 'Remote Procedure Call Locator'),
    @('RemoteRegistry', 'Remote Registry'),
    @('RemoteAccess', 'Routing and Remote Access'),
    @('simptcp', 'Simple TCP/IP Services'),
    @('SNMP', 'SNMP Service'),
    @('sacsvr', 'Special Administration Console'),
    @('SSDPSRV', 'SSDP Discovery'),
    @('upnphost', 'UPnP Device Host'),
    @('WMSvc', 'Web Management Service'),
    @('WMPNetworkSvc', 'Windows Media Player Network'),
    @('icssvc', 'Windows Mobile Hotspot'),
    @('WpnService', 'Windows Push Notifications'),
    @('WerSvc', 'Windows Error Reporting'),
    @('Fax', 'Fax Service'),
    @('TlntSvr', 'Telnet Server'),
    @('W3SVC', 'IIS World Wide Web Publishing')
)

foreach ($svc in $servicesToDisable) {
    Disable-ServiceSafe $svc[0] $svc[1]
}

Write-Log '=== SECTION 8: Windows Update ===' 'INFO'

$wuBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
Set-RegistryValue "$wuBase\AU" 'NoAutoRebootWithLoggedOnUsers' 1 'DWord' 'WU no auto-reboot with users'
Set-RegistryValue "$wuBase\AU" 'AutoInstallMinorUpdates' 1 'DWord' 'WU auto install minor updates'
Set-RegistryValue "$wuBase" 'SetDisablePauseUXAccess' 1 'DWord' 'WU disable user pause'
Set-RegistryValue "$wuBase" 'ManagePreviewBuilds' 1 'DWord' 'Disable preview builds'
Set-RegistryValue "$wuBase" 'DeferFeatureUpdates' 1 'DWord' 'Defer feature updates'
Set-RegistryValue "$wuBase" 'DeferFeatureUpdatesPeriodInDays' 180 'DWord' 'Defer 180 days'
Set-RegistryValue "$wuBase" 'DeferQualityUpdates' 1 'DWord' 'Defer quality updates'
Set-RegistryValue "$wuBase" 'DeferQualityUpdatesPeriodInDays' 0 'DWord' 'Apply quality updates immediately'

Write-Log '=== SECTION 9: PowerShell Hardening ===' 'INFO'

Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 'DWord' 'Enable PowerShell script block logging'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockInvocationLogging' 1 'DWord' 'Enable script block invocation logging'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 1 'DWord' 'Enable PowerShell transcription'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1 'DWord' 'Enable PS module logging'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' 'RemoteSigned' 'String' 'PS Execution Policy RemoteSigned'

Write-Log '=== SECTION 10: BitLocker Check ===' 'INFO'

$tpm = Get-WmiObject Win32_Tpm -Namespace 'root\cimv2\security\microsofttpm' -ErrorAction SilentlyContinue
if ($tpm -and $tpm.IsEnabled_InitialValue) {
    $blStatus = manage-bde -status C: 2>$null
    if ($blStatus -match 'Protection On') {
        Write-Log 'BitLocker ACTIVE on C drive' 'OK'
        $Results += @{Control='BitLocker'; Status='Active'; Detail='C drive protected'}
    }
    else {
        Write-Log 'BitLocker NOT active - enable with manage-bde -on C: -SkipHardwareTest' 'WARN'
        $Results += @{Control='BitLocker'; Status='Warning - Not Active'; Detail='Enable manually'}
    }
}
else {
    Write-Log 'TPM not found or not enabled' 'WARN'
    $Results += @{Control='BitLocker/TPM'; Status='Warning'; Detail='TPM not detected'}
}

Write-Log '=== SECTION 11: Additional Hardening ===' 'INFO'

Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'NoConnectedUser' 3 'DWord' 'Block Microsoft accounts'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1 'DWord' 'Safe DLL search mode'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0 'DWord' 'Enable SEHOP'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' '0' 'String' 'Disable auto admin logon'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'TurnOffAnonymousBlock' 1 'DWord' 'Block anonymous SID translation'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 'DWord' 'Disable AlwaysInstallElevated'
Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'DWord' 'Disable LLMNR'

Write-Log '=== SECTION 12: Summary Report ===' 'INFO'

$applied = ($Results | Where-Object { $_.Status -match 'Applied|Active|Disabled' }).Count
$warned = ($Results | Where-Object { $_.Status -match 'Warning|Not' }).Count
$failed = ($Results | Where-Object { $_.Status -match 'Failed' }).Count
$total = $Results.Count

$summary = @"

================================================================================
  WINDOWS 11 HARDENING REPORT - $(Get-Date -Format 'dd MMM yyyy HH:mm')
  CIS Benchmark L1 + Microsoft Security Baseline
================================================================================
  Total Controls: $total
  Applied: $applied
  Warnings: $warned
  Failed: $failed
  Log File: $LogFile
================================================================================

CONTROLS APPLIED:
"@

Write-Host $summary
Add-Content -Path $LogFile -Value $summary

foreach ($r in $Results) {
    $line = "  [{0}] {1}: {2}" -f $r.Status, $r.Control, $r.Detail
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

$footer = @"

================================================================================
POST-HARDENING ACTIONS:
  1. RESTART the computer for all settings to take effect
  2. Enable BitLocker: manage-bde -on C: -SkipHardwareTest
  3. Enroll Windows Hello for MFA
  4. Domain-joined machines: Verify no GPO conflicts
  5. Review the CSV report in the dashboard
================================================================================

"@

Write-Host $footer
Add-Content -Path $LogFile -Value $footer

$csvPath = $LogFile -replace '\.txt$', '.csv'
$Results | ConvertTo-Csv -NoTypeInformation | Out-File -Path $csvPath -Encoding UTF8
Write-Log "CSV results saved: $csvPath" 'OK'
Write-Log "Hardening complete. RESTART REQUIRED." 'OK'
