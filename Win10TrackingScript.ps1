# Script to Disable Windows Tracking
# WIP
# By Mike J. McGuirk

#Create Functions

$currentDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$logName = '\Win10TrackingLog_'
$scriptStart = Get-Date -Format "yyyy-mm-dd_HHmmss"
$outputFile = ($currentDir + $logName + $scriptStart + ".txt")

Function Write-Log {
    Param ([string]$userInput)

    Write-Host $userInput
    Add-Content -Path $outputFile -Value $userInput
}

Function If-Admin {
    Param(
        [parameter(position=0)]
        $adminStatus, 
        [parameter(position=1)]
        [string]$userInput
    )

    if($adminStatus) {
        Invoke-Expression $userInput
    }
}

Write-Log ''

#Check Windows Version

$expectedPlatform = 'Win32NT'
$expectedArchitecture = '64-bit'
$expectedMajorVersion = 10
$expectedMinorVersion = 0
$expectedBuildNumber = 18363
$expectedRevision = 720

$winVer = New-Object -TypeName PSObject

$winVer | Add-Member -MemberType NoteProperty -Name Platform `
    -Value $([System.Environment]::OSVersion.Platform)
$winVer | Add-Member -MemberType NoteProperty -Name Architecture `
    -Value $(Get-WmiObject Win32_OperatingSystem).OSArchitecture
$winVer | Add-Member -MemberType NoteProperty -Name MajorVersion `
    -Value $(Get-ItemProperty -Path `
   'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber
$winVer | Add-Member -MemberType NoteProperty -Name MinorVersion `
    -Value $(Get-ItemProperty -Path `
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber
$winVer | Add-Member -MemberType NoteProperty -Name Build `
    -Value $(Get-ItemProperty -Path `
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentBuildNumber).CurrentBuildNumber
$winVer | Add-Member -MemberType NoteProperty -Name Revision `
    -Value $(Get-ItemProperty -Path `
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR

if (($expectedPlatform -ne $winVer.Platform) -or `
    ($expectedArchitecture -ne $winVer.Architecture) -or `
    ($expectedMajorVersion) -ne $winVer.MajorVersion) {
    Write-Log 'Script not running on Windows 10 64-bit. Exiting'
    exit
}
elseif ($expectedMinorVersion -gt $winVer.MinorVersion) {
    Write-Log ('Minor version must be at least ' + $expectedMinorVersion + '. Exiting')
    exit
}
elseif ($expectedMinorVersion -eq $winVer.MinorVersion) {
    if ($expectedBuildNumber -gt $winVer.Build) {
        Write-Log ('Current build ' + $winVer.Build + ' is less than minimum build ' + $expectedBuildNumber + '. Exiting')
        exit
    }
    elseif ($expectedBuildNumber -eq $winVer.Build) {
        if ($expectedRevision -gt $winVer.Revision) {
            Write-Log ('Current revision ' + $winVer.Revision + ' is less than expected revision ' + $expectedRevision + '. Exiting')
            exit
        }
    }
}

Write-Log 'Script running on an up-to-date Windows 10 64-bit system. Continuing'
Write-Log ''

$isAdmin = $False

if (([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Running as administrator"
    $isAdmin = $True
} else {
    Write-Log "Not running as administrator. Some fixes will be unable to run"
}

Write-Log ''

#Implement Privacy Fixes

If-Admin $isAdmin 'Write-Log ''Disallowing Cortana'''
If-Admin $isAdmin 'Set-ItemProperty -Path `
    ''Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Search'' -Name ''Allow Cortana'' -Value 0'

Write-Log 'Removing and disabling Recent Items and Frequent Places'
Remove-Item ($env:APPDATA + '\Microsoft\Windows\Recent\*.*') -Force
Remove-Item ($env:APPDATA + '\Microsoft\Windows\Recent\AutomaticDestinations\*.*') -Force
Remove-Item ($env:APPDATA + '\Microsoft\Windows\Recent\CustomDestinations\*.*') -Force
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
	-Name 'Start_TrackDocs' -Value 0

Write-Log 'Disabling Connected Device Platform Service'
$globalSettings = ($env:LOCALAPPDATA + '\ConnectedDevicesPlatform\CDPGlobalSettings_Copy.cdp')

Write-Log 'Disabling Activity Feed/Timeline'
If-Admin $isAdmin 'Set-ItemProperty -Path ''Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'' -Name ''EnableActivityFeed'' -Value 0'
If-Admin $isAdmin 'Set-ItemProperty -Path ''Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'' -Name ''PublishUserActivities'' -Value 0'
If-Admin $isAdmin 'Set-ItemProperty -Path ''Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'' -Name ''UploadUserActivities'' -Value 0'
Write-Log 'Deleting old Activity Feed files. Feature only disabled when running as admin'
Remove-Item ($env:LOCALAPPDATA + '\Microsoft\Windows\History\*.*') -Force -Recurse

Write-Log 'Disabling "Improve Typing" Feature'
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value 0
If-Admin $isAdmin 'Set-ItemProperty -Path ''Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Input\TIPC'' -Name ''Enabled'' -Value 0'

Write-Log 'Disabling Locally Relevant Content'
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Value 1

Write-Log 'Disabling Advertising Info Sends'
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0

If-Admin $isAdmin 'Write-Log ''Disabling Superfetch'''
$superCheck = Get-Service -Name Superfetch -ErrorAction SilentlyContinue
if ($superCheck.Length -gt 0) {
    Stop-Service -Name 'Superfetch'
    Disable-Service -Name 'Superfetch' 
}
If-Admin $isAdmin 'Set-ItemProperty -Path ''Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'' `
    -Name ''EnableSuperfetch'' -Value 0'

If-Admin $isAdmin 'Write-Log ''Stopping and disabling Device Management Wireless Application Protocol (WAP) Push message Routing Service'''
If-Admin $isAdmin 'Stop-Service -Name ''dmwappushservice'''
If-Admin $isAdmin 'Set-Service -Name ''dmwappushservice'' -StartupType Disabled'

If-Admin $isAdmin 'Write-Log ''Stopping and disabling Connected Devices Platform Service'''
If-Admin $isAdmin 'Stop-Service -Name ''CDPSvc'''
If-Admin $isAdmin 'Set-Service -Name ''CDPSvc'' -StartupType Disabled'

If-Admin $isAdmin 'Write-Log ''Stopping and disabling Microsoft Compabitibility Appraiser task'''
If-Admin $isAdmin 'Stop-ScheduledTask -TaskName ''\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'''
If-Admin $isAdmin 'Disable-ScheduledTask -TaskName ''\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'' | Out-Null'

Write-Log ''
Write-Log 'Tracking script complete. Restart recommended for all changes to take effect'