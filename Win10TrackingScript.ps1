#Create Functions

Function Write-Log {
    Param ([string]$userInput)

    Write-Host $userInput
}

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

Write-Log "Script running on an up-to-date Windows 10 64-bit system. Continuing"

#Implement Privacy Fixes

Write-Log 'Disabling "Improve Typing" feature'
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value 0

Write-Log 'Disabling Locally Relevant Content'
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Value 1

Write-Log 'Disabling Advertising Info Sends'
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0