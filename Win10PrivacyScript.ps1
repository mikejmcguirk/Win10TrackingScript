#Create Functions

Function Write-Log {
    Param ([string]$userInput)

    Write-Host $userInput
}

#Main Script Body

$platformCheck = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
$versionCheck = (Get-ItemProperty -Path `
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber `
     -eq 10
$architectureCheck = (Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit'

if ($platformCheck -and $versionCheck -and $architectureCheck) {
    Write-Log 'Script running on Windows 10 64-bit. Proceeding'
}
else {
    Write-Log 'Script not running on Windows 10 64-bit. Exiting'
}

