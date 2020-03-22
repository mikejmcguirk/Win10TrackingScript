#Create Functions

Function Write-Log
{
    Param ([string]$userInput)

    Write-Host $userInput
}

#Main Script Body

if 
(
    ([System.Environment]::OSVersion.Platform -eq 'Win32NT') `
        -and 
        (
            (Get-ItemProperty `
            -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber `
            -eq 10 `
        ) `
        -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit')
)
{
    Write-Log 'Script running on Windows 10 64-bit. Proceeding'
}
else
{
    Write-Log 'Script not running on Windows 10 64-bit. Exiting'
}

