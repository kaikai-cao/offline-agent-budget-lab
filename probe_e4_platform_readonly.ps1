# E4 hardware discovery only.
# Read-only: does NOT define/write/delete TPM NV indices, increment counters,
# clear/initialize TPM, or change BIOS/UEFI settings.

$ErrorActionPreference = 'Continue'

function Get-FirstValue {
    param(
        [object]$InputObject,
        [string]$PropertyName
    )
    if ($null -ne $InputObject -and $InputObject.PSObject.Properties.Name -contains $PropertyName) {
        return $InputObject.$PropertyName
    }
    return $null
}

Write-Output '========== E4 READ-ONLY PLATFORM PROBE =========='
Write-Output 'No TPM NV write command or configuration change is performed.'
Write-Output ''

$cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
$system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

[PSCustomObject]@{
    CpuName        = (Get-FirstValue -InputObject $cpu -PropertyName 'Name')
    SystemMaker    = (Get-FirstValue -InputObject $system -PropertyName 'Manufacturer')
    SystemModel    = (Get-FirstValue -InputObject $system -PropertyName 'Model')
    BaseboardMaker = (Get-FirstValue -InputObject $board -PropertyName 'Manufacturer')
    BaseboardModel = (Get-FirstValue -InputObject $board -PropertyName 'Product')
    BaseboardVer   = (Get-FirstValue -InputObject $board -PropertyName 'Version')
    BiosMaker      = (Get-FirstValue -InputObject $bios -PropertyName 'Manufacturer')
    BiosVersion    = (Get-FirstValue -InputObject $bios -PropertyName 'SMBIOSBIOSVersion')
    BiosDate       = (Get-FirstValue -InputObject $bios -PropertyName 'ReleaseDate')
    WindowsCaption = (Get-FirstValue -InputObject $os -PropertyName 'Caption')
    WindowsVersion = (Get-FirstValue -InputObject $os -PropertyName 'Version')
    WindowsBuild   = (Get-FirstValue -InputObject $os -PropertyName 'BuildNumber')
    HypervisorPresent = (Get-FirstValue -InputObject $system -PropertyName 'HypervisorPresent')
} | Format-List

Write-Output '========== TPM STATUS (Get-Tpm) =========='
$tpm = $null
try {
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        $tpm = Get-Tpm -ErrorAction Stop
        [PSCustomObject]@{
            TpmPresent                = Get-FirstValue $tpm 'TpmPresent'
            TpmReady                  = Get-FirstValue $tpm 'TpmReady'
            TpmEnabled                = Get-FirstValue $tpm 'TpmEnabled'
            TpmActivated              = Get-FirstValue $tpm 'TpmActivated'
            TpmOwned                  = Get-FirstValue $tpm 'TpmOwned'
            ManufacturerIdTxt         = Get-FirstValue $tpm 'ManufacturerIdTxt'
            ManufacturerVersion       = Get-FirstValue $tpm 'ManufacturerVersion'
            ManufacturerVersionFull20 = Get-FirstValue $tpm 'ManufacturerVersionFull20'
            ManagedAuthLevel          = Get-FirstValue $tpm 'ManagedAuthLevel'
            AutoProvisioning          = Get-FirstValue $tpm 'AutoProvisioning'
            LockedOut                 = Get-FirstValue $tpm 'LockedOut'
        } | Format-List
    }
    else {
        Write-Output 'Get-Tpm cmdlet is unavailable on this system.'
    }
}
catch {
    Write-Output ('Get-Tpm query failed: ' + $_.Exception.Message)
}

Write-Output '========== WIN32 TPM METADATA =========='
try {
    $tpmCim = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $tpmCim) {
        [PSCustomObject]@{
            SpecVersion         = Get-FirstValue $tpmCim 'SpecVersion'
            ManufacturerId      = Get-FirstValue $tpmCim 'ManufacturerId'
            ManufacturerIdTxt   = Get-FirstValue $tpmCim 'ManufacturerIdTxt'
            ManufacturerVersion = Get-FirstValue $tpmCim 'ManufacturerVersion'
        } | Format-List
    }
    else {
        Write-Output 'Win32_Tpm returned no instance.'
    }
}
catch {
    Write-Output ('Win32_Tpm query unavailable: ' + $_.Exception.Message)
}

Write-Output '========== SECURE BOOT STATUS =========='
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Output ('SecureBootEnabled = ' + $secureBoot)
}
catch {
    Write-Output ('Secure Boot state unavailable: ' + $_.Exception.Message)
}

Write-Output ''
Write-Output '========== END OF READ-ONLY PROBE =========='
Write-Output 'This probe does not test TPM2_NV_Increment permission or NV counter availability.'
