
# Set IsWindows or IsLinux/IsMacOs variable accordingly
function Set-PSPlatform
{
    switch ([System.Environment]::OSVersion.Platform)
    {
        'Win32NT' {
            New-Variable -Option Constant -Name IsWindows -Scope global -Value $True -ErrorAction SilentlyContinue
            New-Variable -Option Constant -Name IsLinux   -Scope global -Value $false -ErrorAction SilentlyContinue
            New-Variable -Option Constant -Name IsMacOs   -Scope global -Value $false -ErrorAction SilentlyContinue
        }
    }
}
Export-ModuleMember -Function Set-PSPlatform

function Set-JavaTools
{
    Set-PSPlatform
    $RootPath = Split-Path $PSScriptRoot -Parent
    #Write-Host "RootPath=${RootPath}"
    if ($IsLinux)
    {
        Write-Host "Running on Linux ..."
        $JavaHome = Join-Path $RootPath -ChildPath "/openjdk-jre-11.0.18-linux-x64"
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java"
    }
    elseif ($IsWindows)
    {
        Write-Host "Running on Windows ..."
        $JavaHome = Join-Path $RootPath -ChildPath "openjdk-jre-11.0.18-windows-x64"
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java.exe"
    }
    else
    {
        throw "Unsupported platform"
    }
    New-Variable -Option Constant -Name JavaHome -Scope global -Value $JavaHome -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name JavaBin  -Scope global -Value $JavaBin -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name JavaExe  -Scope global -Value $JavaExe -ErrorAction SilentlyContinue
}
Export-ModuleMember -Function Set-JavaTools

function Get-PodStatus
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$PodName
    )
    $Status = (kubectl get pods -n default $PodName -o jsonpath="{.status.phase}") 2>$null
    return $Status
}
Export-ModuleMember Get-PodStatus

function Wait-UntilPodStatus
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$PodName,
        [Parameter(Mandatory=$false)]
        [String]$UntilStatus = "Running"
    )
    $Status = $Null
    Write-Host -n "Waiting for ${PodName} status: ${UntilStatus} "
    While ($Status -ne $UntilStatus)
    {
        $Status = (kubectl get pods -n default $PodName -o jsonpath="{.status.phase}") 2>$null
        Write-Host -n "."
        Start-Sleep -Seconds 5
    }
    Write-Host ""
    return $Status
}
Export-ModuleMember Wait-UntilPodStatus
