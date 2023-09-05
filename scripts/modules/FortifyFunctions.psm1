
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
        $JavaHome = Join-Path $RootPath -ChildPath "jdk-17-jre-linux-x64"
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java"
        $KeytoolExe = Join-Path $JavaBin -ChildPath "keytool"
    }
    elseif ($IsWindows)
    {
        Write-Host "Running on Windows ..."
        $JavaHome = Join-Path $RootPath -ChildPath "jdk-17-jre-windows-x64"
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java.exe"
        $KeytoolExe = Join-Path $JavaBin -ChildPath "keytool.exe"
    }
    else
    {
        throw "Unsupported platform"
    }
    $FcliDir = Join-Path $RootPath -ChildPath "fcli"
    $FcliJar = Join-Path $FcliDir -ChildPath "fcli.jar"
    New-Variable -Option Constant -Name JavaHome -Scope global -Value $JavaHome -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name JavaBin  -Scope global -Value $JavaBin -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name JavaExe  -Scope global -Value $JavaExe -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name KeytoolExe  -Scope global -Value $KeytoolExe -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name FcliDir  -Scope global -Value $FcliDir -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name FcliJar  -Scope global -Value $FcliJar -ErrorAction SilentlyContinue
}
Export-ModuleMember -Function Set-JavaTools

function Invoke-Fcli
{
    $ArgumentList = @("-jar", $FcliJar)
    ForEach ($a in $args) { $ArgumentList += $a}
    Write-Host "Executing fcli: java $ArgumentList"
    $params = @{
        FilePath = $JavaExe
        WorkingDirectory = $PSScriptRoot
        ArgumentList = $ArgumentList
        PassThru = $true
        Wait = $true
    }
    $p = Start-Process @params
}
Export-ModuleMember -Function Invoke-Fcli

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
    Write-Host -n "Waiting unitl ${PodName} is ${UntilStatus} "
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

function Update-EnvFile
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$File,
        [Parameter(Mandatory=$true)]
        [String]$Find,
        [Parameter(Mandatory=$true)]
        [String]$Replace
    )
    Write-Host $File
    (Get-Content -Path $File) | ForEach-Object{$_ -replace $Find,$Replace} | Set-Content -Path $File
}
Export-ModuleMember Update-EnvFile
