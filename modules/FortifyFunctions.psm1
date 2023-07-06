

function Test-Environment {
    $SCALocalInstall = $True
    $ScanCentralClient = $True

    $WarningPreference = "Continue"

    Write-Host "Validating Fortify Installation..."

    # Check Source Analyzer is on the path
    if ((Get-Command "sourceanalyzer.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-Warning "Unable to find sourceanalyzer.exe in your PATH - local analysis and scan not available"
        $SCALocalInstall = $False
    }

    # Check FPR Utility is on the path
    if ((Get-Command "FPRUtility.bat" -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-Warning "Unable to find FPRUtility.bat in your PATH - issue summaries not available"
        $SCALocalInstall = $False
    }

    # Check Report Generator is on the path
    if ((Get-Command "ReportGenerator.bat" -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-Warning "Unable to find ReportGenerator.bat in your PATH - report generation not available"
        $SCALocalInstall = $False
    }

    # Check Fortify Client is installed
    if ((Get-Command "fortifyclient.bat" -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-Warning "fortifyclient.bat is not in your PATH - upload to SSC not available"
        $SCALocalInstall = $False
    }

    # Check ScanCentral Client is installed
    if ((Get-Command "scancentral.bat" -ErrorAction SilentlyContinue) -eq $null)
    {
        if ($SCALocalInstall -eq $False) {
            Write-Host
            throw "scancentral.bat is not in your PATH - cannot run local or remote scan, exiting ..."
        }
        $ScanCentralClient = $False
    }

    Write-Host "Done."
}


function Test-ThirdPartyEnvironment {
    Write-Host "Validating Third Party Installation..."

    # Check Maven is on the path
    if ((Get-Command "mvn" -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-Host
        throw "Unable to find mvn in your PATH"
    }

    # Check Sonatype is installed
    if ((Get-Command "nexus-iq-cli.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-Host
        throw "Unable to find nexus-iq-cli.exe is not in your PATH"
    }

    Write-Host "Done."
}

$TestVar = "abcd"
Export-ModuleMember -Variable TestVar

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
        Write-Host "Running on Linux..."
        $JavaHome = Join-Path $RootPath -ChildPath "/openjdk-jre-11.0.18-linux-x64"
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java"
    }
    elseif ($IsWindows)
    {
        Write-Host "Running on Windows..."
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
