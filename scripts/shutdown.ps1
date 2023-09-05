Write-Host "Fortify minikube shutdown script"

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

# Setup Java Environment and Tools
Set-JavaTools

& minikube stop

& minikube delete

$RootDir = Split-Path -Path $PSScriptRoot -Parent

$CertDir = "$($RootDir)\certificates"
If ((Test-Path -PathType container $CertDir))
{
    Remove-Item -LiteralPath $CertDir -Force -Recurse
}

$SSCSecretDir = "$($RootDir)\ssc-secret"
If ((Test-Path -PathType container $SSCSecretDir))
{
    Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
}
