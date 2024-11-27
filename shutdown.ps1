Write-Host "Fortify minikube shutdown script"

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

& minikube stop

& minikube delete

$CertDir = "$($PSScriptRoot)\certificates"
If ((Test-Path -PathType container $CertDir))
{
    Remove-Item -LiteralPath $CertDir -Force -Recurse
}

$SSCSecretDir = "$($PSScriptRoot)\ssc-secret"
If ((Test-Path -PathType container $SSCSecretDir))
{
    Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
}
