Write-Host "Fortify minikube shutdown script"

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

# Setup Java Environment and Tools
Set-JavaTools

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

$FcliDir = "$($PSScriptRoot)\fcli"
If ((Test-Path -PathType container $FcliDir))
{
    Get-ChildItem -Path $FcliDir -Exclude 'fcli.*' | Remove-Item -Recurse -Force
}

if ((Test-Path -PathType Leaf "fcli.env"))
{
    Remove-Item -Path fcli.env -Force
}    

#Invoke-Fcli tool scancentral-client uninstall latest -y