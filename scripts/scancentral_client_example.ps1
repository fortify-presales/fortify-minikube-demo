#
# Example script to perform Fortify ScanCentral SAST scan
#

$RootDir = Split-Path -Path $PSScriptRoot -Parent

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))

$SCSAST_URL=$EnvSettings['SCSAST_URL']
$SSC_APP_NAME=$EnvSettings['SSC_APP_NAME']
$SSC_APP_VER_NAME=$EnvSettings['SSC_APP_VER_NAME']
$SSC_CI_TOKEN=$EnvSettings['SSC_CI_TOKEN']

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

# Setup Java Environment and Tools
Set-JavaTools

# ScanCentral Client should have been installed
#$Env:PATH = "$($JavaHome)\bin;$($PSScriptRoot)\scancentral_client\bin;$Env:PATH"

# Package, upload and run the scan and import results into SSC
Write-Host Invoking ScanCentral SAST ...
& "$( $RootDir )\scancentral_client\bin\scancentral.bat" -url $SCSAST_URL start -upload -uptoken $SSC_CI_TOKEN `
    -application $SSC_APP_NAME -version $SSC_APP_VER_NAME -p "$( $RootDir )\samples\package.zip" `
    -block -o -f "$( $RootDir)\$($SSC_APP_NAME).fpr"

