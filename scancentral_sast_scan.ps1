#
# Example script to perform Fortify ScanCentral SAST scan
#

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))

$SSC_URL=$EnvSettings['SSC_URL']
$SCSAST_URL=$EnvSettings['SCSAST_URL']
$SSC_APP_NAME=$EnvSettings['SSC_APP_NAME']
$SSC_APP_VER_NAME=$EnvSettings['SSC_APP_VER_NAME']
$SSC_CI_TOKEN=$EnvSettings['SSC_CI_TOKEN']
$SCANCENTRAL_VERSION=$EnvSettings['SCANCENTRAL_VERSION']
$CLIENT_AUTH_TOKEN=$EnvSettings['CLIENT_AUTH_TOKEN']

if ([string]::IsNullOrEmpty($SSC_URL)) { throw "SSC_URL needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SCSAST_URL)) { throw "SCSAST_URL needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SSC_APP_NAME)) { throw "SSC_APP_NAME needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SSC_APP_VER_NAME)) { throw "SSC_APP_VER_NAME needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SSC_CI_TOKEN)) { throw "SSC_CI_TOKEN needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SCANCENTRAL_VERSION)) { throw "SCANCENTRAL_VERSION needs to be set in .env file" }
if ([string]::IsNullOrEmpty($CLIENT_AUTH_TOKEN)) { throw "CLIENT_AUTH_TOKEN needs to be set in .env file" }

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

# Setup Java Environment and Tools
Set-JavaTools
$Env:JAVA_HOME=$JavaHome
Write-Host "Using JAVA_HOME=$($Env:JAVA_HOME)"

if (-not(Test-Path -PathType container "scancentral-client")) {
    Write-Host "Installing ScanCentral Client $($SCANCENTRAL_VERSION)"
    Install-ScanCentralClient -Version $SCANCENTRAL_VERSION -ClientAuthToken $CLIENT_AUTH_TOKEN
}

# Package, upload and run the scan and import results into SSC
Write-Host Invoking ScanCentral SAST ...
& ".\scancentral-client\bin\scancentral.bat" -url $SCSAST_URL start -upload -uptoken $SSC_CI_TOKEN `
    -application $SSC_APP_NAME -version $SSC_APP_VER_NAME -p ".\samples\package.zip" `
    -block -o -f ".\$($SSC_APP_NAME).fpr"

