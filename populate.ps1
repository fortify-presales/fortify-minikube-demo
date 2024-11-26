Write-Host "Fortify Population script"

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))
$EnvFile = Join-Path $PSScriptRoot -ChildPath ".env"

$SSC_ADMIN_USER = $EnvSettings['SSC_ADMIN_USER']
$SSC_ADMIN_PASSWORD = $EnvSettings['SSC_ADMIN_PASSWORD']
$SSC_URL = $EnvSettings['SSC_URL']

if ([string]::IsNullOrEmpty($SSC_ADMIN_USER)) { $SSC_ADMIN_USER = "admin" }
if ([string]::IsNullOrEmpty($SSC_ADMIN_PASSWORD)) { $SSC_ADMIN_PASSWORD = "admin" }
if ([string]::IsNullOrEmpty($SSC_URL)) { throw "SSC_URL needs to be set in .env file" }

$CertDir = "$($PSScriptRoot)\certificates"
$TrustStore = Join-Path $CertDir -ChildPath "ssc-service.jks"

fcli config truststore set -f $TrustStore -p changeit -t jks
fcli ssc session login --url $SSC_URL -k -u $SSC_ADMIN_USER -p $SSC_ADMIN_PASSWORD

fcli ssc appversion create IWA-Java:1.0 --auto-required-attrs --issue-template Prioritized-HighRisk-Project-Template --skip-if-exists
fcli ssc appversion create IWA-DotNet:1.0 --auto-required-attrs --issue-template Prioritized-HighRisk-Project-Template --skip-if-exists
fcli ssc appversion create ZeroBank:1.0 --auto-required-attrs --issue-template Prioritized-HighRisk-Project-Template --skip-if-exists

fcli ssc session logout