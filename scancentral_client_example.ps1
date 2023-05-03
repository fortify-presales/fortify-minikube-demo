#
# Example script to perform Fortify ScanCentral SAST scan
#

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))

$SSC_APP_NAME = $EnvSettings['SSC_APP_NAME']
$SSC_APP_VER_NAME = $EnvSettings['SSC_APP_VER_NAME']

if ([string]::IsNullOrEmpty($SSC_APP_NAME)) { $SSC_APP_NAME = "FortifyDemoApp" }
if ([string]::IsNullOrEmpty($SSC_APP_VER_NAME)) { $SSC_APP_VER_NAME = "1.0" }

$Env:JAVA_HOME = "$($PSScriptRoot)\openjdk-jre-11.0.18\"
$Env:PATH = "$($Env:JAVA_HOME)\bin;$($PSScriptRoot)\scancentral_client\bin;$Env:PATH"

# Importing certificates
keytool -importkeystore -srckeystore "$($PSScriptRoot)\certificates\keystore.p12" -srcstoretype pkcs12 -destkeystore "$($Env:JAVA_HOME)\lib\security\cacerts" -srcstorepass changeme -deststorepass changeit -noprompt

# Package, upload and run the scan and import results into SSC
Write-Host Invoking ScanCentral SAST ...
& scancentral -url $Env:FCLI_DEFAULT_SCSAST_URL start -upload -uptoken $Env:FCLI_DEFAULT_SSC_CI_TOKEN `
    -b $SSC_APP_NAME -application $SSC_APP_NAME -version $SSC_APP_VER_NAME -p .\samples\package.zip `
    -block -o -f "$($SSC_APP_NAME).fpr"

# Uncomment if not using "-block" in scancentral command above
#Write-Host
#Write-Host You can check ongoing status with:
#Write-Host " scancentral -url $Env:FCLI_DEFAULT_SCSAST_URL status -token [received-token]"
