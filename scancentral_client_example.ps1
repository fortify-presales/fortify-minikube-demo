#
# Example script to perform Fortify ScanCentral SAST scan
#

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath "fcli.env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))

$SSC_USER=$EnvSettings['FCLI_DEFAULT_SSC_USER']
$SSC_PASSWORD=$EnvSettings['FCLI_DEFAULT_SSC_PASSWORD']
$SSC_URL=$EnvSettings['FCLI_DEFAULT_SSC_URL']
$SCSAST_URL=$EnvSettings['FCLI_DEFAULT_SCSAST_URL']
$SC_SAST_CLIENT_AUTH_TOKEN=$EnvSettings['FCLI_DEFAULT_SC_SAST_CLIENT_AUTH_TOKEN']
$SC_SAST_WORKER_AUTH_TOKEN=$EnvSettings['FCLI_DEFAULT_SC_SAST_WORKER_AUTH_TOKEN']
$SC_SAST_SHARED_SECRET=$EnvSettings['FCLI_DEFAULT_SC_SAST_SHARED_SECRET']
$SENSOR_VERSION=$EnvSettings['FCLI_DEFAULT_SENSOR_VERSION']
$SSC_APP_NAME=$EnvSettings['FCLI_DEFAULT_SSC_APP']
$SSC_APPVER_NAME=$EnvSettings['FCLI_DEFAULT_SSC_APPVERSION']

# Change the below to your preferred JVM
$Env:JAVA_HOME = "$($PSScriptRoot)\openjdk-jre-11.0.18-windows-x64\"
# ScanCentral Client should have been installed by fcli in "populate.ps1"
$Env:PATH = "$($Env:JAVA_HOME)\bin;$($PSScriptRoot)\scancentral_client\bin;$Env:PATH"

# Importing certificates
& "$($Env:JAVA_HOME)\bin\keytool" -importkeystore -srckeystore "$($PSScriptRoot)\certificates\keystore.p12" -srcstoretype pkcs12 -destkeystore "$($Env:JAVA_HOME)\lib\security\cacerts" -srcstorepass changeme -deststorepass changeit -noprompt

fcli ssc token create CIToken --store=myToken
$Env:FCLI_DEFAULT_SSC_CI_TOKEN = (fcli state var contents myToken -o "expr={restToken}")
fcli ssc session logout

Write-Host "Installing Scancentral Client ..."
fcli tool scancentral-client install -d "$( $PSScriptRoot )\scancentral_client" -y -t $SC_SAST_CLIENT_AUTH_TOKEN $SCANCENTRAL_VERSION

# Package, upload and run the scan and import results into SSC
Write-Host Invoking ScanCentral SAST ...
& "$( $PSScriptRoot )\scancentral_client\bin\scancentral.bat" -url $SCSAST_URL start -upload -uptoken $Env:FCLI_DEFAULT_SSC_CI_TOKEN `
    -b $SSC_APP_NAME -application $SSC_APP_NAME -version $SSC_APP_VER_NAME -p .\samples\package.zip `
    -block -o -f "$($SSC_APP_NAME).fpr"

# Uncomment if not using "-block" in scancentral command above
#Write-Host
#Write-Host You can check ongoing status with:
#Write-Host " scancentral -url $Env:FCLI_DEFAULT_SCSAST_URL status -token [received-token]"
