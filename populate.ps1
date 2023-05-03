# Example script to populate SSC environment via fcli

function kubectl { minikube kubectl -- $args }
function jfcli { java -jar .\fcli\fcli.jar $args }

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))

$SCANCENTRAL_VERSION = $EnvSettings['SCANCENTRAL_VERSION']
$SSC_ADMIN_USER = $EnvSettings['SSC_ADMIN_USER']
$SSC_ADMIN_PASSWORD = $EnvSettings['SSC_ADMIN_PASSWORD']
$SSC_APP_NAME = $EnvSettings['SSC_APP_NAME']
$SSC_APP_VER_NAME = $EnvSettings['SSC_APP_VER_NAME']

if ([string]::IsNullOrEmpty($SSC_ADMIN_USER)) { $SSC_ADMIN_USER = "admin" }
if ([string]::IsNullOrEmpty($SSC_ADMIN_PASSWORD)) { $SSC_ADMIN_PASSWORD = "admin" }
if ([string]::IsNullOrEmpty($SCANCENTRAL_VERSION)) { $SCANCENTRAL_VERSION = "22.2.0" }
if ([string]::IsNullOrEmpty($SSC_APP_NAME)) { $SSC_APP_NAME = "FortifyDemoApp" }
if ([string]::IsNullOrEmpty($SSC_APP_VER_NAME)) { $SSC_APP_VER_NAME = "1.0" }

$MinikubeIP = (minikube ip)
$SSCUrl = "ssc.$($MinikubeIP.Replace('.','-')).nip.io"
$SCSASTUrl = "scsast.$($MinikubeIP.Replace('.','-')).nip.io"
$SCDASTAPIUrl = "scsastapi.$($MinikubeIP.Replace('.','-')).nip.io"

$ClientAuthTokenBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-client-auth-token}")
$ClientAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ClientAuthTokenBase64))
$WorkerAuthTokenBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-worker-auth-token}")
$WorkerAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WorkerAuthTokenBase64))
$ScanCentralCtrlSecretBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-ssc-scancentral-ctrl-secret}")
$ScanCentralCtrlSecret = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ScanCentralCtrlSecretBase64))

$Env:PATH = "$($PSScriptRoot)\fcli;$Env:PATH"

# store FCLI vars locally
$Env:FCLI_HOME="$($PSScriptRoot)\fcli"
# use local JRE
#$Env:JAVA_HOME="$($PSScriptRoot)\openjdk-jre-11.0.18"

$Env:FCLI_DEFAULT_SSC_USER=$EnvSettings['SSC_ADMIN_USER']
$Env:FCLI_DEFAULT_SSC_PASSWORD=$EnvSettings['SSC_ADMIN_PASSWORD']
$Env:FCLI_DEFAULT_SSC_URL="https://$($SSCUrl)"
$Env:FCLI_DEFAULT_SCSAST_URL="https://$($SCSASTUrl)/scancentral-ctrl/"
$Env:FCLI_DEFAULT_SC_SAST_CLIENT_AUTH_TOKEN="$ClientAuthToken"
$Env:FCLI_DEFAULT_SC_SAST_WORKER_AUTH_TOKEN="$WorkerAuthToken"
$Env:FCLI_DEFAULT_SC_SAST_SHARED_SECRET="$ScanCentralCtrlSecret"
$Env:FCLI_DEFAULT_SENSOR_VERSION="$SCANCENTRAL_VERSION"

Write-Host "Using $(jfcli --version)"
jfcli config ssl truststore clear
jfcli config ssl truststore set .\certificates\keystore.p12 -p changeme -t pkcs12
jfcli ssc session login --url="$Env:FCLI_DEFAULT_SSC_URL" -u="$SSC_ADMIN_USER" -p="$SSC_ADMIN_PASSWORD"
# create sample applications and import data
jfcli ssc appversion create IWA-Java:1.0 --issue-template="Prioritized-LowRisk-Project-Template" --description="IWA-JAVA 1.0" --auto-required-attrs --skip-if-exists
jfcli ssc appversion-artifact upload --appversion="IWA-Java:1.0" .\samples\IWA-Java-sast.fpr --store=myArtifact
jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="REQUIRE_AUTH"
jfcli ssc appversion-artifact approve "{?myArtifact:id}"
jfcli ssc appversion-artifact upload --appversion="IWA-Java:1.0" .\samples\IWA-Java-dast.fpr --store=myArtifact
jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
jfcli ssc appversion-artifact upload --appversion="IWA-Java:1.0" .\samples\IWA-Java-dast-api.fpr --store=myArtifact
jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
# create demo app
jfcli ssc appversion create FortifyDemoApp:1.0 --issue-template="Prioritized-LowRisk-Project-Template" --description="$SSC_APP_NAME" --auto-required-attrs --skip-if-exists
jfcli ssc token create CIToken --store=myToken
$Env:FCLI_DEFAULT_SSC_CI_TOKEN = (jfcli config var contents get myToken -o "expr={restToken}")
jfcli ssc session logout
# run a sample ScanCentral SAST scan
jfcli sc-sast session login --ssc-url="$Env:FCLI_DEFAULT_SSC_URL" --ssc-ci-token="{?myToken:restToken}" --client-auth-token="$Env:FCLI_DEFAULT_SC_SAST_CLIENT_AUTH_TOKEN"
jfcli sc-sast scan start -p .\samples\package.zip --appversion "$($SSC_APP_NAME):$($SSC_APP_VER_NAME)" --sensor-version="$SENSOR_VERSION" --store=myScan
Start-Sleep -Seconds 5
jfcli sc-sast scan wait-for "{?myScan:jobToken}" -i 5s -t 1h
jfcli sc-sast session logout
