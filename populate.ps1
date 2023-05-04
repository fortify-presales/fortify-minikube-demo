# Example script to populate SSC environment with sample data via fcli

# Parameters
param (
    [Parameter(Mandatory=$false)]
    [switch]$SkipSamples
)

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
$Env:FCLI

Write-Host "Using $(jfcli --version)"
jfcli config ssl truststore clear
jfcli config ssl truststore set .\certificates\keystore.p12 -p changeme -t pkcs12
jfcli ssc session login --url="$Env:FCLI_DEFAULT_SSC_URL" -u="$SSC_ADMIN_USER" -p="$SSC_ADMIN_PASSWORD"

if (-not $SkipSamples)
{
    # create sample applications and import data
    # IWA-Java
    jfcli ssc appversion create "IWA-Java:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Insecure Web App (IWA) Java" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload ---appversion="IWA-Java:1.0" .\samples\IWA-Java-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="REQUIRE_AUTH"
    jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload ---appversion="IWA-Java:1.0" .\samples\IWA-Java-dast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload --appversio ="IWA-Java:1.0" .\samples\IWA-Java-dast-api.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    # IWA-DotNet
    jfcli ssc appversion create "IWA-DotNet:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Insecure Web App (IWA) DotNet" --auto-required-attrs --skip-if-exists
    # TBD
    # IWA-Mobile
    jfcli ssc appversion create "IWA-Mobile:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Insecure Web App (IWA) Mobile" --auto-required-attrs --skip-if-exists
    # TBD
    # Bricks PHP
    jfcli ssc appversion create "Bricks:2.2" --issue-template="Prioritized-LowRisk-Project-Template" --description="Bricks PHP" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="Bricks:2.2" .\samples\Bricks-2.2-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    # Java Vulnerable Lab
    jfcli ssc appversion create "Java VulnerableLab:2010-01-24" --issue-template="Prioritized-LowRisk-Project-Template" --description="Java VulnerableLab" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="Java VulnerableLab:2010-01-24" .\samples\Java-VulnerableLab-2010-01-24-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    # Juice Shop
    jfcli ssc appversion create "Juice Shop:2021-06-30" --issue-template="Prioritized-HighRisk-Project-Template" --description="OWASP Juice Shop" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="Juice Shop:2021-06-30" .\samples\Juice-Shop-2021-06-30-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload --appversion="Juice Shop:2021-06-30" .\samples\Juice-Shop-2021-06-30-dast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    # WebGoat Java
    jfcli ssc appversion create "WebGoat-Java:8.2" --issue-template="Prioritized-HighRisk-Project-Template" --description="WebGoat Java" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="WebGoat-Java:8.2" .\samples\WebGoat-Java-8.2-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload --appversion="WebGoat-Java:8.2" .\samples\WebGoat-Java-8.2-dast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    # WebGoat DotNet
    jfcli ssc appversion create "WebGoat-DotNet:Version_1" --issue-template="Prioritized-HighRisk-Project-Template" --description="WebGoat DotNet" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="WebGoat-DotNet:Version_1" .\samples\WebGoat-DotNet-Version_1-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    # Sample CPP
    jfcli ssc appversion create "sample-cpp:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Sample CPP Project" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="sample-cpp:1.0" .\samples\sample-cpp-1.0-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="REQUIRE_AUTH"
    jfcli ssc appversion-artifact approve "{?myArtifact:id}"
}

# create demo app for starting scan
jfcli ssc appversion create FortifyDemoApp:1.0 --issue-template="Prioritized-HighRisk-Project-Template" --description="$SSC_APP_NAME" --auto-required-attrs --skip-if-exists
jfcli ssc token create CIToken --store=myToken
$Env:FCLI_DEFAULT_SSC_CI_TOKEN = (jfcli config var contents get myToken -o "expr={restToken}")
jfcli ssc session logout

# run a sample ScanCentral SAST scan
jfcli sc-sast session login --ssc-url="$Env:FCLI_DEFAULT_SSC_URL" --ssc-ci-token="{?myToken:restToken}" --client-auth-token="$Env:FCLI_DEFAULT_SC_SAST_CLIENT_AUTH_TOKEN"
jfcli sc-sast scan start -p .\samples\package.zip -appversion"$($SSC_APP_NAME):$($SSC_APP_VER_NAME)" --sensor-version="$Env:FCLI_DEFAULT_SENSOR_VERSION" --store=myScan
Start-Sleep -Seconds 5
jfcli sc-sast scan wait-for "{?myScan:jobToken}" --until-any="REQUIRE_AUTH|PROCESS_COMPLETE" -i 5s -t 1h
jfcli sc-sast session logout
