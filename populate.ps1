# Example script to populate SSC environment with sample data via fcli

# Parameters
param (
    [Parameter(Mandatory=$false)]
    [switch]$SkipSamples,
    [Parameter(Mandatory=$false)]
    [switch]$SkipUsers
)

# Change the below to your preferred JVM
$Env:JAVA_HOME = "$($PSScriptRoot)\openjdk-jre-11.0.18-windows-x64\"
#$Env:PATH = "$($Env:JAVA_HOME)\bin;$Env:PATH"
function jfcli { java -jar .\fcli\fcli.jar $args }
$Env:FCLI_HOME = ".\fcli"

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

Write-Host "Using $(jfcli --version)"
Write-Host "Configuring SSL ..."
jfcli config ssl truststore clear
jfcli config ssl truststore set .\certificates\keystore.p12 -p changeme -t pkcs12
Write-Host "Logging in to $SSC_URL"
jfcli ssc session login --url="$SSC_URL" -u="$SSC_USER" -p="$SSC_PASSWORD"

if (-not $SkipUsers)
{
    # create demo group
    # create dev user
    # create security user
}

if (-not $SkipSamples)
{
    # create sample applications and import data
    jfcli ssc appversion create "ZeroBank:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Zero Online Bank" --auto-required-attrs --skip-if-exists
    # IWA-Java
    jfcli ssc appversion create "IWA-Java:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Insecure Web App (IWA) Java" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="IWA-Java:1.0" .\samples\IWA-Java-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="REQUIRE_AUTH,PROCESS_COMPLETE"
    jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload --appversion="IWA-Java:1.0" .\samples\IWA-Java-dast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload --appversion="IWA-Java:1.0" .\samples\IWA-Java-dast-api.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    # IWA-DotNet
    jfcli ssc appversion create "IWA-DotNet:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Insecure Web App (IWA) DotNet" --auto-required-attrs --skip-if-exists
    # TBD
    # IWA-Mobile
    jfcli ssc appversion create "IWA-Mobile:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Insecure Web App (IWA) Mobile" --auto-required-attrs --skip-if-exists
    # TBD
    # Bricks PHP
    #jfcli ssc appversion create "Bricks:2.2" --issue-template="Prioritized-LowRisk-Project-Template" --description="Bricks PHP" --auto-required-attrs --skip-if-exists
    #jfcli ssc appversion-artifact upload --appversion="Bricks:2.2" .\samples\Bricks-2.2-sast.fpr --store=myArtifact
    #jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    # Java Vulnerable Lab
    #jfcli ssc appversion create "Java VulnerableLab:2010-01-24" --issue-template="Prioritized-LowRisk-Project-Template" --description="Java VulnerableLab" --auto-required-attrs --skip-if-exists
    #jfcli ssc appversion-artifact upload --appversion="Java VulnerableLab:2010-01-24" .\samples\Java-VulnerableLab-2010-01-24-sast.fpr --store=myArtifact
    #jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    # OWASP Juice Shop
    jfcli ssc appversion create "Juice Shop:2021-06-30" --issue-template="Prioritized-HighRisk-Project-Template" --description="OWASP Juice Shop" --auto-required-attrs --skip-if-exists
    jfcli ssc appversion-artifact upload --appversion="Juice Shop:2021-06-30" .\samples\Juice-Shop-2021-06-30-sast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    jfcli ssc appversion-artifact upload --appversion="Juice Shop:2021-06-30" .\samples\Juice-Shop-2021-06-30-dast.fpr --store=myArtifact
    jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    # WebGoat Java
    #jfcli ssc appversion create "WebGoat-Java:8.2" --issue-template="Prioritized-HighRisk-Project-Template" --description="WebGoat Java" --auto-required-attrs --skip-if-exists
    #jfcli ssc appversion-artifact upload --appversion="WebGoat-Java:8.2" .\samples\WebGoat-Java-8.2-sast.fpr --store=myArtifact
    #jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    #jfcli ssc appversion-artifact upload --appversion="WebGoat-Java:8.2" .\samples\WebGoat-Java-8.2-dast.fpr --store=myArtifact
    #jfcli ssc appversion-artifact wait-for "{?myArtifact:id}"
    # WebGoat DotNet
    #jfcli ssc appversion create "WebGoat-DotNet:Version_1" --issue-template="Prioritized-HighRisk-Project-Template" --description="WebGoat DotNet" --auto-required-attrs --skip-if-exists
    #jfcli ssc appversion-artifact upload --appversion="WebGoat-DotNet:Version_1" .\samples\WebGoat-DotNet-Version_1-sast.fpr --store=myArtifact
    #jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="PROCESS_COMPLETE"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
    # Sample CPP
    #jfcli ssc appversion create "sample-cpp:1.0" --issue-template="Prioritized-HighRisk-Project-Template" --description="Sample CPP Project" --auto-required-attrs --skip-if-exists
    #jfcli ssc appversion-artifact upload --appversion="sample-cpp:1.0" .\samples\sample-cpp-1.0-sast.fpr --store=myArtifact
    #jfcli ssc appversion-artifact wait-for "{?myArtifact:id}" --until="REQUIRE_AUTH"
    #jfcli ssc appversion-artifact approve "{?myArtifact:id}"
}

# create demo app for starting scans in
Write-Host "Creating application version ${SSC_APP_NAME}:${SSC_APPVER_NAME}"
jfcli ssc appversion create "${SSC_APP_NAME}:${SSC_APPVER_NAME}" --issue-template="Prioritized-HighRisk-Project-Template" --description="$SSC_APP_NAME" --auto-required-attrs --skip-if-exists
jfcli ssc token create CIToken --store=myToken
$Env:FCLI_DEFAULT_SSC_CI_TOKEN = (jfcli config var contents get myToken -o "expr={restToken}")

# run a sample ScanCentral SAST scan in demo app
Write-Host "Running ScanCentral SAST scan on version ${SSC_APP_NAME}:${SSC_APPVER_NAME}"
jfcli sc-sast session login --ssc-url="$SSC_URL"  --ssc-ci-token="{?myToken:restToken}" --client-auth-token="$SC_SAST_CLIENT_AUTH_TOKEN"
jfcli sc-sast scan start -p .\samples\package.zip --appversion="${SSC_APP_NAME}:${SSC_APPVER_NAME}" --ssc-ci-token="{?myToken:restToken}" --sensor-version="$SENSOR_VERSION" --store=myScan
Start-Sleep -Seconds 5
jfcli sc-sast scan wait-for "{?myScan:jobToken}" --until-any="REQUIRE_AUTH|PROCESS_COMPLETE" -i 5s -t 1h
jfcli sc-sast session logout

jfcli ssc session logout

