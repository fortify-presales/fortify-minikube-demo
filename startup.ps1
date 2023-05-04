# Example script to start minikube on Windows (Hyoer-V) and install Fortify ScanCentral SAST/DAST

# Parameters
param (
    [Parameter(Mandatory=$false)]
    [switch]$StartDAST
)

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))

$MINIKUBE_MEM = $EnvSettings['MINIKUBE_MEM']
$MINIKUBE_CPUS = $EnvSettings['MINIKUBE_CPUS']
$SSC_ADMIN_USER = $EnvSettings['SSC_ADMIN_USER']
$SSC_ADMIN_PASSWORD = $EnvSettings['SSC_ADMIN_PASSWORD']
$DOCKERHUB_USERNAME = $EnvSettings['DOCKERHUB_USERNAME']
$DOCKERHUB_PASSWORD = $EnvSettings['DOCKERHUB_PASSWORD']
$OPENSSL_PATH = $EnvSettings['OPENSSL_PATH']
$SCANCENTRAL_VERSION = $EnvSettings['SCANCENTRAL_VERSION']
$SSC_HELM_VERSION = $EnvSettings['SSC_HELM_VERSION']
$SCSAST_HELM_VERSION = $EnvSettings['SCSAST_HELM_VERSION']
$SCDAST_HELM_VERSION = $EnvSettings['SCDAST_HELM_VERSION']
$MYSQL_HELM_VERSION = $EnvSettings['MYSQL_HELM_VERSION']
$POSTGRES_HELM_VERSION = $EnvSettings['POSTGRES_HELM_VERSION']

if ([string]::IsNullOrEmpty($MINIKUBE_MEM)) { $MINIKUBE_MEM = "8192" }
if ([string]::IsNullOrEmpty($MINIKUBE_CPUS)) { $MINIKUBE_CPUS = "2" }
if ([string]::IsNullOrEmpty($SSC_ADMIN_USER)) { $SSC_ADMIN_USER = "admin" }
if ([string]::IsNullOrEmpty($SSC_ADMIN_PASSWORD)) { $SSC_ADMIN_PASSWORD = "admin" }
if ([string]::IsNullOrEmpty($DOCKERHUB_USERNAME)) { throw "DOCKER_USERNAME needs to be set in .env file" }
if ([string]::IsNullOrEmpty($DOCKERHUB_PASSWORD)) { throw "DOCKER_PASSWORD needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SCANCENTRAL_VERSION)) { $SCANCENTRAL_VERSION = "22.2.0" }
if ([string]::IsNullOrEmpty($SSC_HELM_VERSION)) { $SSC_HELM_VERSION = "1.1.2221008" }
if ([string]::IsNullOrEmpty($SCSAST_HELM_VERSION)) { $SCSAST_HELM_VERSION = "22.2.0" }
if ([string]::IsNullOrEmpty($SCDAST_HELM_VERSION)) { $SCDAST_HELM_VERSION = "22.2.1" }
if ([string]::IsNullOrEmpty($MYSQL_HELM_VERSION)) { $MYSQL_HELM_VERSION = "9.3.1" }
if ([string]::IsNullOrEmpty($POSTGRES_HELM_VERSION)) { $POSTGRES_HELM_VERSION = "11.9.0" }
if ([string]::IsNullOrEmpty($OPENSSL_PATH)) { $OPENSSL_PATH= "openssl" }

function kubectl { minikube kubectl -- $args }

& minikube start --memory $MINIKUBE_MEM --cpus $MINIKUBE_CPUS
Start-Sleep -Seconds 5
& minikube addons enable ingress

$MinikubeIP = (minikube ip)
$SSCUrl = "ssc.$($MinikubeIP.Replace('.','-')).nip.io"
$SCSASTUrl = "scsast.$($MinikubeIP.Replace('.','-')).nip.io"
$SCDASTAPIUrl = "scsastapi.$($MinikubeIP.Replace('.','-')).nip.io"
$CertUrl = "/CN=*.$($MinikubeIP.Replace('.','-')).nip.io"

Write-Host "Creating certificates ..."

$CertDir = "$($PSScriptRoot)\certificates"
If ((Test-Path -PathType container $CertDir))
{
    Remove-Item -LiteralPath $CertDir -Force -Recurse
}
New-Item -ItemType Directory -Path $CertDir

Set-Location $CertDir

& "$OPENSSL_PATH" req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem -subj $CertUrl

kubectl create secret tls wildcard-certificate --cert=certificate.pem --key=key.pem

& "$OPENSSL_PATH" pkcs12 -export -name ssc -in certificate.pem -inkey key.pem -out keystore.p12 -password pass:changeme

& keytool -importkeystore -destkeystore ssc-service.jks -srckeystore keystore.p12 -srcstoretype pkcs12 -alias ssc -srcstorepass changeme -deststorepass changeme

& keytool -import -trustcacerts -file certificate.pem -alias "wildcard-cert" -keystore truststore -storepass changeme -noprompt

keytool -importkeystore -srckeystore "$($PSScriptRoot)\certificates\keystore.p12" -srcstoretype pkcs12 -destkeystore "$($Env:JAVA_HOME)\lib\security\cacerts" -srcstorepass changeme -deststorepass changeit -noprompt

Set-Location $PSScriptRoot

Write-Host "Installing MySql ..."

& helm repo add bitnami https://charts.bitnami.com/bitnami
& helm install mysql bitnami/mysql -f mysql-values.yaml --version $MYSQL_HELM_VERSION

Start-Sleep -Seconds 30

if ($StartDAST)
{
    Write-Host "Installing Postgres ..."
    & helm install postgresql bitnami/postgresql --version $POSTGRES_HELM_VERSION `
        --set auth.postgresPassword = password `
        --set auth.database = scdast_db
}

kubectl create secret docker-registry fortifydocker --docker-username $DOCKERHUB_USERNAME --docker-password $DOCKERHUB_PASSWORD

Write-Host "Installing SSC ..."

$SSCSecretDir = "$($PSScriptRoot)\ssc-secret"
If ((Test-Path -PathType container $SSCSecretDir))
{
    Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
}
New-Item -ItemType Directory -Path $SSCSecretDir

Copy-Item "$($PSScriptRoot)\ssc.autoconfig" -Destination $SSCSecretDir
Copy-Item "$($PSScriptRoot)\fortify.license" -Destination $SSCSecretDir
Copy-Item "$($CertDir)\ssc-service.jks" -Destination $SSCSecretDir
Copy-Item "$($CertDir)\truststore" -Destination $SSCSecretDir

Set-Location $SSCSecretDir

kubectl create secret generic ssc `
    --from-file=. `
    --from-literal=ssc-service.jks.password=changeme `
    --from-literal=ssc-service.jks.key.password=changeme `
    --from-literal=truststore.password=changeme

Set-Location $PSScriptRoot

& helm repo add fortify https://fortify.github.io/helm3-charts

& helm install ssc fortify/ssc --version $SSC_HELM_VERSION `
    --set urlHost=$SSCUrl `
    --set imagePullSecrets[0].name=fortifydocker `
    --set secretRef.name=ssc `
    --set secretRef.keys.sscLicenseEntry=fortify.license `
    --set secretRef.keys.sscAutoconfigEntry=ssc.autoconfig `
    --set secretRef.keys.httpCertificateKeystoreFileEntry=ssc-service.jks `
    --set secretRef.keys.httpCertificateKeystorePasswordEntry=ssc-service.jks.password `
    --set secretRef.keys.httpCertificateKeyPasswordEntry=ssc-service.jks.key.password `
    --set secretRef.keys.jvmTruststoreFileEntry=truststore `
    --set secretRef.keys.jmvTruststorePasswordEntry=truststore.password `
    --set resources=null

Start-Sleep -Seconds 10

kubectl create ingress ssc-ingress `
    --rule="$($SSCUrl)/*=ssc-service:443,tls=wildcard-certificate" `
    --annotation nginx.ingress.kubernetes.io/backend-protocol=HTTPS `
    --annotation nginx.ingress.kubernetes.io/proxy-body-size='0' `
    --annotation nginx.ingress.kubernetes.io/client-max-body-size='512M'

Start-Sleep -Seconds 30

Write-Host "Installing ScanCentral SAST ..."

helm install scancentral-sast fortify/scancentral-sast --version $SCSAST_HELM_VERSION `
    --set imagePullSecrets[0].name=fortifydocker `
    --set-file fortifyLicense=fortify.license `
    --set controller.thisUrl="https://$($SCSASTUrl)/scancentral-ctrl" `
    --set controller.sscUrl="https://$($SSCUrl)" `
    --set-file controller.trustedCertificates[0]=certificates/certificate.pem `
    --set controller.persistence.enabled=false `
    --set controller.ingress.enabled=true `
    --set controller.ingress.hosts[0].host="$($SCSASTUrl)" `
    --set controller.ingress.hosts[0].paths[0].path=/ `
    --set controller.ingress.hosts[0].paths[0].pathType=Prefix `
    --set controller.ingress.tls[0].secretName=wildcard-certificate `
    --set controller.ingress.tls[0].hosts[0]=$($SCSASTUrl) `
    --set controller.ingress.annotations."nginx\.ingress\.kubernetes\.io/proxy-body-size"="512m"

Start-Sleep -Seconds 10

$ClientAuthTokenBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-client-auth-token}")
$ClientAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ClientAuthTokenBase64))
$WorkerAuthTokenBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-worker-auth-token}")
$WorkerAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WorkerAuthTokenBase64))
$ScanCentralCtrlSecretBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-ssc-scancentral-ctrl-secret}")
$ScanCentralCtrlSecret = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ScanCentralCtrlSecretBase64))

if ($StartDAST)
{
    Write-Host "Installing ScanCentral DAST ..."
    # TBD
}

Write-Host "Setting Fortify Environment for minikube"
$Env:FCLI_HOME="$($PSScriptRoot)\fcli"

$Env:FCLI_DEFAULT_SSC_USER=$EnvSettings['SSC_ADMIN_USER']
$Env:FCLI_DEFAULT_SSC_PASSWORD=$EnvSettings['SSC_ADMIN_PASSWORD']
$Env:FCLI_DEFAULT_SSC_URL="https://$($SSCUrl)"
$Env:FCLI_DEFAULT_SCSAST_URL="https://$($SCSASTUrl)/scancentral-ctrl/"
$Env:FCLI_DEFAULT_SC_SAST_CLIENT_AUTH_TOKEN="$ClientAuthToken"
$Env:FCLI_DEFAULT_SC_SAST_WORKER_AUTH_TOKEN="$WorkerAuthToken"
$Env:FCLI_DEFAULT_SC_SAST_SHARED_SECRET="$ScanCentralCtrlSecret"

#$Env:JAVA_HOME = "$($PSScriptRoot)\openjdk-jre-11.0.18\"
$Env:PATH = "$($PSScriptRoot)\fcli;$($PSScriptRoot)\scancentral-client\bin;$Env:PATH"

function jfcli { java -jar .\fcli\fcli.jar $args }

Write-Host "Installing Scancentral Client..."
jfcli tool scancentral-client install -d "$($PSScriptRoot)\scancentral_client" -y -t $ClientAuthToken
jfcli tool scancentral-client uninstall -y

Write-Host ""
Write-Host "================================================================================"
Write-Host "Software Security Center URL: https://$($SSCUrl)"
Write-Host "ScanCentral Controller URL: https://$($SCSASTUrl)/scancentral-ctrl/"
Write-Host "Client Authentication Token: $ClientAuthToken"
Write-Host "Worker Authentication Token: $WorkerAuthToken"
Write-Host "ScanCentral Controller Shared Secret: $ScanCentralCtrlSecret"
Write-Host
Write-Host "After Enabling ScanCentral SAST/DAST from SSC restart with:"
Write-Host ""
Write-Host "minikube kubectl -- delete pod ssc-webapp-0"
Write-Host ""
Write-Host "================================================================================"
Write-Host ""

