# Example script to start minikube and install Fortify LIM, SSC and ScanCentral SAST/DAST

# Parameters
param (
    [Parameter(Mandatory=$false)]
    [switch]$RecreateCertificates
)

Write-Host "Fortify minikube startup script"

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

# Import local environment specific settings
$EnvSettings = $(ConvertFrom-StringData -StringData (Get-Content (Join-Path "." -ChildPath ".env") | Where-Object {-not ($_.StartsWith('#'))} | Out-String))
$EnvFile = Join-Path $PSScriptRoot -ChildPath ".env"

$InstallLIM = $EnvSettings['INSTALL_LIM']
$InstallSSC = $EnvSettings['INSTALL_SSC']
$InstallSCSAST = $EnvSettings['INSTALL_SCSAST']
$InstallSCDAST = $EnvSettings['INSTALL_SCDAST']
$MINIKUBE_MEM = $EnvSettings['MINIKUBE_MEM']
$MINIKUBE_CPUS = $EnvSettings['MINIKUBE_CPUS']
$SIGNING_PASSWORD = $EnvSettings['SIGNING_PASSWORD']
$SSC_ADMIN_USER = $EnvSettings['SSC_ADMIN_USER']
$SSC_ADMIN_PASSWORD = $EnvSettings['SSC_ADMIN_PASSWORD']
$DOCKERHUB_USERNAME = $EnvSettings['DOCKERHUB_USERNAME']
$DOCKERHUB_PASSWORD = $EnvSettings['DOCKERHUB_PASSWORD']
$OPENSSL = $EnvSettings['OPENSSL_PATH']
$SCANCENTRAL_VERSION = $EnvSettings['SCANCENTRAL_VERSION']
$LIM_HELM_VERSION = $EnvSettings['LIM_HELM_VERSION']
$SSC_HELM_VERSION = $EnvSettings['SSC_HELM_VERSION']
$SCSAST_HELM_VERSION = $EnvSettings['SCSAST_HELM_VERSION']
$SCDAST_HELM_VERSION = $EnvSettings['SCDAST_HELM_VERSION']
$MYSQL_HELM_VERSION = $EnvSettings['MYSQL_HELM_VERSION']
$POSTGRES_HELM_VERSION = $EnvSettings['POSTGRES_HELM_VERSION']
$SCDAST_UPGRADE_REPO = $EnvSettings['SCDAST_UPGRADE_REPO']
$SCDAST_UPGRADE_REPO_VER = $EnvSettings['SCDAST_UPGRADE_REPO_VER']
$LIM_API_URL = $EnvSettings['LIM_API_URL']
$LIM_ADMIN_USER = $EnvSettings['LIM_ADMIN_USER']
$LIM_ADMIN_PASSWORD = $EnvSettings['LIM_ADMIN_PASSWORD']
$LIM_POOL_NAME = $EnvSettings['LIM_POOL_NAME']
$LIM_POOL_PASSWORD = $EnvSettings['LIM_POOL_PASSWORD']

# Set some defaults in case they are missing from .env file
if ([string]::IsNullOrEmpty($MINIKUBE_MEM)) { $MINIKUBE_MEM = "8192" }
if ([string]::IsNullOrEmpty($MINIKUBE_CPUS)) { $MINIKUBE_CPUS = "2" }
if ([string]::IsNullOrEmpty($SIGNING_PASSWORD)) {  throw "SIGNING_PASSWORD needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SSC_ADMIN_USER)) { $SSC_ADMIN_USER = "admin" }
if ([string]::IsNullOrEmpty($SSC_ADMIN_PASSWORD)) { $SSC_ADMIN_PASSWORD = "admin" }
if ([string]::IsNullOrEmpty($DOCKERHUB_USERNAME)) { throw "DOCKER_USERNAME needs to be set in .env file" }
if ([string]::IsNullOrEmpty($DOCKERHUB_PASSWORD)) { throw "DOCKER_PASSWORD needs to be set in .env file" }
if ([string]::IsNullOrEmpty($SCANCENTRAL_VERSION)) { $SCANCENTRAL_VERSION = "22.2.0" }
if ([string]::IsNullOrEmpty($LIM_HELM_VERSION)) { $LIM_HELM_VERSION = "24.2.0-2" }
if ([string]::IsNullOrEmpty($SSC_HELM_VERSION)) { $SSC_HELM_VERSION = "1.1.2420186+24.2.0.0186" }
if ([string]::IsNullOrEmpty($SCSAST_HELM_VERSION)) { $SCSAST_HELM_VERSION = "22.2.0" }
if ([string]::IsNullOrEmpty($SCDAST_HELM_VERSION)) { $SCDAST_HELM_VERSION = "22.2.1" }
if ([string]::IsNullOrEmpty($MYSQL_HELM_VERSION)) { $MYSQL_HELM_VERSION = "9.3.1" }
if ([string]::IsNullOrEmpty($POSTGRES_HELM_VERSION)) { $POSTGRES_HELM_VERSION = "11.9.0" }
if ([string]::IsNullOrEmpty($OPENSSL)) { $OPENSSL = "openssl" }
if ($InstallLIM)
{
    # we will set LIM_API_URL on completion
    #if ([string]::IsNullOrEmpty($LIM_API_URL)) { throw "LIM_API_URL needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_USER)) { throw "LIM_ADMIN_USER needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_PASSWORD)) { throw "LIM_ADMIN_PASSWORD needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_POOL_NAME)) { throw "LIM_POOL_NAME needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_POOL_PASSWORD)) { throw "LIM_POOL_PASSWORD needs to be set in .env file" }
}
if ($InstallSSC)
{
    # any other required SSC settings
}
if ($InstallSCSAST)
{
    # any other required SCSAST settings
}
if ($InstallSCDAST)
{
    #if ([string]::IsNullOrEmpty($LIM_API_URL)) { throw "LIM_API_URL needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_USER)) { throw "LIM_ADMIN_USER needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_PASSWORD)) { throw "LIM_ADMIN_PASSWORD needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_POOL_NAME)) { throw "LIM_POOL_NAME needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($LIM_POOL_PASSWORD)) { throw "LIM_POOL_PASSWORD needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($SCDAST_UPGRADE_REPO)) { throw "SCDAST_UPGRADE_REPO needs to be set in .env file" }
    if ([string]::IsNullOrEmpty($SCDAST_UPGRADE_REPO_VER)) { throw "SCDAST_UPGRADE_REPO_VER needs to be set in .env file" }
}
if ($IsLinux)
{
    $MinikubeDriver = "docker"
    $UseStaticIP="--static-ip=192.168.200.200"
}
else
{
    $MinikubeDriver = "hyperv"
    $UseStaticIP = ""
}

# Setup Java Environment and Tools
Set-JavaTools

# check if minikube is running
$MinikubeStatus = (minikube status --format='{{.Host}}')
if ($MinikubeStatus -eq "Running")
{
    Write-Host "minikube is running ..."
}
else
{
    Write-Host "minikube not running ... starting ..."
    & minikube start --memory $MINIKUBE_MEM --cpus $MINIKUBE_CPUS --driver=$MinikubeDriver $UseStaticIP
    Start-Sleep -Seconds 5
    & minikube addons enable ingress
    & minikube addons enable metrics-server
    #& minikube addons enable yakd
    Write-Host "minikube is running ..."
}

$MinikubeIP = (minikube ip)
$LIMUrl = "lim.$($MinikubeIP.Replace('.','-')).nip.io"
$SSCUrl = "ssc.$($MinikubeIP.Replace('.','-')).nip.io"
$SCSASTUrl = "scsast.$($MinikubeIP.Replace('.','-')).nip.io"
$SCDASTAPIUrl = "scdastapi.$($MinikubeIP.Replace('.','-')).nip.io"
$CertUrl = "/CN=*.$($MinikubeIP.Replace('.','-')).nip.io"

& helm repo add bitnami https://charts.bitnami.com/bitnami 2>$null

kubectl delete secret docker-registry fortifydocker --ignore-not-found
kubectl create secret docker-registry fortifydocker --docker-username $DOCKERHUB_USERNAME --docker-password $DOCKERHUB_PASSWORD

$CertDir = Join-Path $PSScriptRoot -ChildPath "certificates"
if ($RecreateCertificates)
{
    Write-Host "Deleting existing certificates ..."
    if ((Test-Path -PathType container $CertDir))
    {
        Remove-Item -LiteralPath $CertDir -Force -Recurse
    }
}

if ((Test-Path -PathType container $CertDir))
{
    Write-Host "Certificates already exist, not creating ..."
}
else
{
    Write-Host "Creating certificates ..."

    New-Item -ItemType Directory -Path $CertDir

    Set-Location $CertDir

    & "$OPENSSL" req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem -subj $CertUrl
    & "$OPENSSL" x509 -inform PEM -in certificate.pem -outform DER -out certificate.cer
    & "$OPENSSL" pkcs12 -export -name ssc -in certificate.pem -inkey key.pem -out keystore.p12 -password pass:changeit
    & "$OPENSSL" pkcs12 -export -name lim -in certificate.pem -inkey key.pem -out certificate.pfx -password pass:changeit

    kubectl create secret tls wildcard-certificate --cert=certificate.pem --key=key.pem

    & "$KeytoolExe" -importkeystore -destkeystore ssc-service.jks -srckeystore keystore.p12 -srcstoretype pkcs12 -alias ssc -srcstorepass changeit -deststorepass changeit
    & "$KeytoolExe" -import -trustcacerts -file certificate.pem -alias "wildcard-cert" -keystore truststore -storepass changeit -noprompt

    $SRCKEYSTORE = Join-Path $PSScriptRoot -ChildPath "certificates" | Join-Path -ChildPath "keystore.p12"
    $DESTKEYSTORE = Join-Path $JavaHome -ChildPath "lib" | Join-Path -ChildPath "security" | Join-Path -ChildPath "cacerts"
    & "$KeytoolExe" -importkeystore -alias ssc -srckeystore $SRCKEYSTORE -srcstoretype pkcs12 -destkeystore $DESTKEYSTORE -srcstorepass changeit -deststorepass changeit -noprompt

    $CERFILE = Join-Path $PSScriptRoot -ChildPath "certificates" | Join-Path -ChildPath "certificate.cer"
    & "$KeytoolExe" -import -alias scancentral -keystore $DESTKEYSTORE -file $CERFILE -trustcacerts -keypass changeit -deststorepass changeit
    Set-Location $PSScriptRoot
}

# run update to prevent spurious errors
helm repo update

#
# License Infrastructure Manager (LIM)
#

if ($InstallLIM)
{
    # check if LIM is already running
    $LIMStatus = Get-PodStatus -PodName lim-0
    if ($LIMStatus -eq "Running")
    {
        Write-Host "LIM is already running ..."
    }
    else
    {

        $CertPem = Join-Path $CertDir -ChildPath "certificate.pem"
        $CertKey = Join-Path $CertDir -ChildPath "key.pem"
        $CertPfx = Join-Path $CertDir -ChildPath "certificate.pfx"
        $LimPv = Join-Path $PSScriptRoot -ChildPath "lim-pv"
        $LimPvc = Join-Path $PSScriptRoot -ChildPath "lim-pvc"

        kubectl delete secret lim-admin-credentials --ignore-not-found
        kubectl create secret generic lim-admin-credentials `
            --type=basic-auth `
            --from-literal=username=$LIM_ADMIN_USER `
            --from-literal=password="$LIM_ADMIN_PASSWORD"

        kubectl delete secret lim-jwt-security-key --ignore-not-found
        kubectl create secret generic lim-jwt-security-key `
            --type=Opaque `
            --from-literal=token="$SIGNING_PASSWORD"
            
        kubectl delete secret lim-server-certificate --ignore-not-found    
        kubectl create secret generic lim-server-certificate `
            --type=TLS `
            --from-file=tls.crt=$CertPem `
            --from-file=tls.key=$CertKey

        kubectl delete secret lim-signing-certificate --ignore-not-found    
        kubectl create secret generic lim-signing-certificate `
            --type=Opaque `
            --from-file=tls.pfx=$CertPfx

        kubectl delete secret lim-signing-certificate-password --ignore-not-found    
        kubectl create secret generic lim-signing-certificate-password `
            --type=Opaque `
            --from-literal=pfx.password=changeit

        kubectl apply --filename=$LimPv
        kubectl apply --filename=$LimPvc

        helm install lim oci://registry-1.docker.io/fortifydocker/helm-lim --version $LIM_HELM_VERSION `
            --set imagePullSecrets[0].name=fortifydocker `
            --set dataPersistence.existingClaim=fortify-lim `
            --set dataPersistence.storeLogs=true `
            --set defaultAdministrator.credentialsSecretName=lim-admin-credentials `
            --set defaultAdministrator.fullName="LIM Administrator" `
            --set defaultAdministrator.email="limadm@ftfydemo.local" `
            --set allowNonTrustedServerCertificate=true `
            --set jwt.securityKeySecretName=lim-jwt-security-key `
            --set serverCertificate.certificateSecretName=lim-server-certificate `
            --set serverCertificate.certificatePasswordSecretName=lim-signing-server-certificate `
            --set signingCertificate.certificateSecretName=lim-signing-certificate `
            --set signingCertificate.certificatePasswordSecretName=lim-signing-certificate-password

        Write-Host
        $LIMStatus = Wait-UntilPodStatus -PodName lim-0

        kubectl create ingress lim-ingress `
            --rule="$($LIMUrl)/*=lim:1433,tls=wildcard-certificate" `
            --annotation nginx.ingress.kubernetes.io/backend-protocol=HTTPS `
            --annotation nginx.ingress.kubernetes.io/proxy-body-size='0' `
            --annotation nginx.ingress.kubernetes.io/client-max-body-size='512M'

        if ($LIMStatus -eq "Running")
        {
            Update-EnvFile -File $EnvFile -Find "^LIM_URL=.*$" -Replace "LIM_URL=https://$($LIMUrl)"
            Update-EnvFile -File $EnvFile -Find "^LIM_API_URL=.*$" -Replace "LIM_API_URL=https://$($LIMUrl)/LIM.API"
        }
    }
}

#
# Software Security Center (SSC)
#

if ($InstallSSC)
{
    # check if SSC is already running
    $SSCStatus = Get-PodStatus -PodName ssc-webapp-0
    if ($SSCStatus -eq "Running")
    {
        Write-Host "SSC is already running ..."
    }
    else
    {
        # check if MySql is already running
        $MySqlStatus = Get-PodStatus -PodName mysql-0
        if ($MysqlStatus -eq "Running")
        {
            Write-Host "MySQL is already running ..."
        }
        else
        {
            Write-Host "Installing MySql ..."
            & helm install mysql bitnami/mysql -f mysql-values.yaml --version $MYSQL_HELM_VERSION
            Start-Sleep -Seconds 30
            Write-Host
            $MySqlStatus = Wait-UntilPodStatus -PodName mysql-0
        }

        Write-Host "Installing SSC ..."

        $SSCSecretDir = Join-Path $PSScriptRoot -ChildPath "ssc-secret"
        If ((Test-Path -PathType container $SSCSecretDir))
        {
            Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
        }
        New-Item -ItemType Directory -Path $SSCSecretDir

        Join-Path $PSScriptRoot -ChildPath "ssc.autoconfig" | Copy-Item -Destination $SSCSecretDir
        Join-Path $PSScriptRoot -ChildPath "fortify.license" | Copy-Item -Destination $SSCSecretDir
        Join-Path $CertDir -ChildPath "ssc-service.jks" |  Copy-Item -Destination $SSCSecretDir
        Join-Path $CertDir -ChildPath "truststore" | Copy-Item -Destination $SSCSecretDir

        Set-Location $SSCSecretDir

        kubectl create secret generic ssc `
            --from-file=. `
            --from-literal=ssc-service.jks.password=changeit `
            --from-literal=ssc-service.jks.key.password=changeit `
            --from-literal=truststore.password=changeit

        Set-Location $PSScriptRoot

        #& helm repo add fortify https://fortify.github.io/helm3-charts

        # tar -xvzftar -xvzf ./ssc-1.1.2420186+24.2.0.0186.tgz
        helm install ssc oci://registry-1.docker.io/fortifydocker/helm-ssc --version 24.4.0-2 `
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

        Write-Host 
        $SSCStatus = Wait-UntilPodStatus -PodName ssc-webapp-0

        kubectl create ingress ssc-ingress `
            --rule="$($SSCUrl)/*=ssc-service:443,tls=wildcard-certificate" `
            --annotation nginx.ingress.kubernetes.io/backend-protocol=HTTPS `
            --annotation nginx.ingress.kubernetes.io/proxy-body-size='0' `
            --annotation nginx.ingress.kubernetes.io/client-max-body-size='512M'

        if ($SSCStatus -eq "Running")
        {
            Update-EnvFile -File $EnvFile -Find "^SSC_URL=.*$" -Replace "SSC_URL=https://$($SSCUrl)"
        }

    }
}    

#
# ScanCentral SAST
#

if ($InstallSCSAST)
{
    $SCSastControllerStatus = Get-PodStatus -PodName scancentral-sast-controller-0
    if ($SCSastControllerStatus -eq "Running")
    {
        Write-Host "ScanCentral SAST is already running ..."
    }
    else
    {
        Write-Host "Installing ScanCentral SAST ..."

        helm install scancentral-sast fortify/scancentral-sast --version $SCSAST_HELM_VERSION `
            --set imagePullSecrets[0].name=fortifydocker `
            --set-file fortifyLicense=fortify.license `
            --set controller.thisUrl="https://$( $SCSASTUrl )/scancentral-ctrl" `
            --set controller.sscUrl="https://$( $SSCUrl )" `
            --set-file trustedCertificates[0]=certificates/certificate.pem `
            --set controller.persistence.enabled=false `
            --set controller.ingress.enabled=true `
            --set controller.ingress.hosts[0].host="$( $SCSASTUrl )" `
            --set controller.ingress.hosts[0].paths[0].path=/ `
            --set controller.ingress.hosts[0].paths[0].pathType=Prefix `
            --set controller.ingress.tls[0].secretName=wildcard-certificate `
            --set controller.ingress.tls[0].hosts[0]=$( $SCSASTUrl ) `
            --set controller.ingress.annotations."nginx\.ingress\.kubernetes\.io/proxy-body-size"="512m"

        Write-Host
        $SCSastControllerStatus = Wait-UntilPodStatus -PodName scancentral-sast-controller-0
        $SCSastWorkerStatus = Wait-UntilPodStatus -PodName scancentral-sast-worker-linux-0

        if ($SCSastControllerStatus -eq "Running")
        {
            $ClientAuthTokenBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-client-auth-token}")
            $ClientAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ClientAuthTokenBase64))
            $WorkerAuthTokenBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-worker-auth-token}")
            $WorkerAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WorkerAuthTokenBase64))
            $ScanCentralCtrlSecretBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-ssc-scancentral-ctrl-secret}")
            $ScanCentralCtrlSecret = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ScanCentralCtrlSecretBase64))

            Update-EnvFile -File $EnvFile -Find "^SCSAST_URL=.*$" -Replace "SCSAST_URL=https://$($SCSASTUrl)/scancentral-ctrl/"
            Update-EnvFile -File $EnvFile -Find "^CLIENT_AUTH_TOKEN=.*$" -Replace "CLIENT_AUTH_TOKEN=$($ClientAuthToken)"
            Update-EnvFile -File $EnvFile -Find "^WORKER_AUTH_TOKEN=.*$" -Replace "WORKER_AUTH_TOKEN=$($WorkerAuthToken)"
            Update-EnvFile -File $EnvFile -Find "^SHARED_SECRET=.*$" -Replace "SHARED_SECRET=$($ScanCentralCtrlSecret)"
        }
    }
}

if ($InstallSCDAST)
{
    $PostgresStatus = Get-PodStatus -PodName postgresql-0
    if ($PostgresStatus -eq "Running")
    {
        Write-Host "Postgres is already running ..."
    }
    else
    {
        Write-Host "Installing Postgres ..."
        & helm install postgresql bitnami/postgresql --version $POSTGRES_HELM_VERSION `
            --set auth.postgresPassword=password `
            --set auth.database=scdast_db
        Start-Sleep -Seconds 30
        $MySqlStatus = Wait-UntilPodStatus -PodName postgresql-0
    }

    Write-Host "Installing ScanCentral DAST ..."

    $CertPem = Join-Path $CertDir -ChildPath "certificate.pem"
        $CertKey = Join-Path $CertDir -ChildPath "key.pem"
        $CertPfx = Join-Path $CertDir -ChildPath "certificate.pfx"

    kubectl delete secret lim-pool --ignore-not-found
    kubectl create secret generic lim-pool `
        --type='basic-auth' `
        --from-literal=username=$LIM_POOL_NAME `
        --from-literal=password="$LIM_POOL_PASSWORD"

    kubectl delete secret scdast-db-owner --ignore-not-found
    kubectl create secret generic scdast-db-owner `
        --type='basic-auth' `
        --from-literal=username=postgres `
        --from-literal=password=password

    kubectl delete secret scdast-db-standard --ignore-not-found
    kubectl create secret generic scdast-db-standard `
        --type='basic-auth' `
        --from-literal=username=postgres `
        --from-literal=password=
        
    kubectl delete secret scdast-service-token --ignore-not-found
    kubectl create secret generic scdast-service-token `
        --type='opaque' `
        --from-literal=service-token="$SIGNING_PASSWORD"

    kubectl delete secret scdast-ssc-serviceaccount --ignore-not-found
    kubectl create secret generic scdast-ssc-serviceaccount `
        --type='basic-auth' `
        --from-literal=username=admin `
        --from-literal=password="FortifyPassword123!"

    kubectl delete secret api-server-certificate --ignore-not-found
    kubectl create secret generic api-server-certificate `
        --type=Opaque `
        --from-file=tls.pfx=$CertPfx

    kubectl delete secret api-server-certificate-password --ignore-not-found    
    kubectl create secret generic api-server-certificate-password `
        --type=Opaque `
        --from-literal=password=changeit

    kubectl delete secret utilityservice-server-certificate --ignore-not-found        
    kubectl create secret generic utilityservice-server-certificate `
        --type=Opaque `
        --from-file=tls.pfx=$CertPfx

    kubectl delete secret utilityservice-server-certificate-password --ignore-not-found        
    kubectl create secret generic utilityservice-server-certificate-password `
        --type=Opaque `
        --from-literal=password=changeit
    
    #helm pull oci://registry-1.docker.io/fortifydocker/helm-scancentral-dast-core --version $SCDAST_HELM_VERSION
    #tar -xvzfhelm-scancentral-dast-core-$($SCDAST_HELM_VERSION).tgz
    helm install scancentral-dast-core oci://registry-1.docker.io/fortifydocker/helm-scancentral-dast-core --version $SCDAST_HELM_VERSION --timeout 60m `
        --set imagePullSecrets[0].name=fortifydocker `
        --set appsettings.lIMSettings.limUrl="https://lim.default.svc.cluster.local:37562" `
        --set appsettings.sSCSettings.sSCRootUrl="https://ssc-service.default.svc.cluster.local:443" `
        --set appsettings.dASTApiSettings.disableCorsOrigins=true `
        --set appsettings.environmentSettings.allowNonTrustedServerCertificate=true `
        --set appsettings.databaseSettings.databaseProvider=PostgreSQL `
        --set appsettings.databaseSettings.server=postgresql `
        --set database.dboLevelAccountCredentialsSecret=scdast-db-owner `
        --set database.standardAccountCredentialsSecret=scdast-db-standard `
        --set sscServiceAccountSecretName=scdast-ssc-serviceaccount `
        --set serviceTokenSecretName=scdast-service-token `
        --set limServiceAccountSecretName=lim-admin-credentials `
        --set limDefaultPoolSecretName=lim-pool `
        --set api.certificate.certificateSecretName=api-server-certificate `
        --set api.certificate.certificateSecretName=api-server-certificate-password `
        --set utilityService.certificate.certificateSecretName=api-server-certificate `
        --set utilityService.certificate.certificateSecretName=api-server-certificate-password

    #& helm install scancentral-dast fortify/scancentral-dast --version $SCDAST_HELM_VERSION --timeout 40m `
    #    --set imagePullSecrets[0].name=fortifydocker `
    #    --set images.upgradeJob.repository="$( $SCDAST_UPGRADE_REPO )" `
    #    --set images.upgradeJob.tag="$( $SCDAST_UPGRADE_REPO_VER )" `
    #    --set configuration.databaseSettings.databaseProvider=PostgreSQL `
    #    --set configuration.databaseSettings.server=postgresql `
    #    --set configuration.databaseSettings.database=scdast_db `
    #    --set configuration.databaseSettings.dboLevelDatabaseAccount.username=postgres `
    #    --set configuration.databaseSettings.dboLevelDatabaseAccount.password=password `
    #    --set configuration.databaseSettings.standardDatabaseAccount.username=postgres `
    #    --set configuration.databaseSettings.standardDatabaseAccount.password=password `
    #    --set configuration.serviceToken=thisisaservicetoken `
    #    --set configuration.sSCSettings.sSCRootUrl="https://$( $SSCUrl )" `
    #    --set configuration.sSCSettings.serviceAccountUserName="$( $SSC_ADMIN_USER )" `
    #    --set configuration.sSCSettings.serviceAccountPassword="$( $SSC_ADMIN_PASSWORD )" `
    #    --set configuration.dASTApiSettings.corsOrigins[0]="https://$( $SSCUrl )" `
    #    --set configuration.dASTApiSettings.corsOrigins[1]="https://$( $SCDASTAPIUrl )" `
    #    --set configuration.lIMSettings.limUrl="$( $LIM_API_URL )" `
    #    --set configuration.lIMSettings.serviceAccountUserName="$( $LIM_ADMIN_USER )" `
    #    --set configuration.lIMSettings.serviceAccountPassword="$( $LIM_ADMIN_PASSWORD )" `
    #    --set configuration.lIMSettings.defaultLimPoolName="$( $LIM_POOL_NAME )" `
    #    --set configuration.lIMSettings.defaultLimPoolPassword="$( $LIM_POOL_PASSWORD )" `
    #    --set configuration.lIMSettings.useLimRestApi=true `
    #    --set ingress.api.enabled=true `
    #    --set ingress.api.hosts[0].host="$( $SCDASTAPIUrl )" `
    #    --set ingress.api.hosts[0].paths[0].path=/ `
    #    --set ingress.api.hosts[0].paths[0].pathType=Prefix `
    #    --set ingress.api.tls[0].secretName=wildcard-certificate `
    #    --set ingress.api.tls[0].hosts[0]="$( $SCDASTAPIUrl )"

        Write-Host
        $SCDastControllerStatus = Wait-UntilPodStatus -PodName scancentral-dast-controller-0
        $SCDastSensorStatus = Wait-UntilPodStatus -PodName scancentral-dast-sensor-linux-0

        if ($SCDastControllerStatus -eq "Running")
        {
            Update-EnvFile -File $EnvFile -Find "^SCDAST_URL=.*$" -Replace "SCDAST_URL=https://$($SCDASTAPIUrl)"
        }
}

Write-Host @"
================================================================================

Please check the ".env" file for URLs of LIM, SSC etc

Note: after Enabling ScanCentral SAST/DAST from SSC restart SSC pod with:

kubectl delete pod ssc-webapp-0

kubectl port-forward svc/lim 8080:37562

================================================================================
"@

