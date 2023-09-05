# Fortify minikube demo (Windows)

This repository contains some example scripts to setup a working Fortify ScanCentral SAST/DAST
demo environment using the [Fortify Helm Charts](https://github.com/fortify/helm3-charts) on Windows. 
It includes a deployment of Fortify Software Security Center (SSC) and Fortify ScanCentral SAST/DAST created using 
[minikube](https://minikube.sigs.k8s.io/docs/). 

Minikube is a tool that allows you to run a single-node Kubernetes cluster locally. It is useful for developing and testing applications that are designed to run on Kubernetes.

## Prerequisites

### Hyper-V

Install **Hyper-V**: https://minikube.sigs.k8s.io/docs/drivers/hyperv/

### Minikube

Install **minikube**: https://minikube.sigs.k8s.io/docs/start/

### Helm

Install **helm**: https://helm.sh/docs/intro/quickstart/

### OpenSSL

You will need OpenSSL (https://www.openssl.org/) to create a self-signed wildcard certificate. You can install OpenSSL 
using the OS package manager or use the version that is already available with the Git command line tool..

### fortify.license file

A working **fortify.license** file for SSC and ScanCentral SAST.
Place this file in the "root" directory of the project.

### Dockerhub ***fortifydocker*** credentials

You will need Docker Hub credentials to access the private docker images in the [fortifydocker](https://hub.docker.com/u/fortifydocker) organisation.

### License and Infrastructure Manager and ScanCentral DAST and WebInspect licenses

ScanCentral DAST requires a working LIM instance with a license pool for WebInspect scanners. Unfortunately, LIM does not currently support Linux, so you cannot install it as part of this deployment.
Follow standard procedures to install and configure LIM on a Windows machine or using Windows containers. **LIM must be accessed in API mode. Using the URL for LIM service will not work.**

### ScanCentral DAST Configuration tool with SecureBase container image

ScanCentral DAST uses a configuration tool to initialize the database. 
The configuration tool image that is hosted at Docker Hub does not include the SecureBase and does not work to initialize/migrate the database.
ScanCentral DAST can be initialized, upgraded or configured automatically if `autoDeploy`: is `true` at **values.yaml**.
By default, the helm chart uses **fortifydocker/scancentral-dast-config** image to run the autoDeploy job.
This docker image does not include the file **DefaultData.zip** which contains the data to seed a new database or to upgrade
from previous versions. As it lacks this file, autoDeploy will not be able to initialize or upgrade the database.

- In GitHub create a Personal Access Token with access to GitHub Container Registry
- On a machine with docker support, sign in to Fortify Customer Portal and download **ScanCentral_DAST_X.X.zip**
- Extract the file **scancentral-dast-config-sb.tar** from within the Zip file **ScanCentral DAST - CLI Config Tool.zip** which itself is in **ScanCentral_DAST_X.X.zip**
- On a command prompt, run the following commands:

```
export CR_PAT=<YOUR_PAT>
docker load -i <PATH_TO_DIRECTORY>/scancentral-dast-config-linux.tar
echo $CR_PAT | docker login ghcr.io -u <USERNAME> --password-stdin
docker tag dast_configsb_redhat_linux:23.1.180.ubi8.0 ghcr.io/<DOCKER_REPO>/dast_configsb_redhat_linux:<IMAGE_VERSION>
docker push ghcr.io/<DOCKER_REPO>/dast_configsb_redhat_linux:<IMAGE_VERSION>
```

where:
- **<DOCKER_USERNAME>** is your GitHub username
- **<DOCKER_PAT>** is your GitHub Personal Access token
- **<PATH_TO_DIRECTORY>** is the directory where you extracted the tar file
- **<DOCKER_REPO>** is your docker registry/repo in GitHub
- **<IMAGE_VERSION>** is the version of the docker image you are using

Change the image reference for the **upgradeJob** at `values.yaml`.

```
upgradeJob:
repository: <DOCKER_REPO>/scancentral-dast-config-sb
tag: "<IMAGE_VERSION>"
pullPolicy: "IfNotPresent"
```

## Environment preparation

Create a `.env` file with settings that you wish to you, an example file is given below:

```aidl
# Default SSC Admin User
SSC_ADMIN_USER=admin
SSC_ADMIN_PASSWORD=admin
# DockerHub login credentials to fortifydocker organisation
DOCKERHUB_USERNAME=_YOUR_DOCKERHUB_LOGIN_
DOCKERHUB_PASSWORD=_YOUR_DOCKERHUB_PASSWORD_
# Path to openssl - use OpenSSL from Git on Windows
OPENSSL_PATH=C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe
# Path to openssl on Linux
#OPENSSL_PATH=/usr/bin/openssl
# Version on ScanCentral to use
SCANCENTRAL_VERSION=23.1
# Fortify Demo App to create
SSC_APP_NAME=FortifyDemoApp
SSC_APP_VER_NAME=1.0
# LIM configuration
LIM_API_URL=http://_YOUR_LIM_SERVER_/LIM.API
LIM_ADMIN_USER=admin
LIM_ADMIN_PASSWORD=_YOUR_LIM_ADMIN_PASSWORD_
LIM_POOL_NAME=Default
LIM_POOL_PASSWORD=_YOUR_LIM_POOL_PASSWORD_
# ScanCentral DAST Upgrade repo
SCDAST_UPGRADE_REPO=_YOUR_UPGRADE_REPO_
SCDAST_UPGRADE_REPO_VER=23.1.180.ubi8.0
# Version of Helm charts to ise
SSC_HELM_VERSION=1.1.2310148
SCSAST_HELM_VERSION=23.1.0
SCDAST_HELM_VERSION=23.1.0
MYSQL_HELM_VERSION=9.3.1
POSTGRES_HELM_VERSION=11.9.0
# The following values will be replaced by scripts
SSC_URL=
SCSAST_URL=
SCDAST_URL=
CLIENT_AUTH_TOKEN=
WORKER_AUTH_TOKEN=
SHARED_SECRET=
SSC_CI_TOKEN=
```
Note: Do not place this file in source control.

## Install environment

Run the following command to start minikube and create a Fortify ScanCentral SAST Environment:

```aidl
.\scripts\startup.ps1 -Components SCSAST
```

It will take a while for everything to complete. You can specify the Fortify "components"
to install with the `-Components` option, e.g. `SCSAST` or `SCDAST`.

Once the details of the environment are complete at the end you will need to login to Fortify
SSC and enter the details of ScanCentral SAST/DAST as per the instructions.

If you want to populate the Fortify environment with sample data, you can the following command:

```aidl
.\scripts\populate.ps1
```

Note: if you need to set/reset the Fortify SSC "admin" user's password you can use the following script:

```aidl
.\scripts\reset_ssc_admin_user.ps1
```

## Remove environment

If you wish to remove the minikube environment completely, you can use the following command:

```aidl
.\scripts\shutdown.ps1
```
