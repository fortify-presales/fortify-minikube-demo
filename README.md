# Fortify minikube demo

This repository contains some example scripts to setup a working Fortify demo environment using [minikube](https://minikube.sigs.k8s.io/docs/)
and the [Fortify Helm Charts](https://github.com/fortify/helm3-charts). 

Minikube is a tool that allows you to run a single-node Kubernetes cluster locally. 
It is useful for developing and testing applications that are designed to run on Kubernetes.

It includes a deployment of:
 [ ] Fortify License Infrastructure Manger (LIM)
 [ ] Fortify Software Security Center (SSC)
 [ ] ScanCentral SAST
 [ ] ScanCentral DAST

## Prerequisites

### Linux environment with Docker installed

See [here](https://gist.github.com/wholroyd/748e09ca0b78897750791172b2abb051) as an example for Ubuntu on WSL2.

### PowerShell on Linux

Install [PowerShell for Linux](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux?view=powershell-7.4).

### Minikube

Install **minikube**: https://minikube.sigs.k8s.io/docs/start

### Kubernetes command line

Install **kubectl**: https://kubernetes.io/docs/tasks/tools/

### Helm

Install **helm**: https://helm.sh/docs/intro/install/

### OpenSSL

You will need OpenSSL (https://www.openssl.org/) to create a self-signed wildcard certificate. You can install OpenSSL 
using the OS package manager or use the version that is already available with the Git command line tool.

### fortify.license file

A working **fortify.license** file for SSC and ScanCentral SAST.
Place this file in the "root" directory of the project.

### Dockerhub ***fortifydocker*** credentials

You will need Docker Hub credentials to access the private docker images in the [fortifydocker](https://hub.docker.com/u/fortifydocker) organisation.

### SSC Helm Charts

You will need the Helm charts from the Fortify SSC Server installation, this will be in the form of a `.tgz` file named
`ssc-1.1.2420186+24.2.0.0186.tgz` or simlar. Extract the contents of this file in the root directory:

```
tar -xvzf ssc-1.1.2420186+24.2.0.0186.tgz
```

### ScanCentral DAST and WebInspect licenses

A working license for ScanCentral DAST and WebInspect if deploying ScanCentral DAST 

## Environment preparation

Copy the file `env.example` to `.env`, e.g.

```
cp env-example .env
```

then edit the file as required. You can set the first few entries depending on which components
you wish to install. For example to install everything except ScanCentral DAST:

```
# Set the following depending on what components you wish to install
# Just leave blank/empty if you don't want to install the component
INSTALL_LIM=1
INSTALL_SSC=1
INSTALL_SCSAST=1
INSTALL_SCSAST_SCANNER=1
INSTALL_SCDAST=
INSTALL_SCDAST_SCANNER=
```

The values at the bottom of the file, for URLs and credentials of the deployed environment
will be updated as the deployment completes.

**Note: Do not place this file in source control.**


## Install environment

Run the following command to start minikube and create a Fortify ScanCentral SAST Environment:

```aidl
pwsh ./startup.ps1
```

It will take a while for everything to complete. 

Once the details of the environment are complete at the end you will need to login to Fortify
SSC and enter the details of ScanCentral SAST/DAST as per the instructions.

If you want to populate the Fortify environment with sample data, you can the following command:

```aidl
pwsh ./scripts/populate.ps1
```

Note: if you need to set/reset the Fortify SSC "admin" user's password you can run the following commands:

```aidl
kubectl exec --stdin --tty mysql-0 -- /bin/bash
mysql -u root -p 
[Enter password]
use ssc_db; 
update fortifyuser set requirePasswordChange='N';
exit
exit
```

## Installing Licenses in LIM

Run the following command to forward the LIM Service to a free port on your local machine, e.g. for port 8888:

```
kubectl port-forward svc/lim 8888:37562
```

Browse to https://127.0.0.1:8888 on your local machine and login using the values of `LIM_ADMIN_USER` and
`LIM_ADMIN_PASSWORD` set in `.env`.

Install your licenses and then you can stop the port forwarding (just Ctrl^C out).

## Login to SSC

Run the following command to forward the SSC Service to a free port on your local machine, e.g. for port 8443:

```
kubectl port-forward svc/ssc-service 8443:443
```

Browse to https://127.0.0.1:8443 on your local machine and login using the values of `SSC_ADMIN_USER` and
`SSCADMIN_PASSWORD` set in `.env`. You will need to change the user's password on first login.

### Configuring ScanCentral SAST/DAST in SSC

To configurate ScanCentral SAST in SSC, first run the following command to forward the ScanCentral SAST Controller API
to a free port on your local machine:

```
kubectl port-forward svc/scancentral-sast 8081:8080
````

Then in Administration -> Configuration "Enable ScanCentral SAST" and set Controller URL to: `https://127.0.0.1:8081/scancentral-ctrl`.


To configure ScanCentral DAST in SSC, first run the following command to forward the ScanCentral DAST API
to a free port on your local machine:

```
kubectl port-forward svc/scancentral-dast-core-api 1444:34785
````

Then in Administration -> Configuration "Enable ScanCentral DAST" and set Server URL to: `https://127.0.0.1:1444`.

## Update environment

You can re-run the `startup.ps1` script with different options set in the `.env` to deploy more components.

## Stopping/Starting Minikube

You can stop minikube using:

```
minikube stop
```

this will keep the kubernetes cluster so that even after reboot of your machine you can restart the cluster with:

```
minikube start
```

## Remove environment

If you wish to remove the minikube environment completely, you can use the following command:

```aidl
pwsh ./shutdown.ps1
```
