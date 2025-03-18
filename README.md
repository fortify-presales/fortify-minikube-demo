# Fortify minikube demo

This repository contains some example scripts to setup a working Fortify demo environment using [minikube](https://minikube.sigs.k8s.io/docs/)
and the [Fortify Helm Charts](https://github.com/fortify/helm3-charts). 

Minikube is a tool that allows you to run a single-node Kubernetes cluster locally. 
It is useful for developing and testing applications that are designed to run on Kubernetes.

It includes a deployment of:

    [X] Fortify License Infrastructure Manger (LIM)
    [X] Fortify Software Security Center (SSC)
    [X] ScanCentral SAST and Linux Scanner/Sensor
    [X] ScanCentral DAST and Linux Scanner/Sensor

## Prerequisites

### Linux environment with Docker installed

See [here](https://gist.github.com/wholroyd/748e09ca0b78897750791172b2abb051) as an example for Ubuntu on WSL2.

### PowerShell on Linux

Install [PowerShell for Linux](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux?view=powershell-7.4).
The scripts are written in PowerShell so that they could be used on both Windows and Linux.

### Kubernetes command line

Install **kubectl** by following: https://kubernetes.io/docs/tasks/tools/

### Helm

Install **helm** by following: https://helm.sh/docs/intro/install/

### Minikube

Install **minikube** by following : https://minikube.sigs.k8s.io/docs/start

### OpenSSL

You will need OpenSSL (https://www.openssl.org/) to create a self-signed wildcard certificate. You can install OpenSSL 
using your OS package manager or use the version that is already available with the Git command line tool. If using Linux there is a good chance that OpenSSL is already installed.

### fortify.license file

A working **fortify.license** file will be need for SSC and ScanCentral SAST.
Place this file in the "root" directory of this project.

### Dockerhub ***fortifydocker*** credentials

You will need Docker Hub credentials to access the Helm charts and private docker images in the [fortifydocker](https://hub.docker.com/u/fortifydocker) organisation.
Enter the username and password into the `.env` file (see below).

### ScanCentral DAST and WebInspect licenses

A working license for ScanCentral DAST and WebInspect will be needed if deploying ScanCentral DAST.

### Fortify Command Line utility

The `fcli` tool can be used to populate data and connect to the Fortify minikube Environment.

## Environment preparation

If you wish for Minikube to use a different drive or location than its default, you should set the MINIKUBE_HOME
environment variable, for example:

``
# Unix
export MINIKUBE_HOME=/otherdrive/.minikube
# Windows
$env:MINIKUBE_HOME = "D:\.minikube"
``
Both of these entries are at the top in the `startup.ps1` script and you can uncomment out the relevant if required.

Copy the file `env.example` to `.env`, e.g.

```
cp env-example .env
```

then edit the file as required. Set the first few entries/flags depending on which components
you wish to install. For example to install everything except ScanCentral DAST:

```
# Set the following depending on what components you wish to install
# Just leave blank/empty if you don't want to install the component
INSTALL_LIM=1
INSTALL_SSC=1
INSTALL_SCSAST=1
INSTALL_SCDAST=
INSTALL_SCDAST_SCANNER=
```

It is recommended to set the components incrementally so you can see what's going on and make sure things are working. For example: set just `INSTALL_LIM=1` first to install LIM and configure licenses then add `INSTALL_SSC=1` and so on. 

Note: a ScanCentral DAST activation token needs to be installed in the LIM for the SecureBase database to be installed successfully.

To save time, the startup scripts creates and uses the same certificates across all of the components.
A single signing password is required and should be configured in the `.env` file:

```
SIGNING_PASSWORD=_YOUR_SIGNING_PASSWOD_
```

To generate your own signing password you can use the command `openssl rand -base64 32`.

**Do not place the `.env` file in source control.**

## Install Fortify environment

Run the following command to start minikube and create the Fortify Environment:

```aidl
pwsh 
./startup.ps1
```

It will take a while for everything to complete. If you want to see the progress and ensure everything
is starting correctly you can start the minikube dashboard using:

```aidl
minikube dashboard
```

and browse to the URL it displays. Once the services have started you can expose them to your local
machine using the following command:

```
minikube tunnel
```

You might need to enter your (sudo) password for this to work.

Note: the command prompt running this tunnel will need to be kept open while you are using the Fortify web UI applications.

## Installing Licenses in LIM

Browse to [https://lim.127-0-0-1.nip.io](https://lim.127-0-0-1.nip.io) on your local machine and login using the 
values of `LIM_ADMIN_USER` and `LIM_ADMIN_PASSWORD` set in `.env`.

## Login to SSC

Browse to https://127.0.0.1:8443 on your local machine and login using the values of `SSC_ADMIN_USER` and
`SSCADMIN_PASSWORD` set in `.env`.

Note: if you want to keep the SSC "admin" user's default password of `admin` you can run the following commands to update the MySQL database before logging in:

```aidl
kubectl exec --stdin --tty mysql-0 -- /bin/bash
mysql -u root -p 
[Enter "password"]
use ssc_db; 
update fortifyuser set requirePasswordChange='N';
exit
exit
```

## ScanCentral SAST and DAST Configuration in SSC

For ScanCentral SAST, you should use the "internal" URL for the ScanCentral DAST controller, e.g.
`http://scancentral-sast-controller:80/scancentral-ctrl` and the `SHARED_SECRET` value populated
in the `.env` file. You will need to restart SSC for this configuration to take affect using:

```
kubectl delete pod ssc-webapp-0
```

For ScanCentral DAST, you should use the "external" URL for the ScanCentral DAST API, e.g.
`https://scdastapi.127-0-0-1.nip.io`. You will need to refresh your browser for the ScanCentral
DAST view to appear.

## Populate environment

There is a script `populate.ps1` that can be used to create some initial Applications, Versions and Issues.
It uses the `fcli` tool to connect to the Fortify Environment. If you wish to use the `fcli` tool yourself
you can use the "truststore" that has previously been created, for example:

```
fcli config truststore set -f certificates/ssc-service.jks -p changeit -t jks
fcli ssc session login --url https://ssc.127-0-0-1.nip.io -k -u admin -p admin
...
..._your fcli commands_...
...
fcli ssc session login
```

## Update environment

You can re-run the `startup.ps1` script with different options set in the `.env` file to deploy additional Fortify components.

## Example commands

Here are some additional kubernetes commands to help you:

|                               |      |
|-------------------------------|------|
|Exec into SSC pod              |`kubectl exec --stdin --tty ssc-webapp-0 -- /bin/bash`|
|Restart SSC pod                |`kubectl delete pod ssc-webapp-0`|
|Exec into ScanCentral SAST pod |`kubectl exec --stdin --tty scancentral-sast-controller-0 -- /bin/bash`|
|Restart ScanCentral SAST pod   |`kubectl delete pod scancentral-sast-controller-0`|
|Exec into ScanCentral SAST sensor  | `kubectl exec --stdin --tty scancentral-sast-worker-linux-0 -- /bin/bash`|
|Exec into ScanCentral DAST sensor  | `kubectl exec --stdin --tty scancentral-dast-scanner-0 -- /bin/bash` |
|minikube list containers       | `minikube ssh docker container ls` |
|minikube exec into container (root)| `minikube ssh "docker container exec -it -u 0 <Container ID> /bin/bash"` |

## Stopping/Starting Minikube

You can stop minikube using:

```
minikube stop
```

Note: this will keep the kubernetes cluster so that even after reboot of your machine you can restart the cluster with:

```
minikube start
```

You may need to restart the SSC pod once more after restarting the cluster.

## Remove Fortify environment

If you wish to remove the minikube environment completely, you can use the following command:

```aidl
./shutdown.ps1
```
