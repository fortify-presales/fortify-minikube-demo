& minikube stop

& minikube delete

$CertDir = "$($PSScriptRoot)\certificates"
If ((Test-Path -PathType container $CertDir))
{
    Remove-Item -LiteralPath $CertDir -Force -Recurse
}

$SSCSecretDir = "$($PSScriptRoot)\ssc-secret"
If ((Test-Path -PathType container $SSCSecretDir))
{
    Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
}

$FcliDir = "$($PSScriptRoot)\fcli"
If ((Test-Path -PathType container $FcliDir))
{
    Get-ChildItem -Path $FcliDir -Exclude 'fcli.*' | Remove-Item -Recurse -Force
}

$Env:PATH = "$($PSScriptRoot)\fcli;$Env:PATH"

function jfcli { java -jar .\fcli\fcli.jar $args }

jfcli tool scancentral-client uninstall latest -y
