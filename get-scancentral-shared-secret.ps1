function kubectl { minikube kubectl -- $args }
$ScanCentralCtrlSecretBase64 = (kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-ssc-scancentral-ctrl-secret}")
$ScanCentralCtrlSecret = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ScanCentralCtrlSecretBase64))
$ScanCentralCtrlSecret
