Param(
    $kubeNetwork = "L2Bridge",
    $kubeConfig = ".\config",
    $hostname = $(hostname).ToLower(),
    $logSeverityFile = "INFO",
    $logSeverityScreen = "INFO"
)

# Set environment variables
$env:KUBE_NETWORK = $kubeNetwork
$env:KUBECONFIG = $kubeConfig
$env:CALICO_DATASTORE_TYPE = "kubernetes"
$env:FELIX_CLUSTERTYPE = "k8s"
$env:FELIX_DEBUGDISABLELOGDROPPING = "true"
$env:FELIX_DEFAULTENDPOINTTOHOSTACTION = "ACCEPT"
$env:FELIX_FELIXHOSTNAME = $hostname
$env:FELIX_HEALTHENABLED = "false"
$env:FELIX_IPV6SUPPORT = "false"
$env:FELIX_LOGSEVERITYFILE = $logSeverityFile
$env:FELIX_LOGSEVERITYSCREEN = $logSeverityScreen
$env:FELIX_METADATAADDR = "none"

# Run felix
.\calico-felix.exe
