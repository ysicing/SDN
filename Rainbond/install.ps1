Param(
    [parameter(Mandatory = $true)] [string] $masterIp,
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16"
)

function DownloadFile(){
    param(
        [parameter(Mandatory = $true)] $Url,
        [parameter(Mandatory = $true)] $Destination
    )

    if (Test-Path $Destination)
    {
        Write-Host "File $Destination already exists."
        return
    }

    try {
        (New-Object System.Net.WebClient).DownloadFile($Url,$Destination)
        Write-Host "Downloaded $Url=>$Destination"
    } catch {
        Write-Host "Failed to download $Url"
            throw
    }
}

function DownloadBinaries {
    Write-Host "Downloading k8s binaries"
    md $BaseDir -ErrorAction Ignore
    DownloadFile -Url https://pkg.rainbond.com/win/calico-felix.exe -Destination $BaseDir\calico-felix.exe
    DownloadFile -Url https://pkg.rainbond.com/win/kubelet.exe -Destination $BaseDir\kubelet.exe
    DownloadFile -Url https://pkg.rainbond.com/win/kubectl.exe -Destination $BaseDir\kubectl.exe
    DownloadFile -Url https://pkg.rainbond.com/win/kube-proxy.exe -Destination $BaseDir\kube-proxy.exe

}

function DownloadWinScripts(){
    Write-Host "Downloading k8s start script"
    DownloadFile -Url https://pkg.rainbond.com/win/start.ps1 -Destination $BaseDir\start.ps1
    DownloadFile -Url https://pkg.rainbond.com/win/stop.ps1 -Destination $BaseDir\stop.ps1
    DownloadFile -Url https://pkg.rainbond.com/win/start-calico.ps1 -Destination $BaseDir\start-calico.ps1
    DownloadFile -Url https://pkg.rainbond.com/win/start-kubelet.ps1 -Destination $BaseDir\start-kubelet.ps1
    DownloadFile -Url https://pkg.rainbond.com/win/start-kube-proxy.ps1 -Destination $BaseDir\start-kube-proxy.ps1


}

function DownloadAllFile(){
    DownloadBinaries
    DownloadWinScripts
}

#Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
#Install-Package -Name docker -ProviderName DockerMsftProvide


$BaseDir = "c:\k"
md $BaseDir -ErrorAction Ignore

DownloadAllFile

start powershell -ArgumentList " -File $BaseDir\start-calico.ps1 "

start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkName $NetworkName"

start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"
