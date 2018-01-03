# Project Calico On-Premise Windows Deployment #
This guide will walk you through deploying Project Calico in policy-only mode on a Linux/Windows mixed-OS Kubernetes cluster without a cloud provider.

## Assumptions and Prerequisites ##
It is assumed that you have followed the [Kubernetes on Windows](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows) guide and that you have a Kubernetes Linux master and a Windows worker node deployed.

**Note**: The guide will assume a local working directory of `~/kube` for the Linux master setup and a local working directory of `c:\k` for the Windows worker node. If you choose different directories for your Kubernetes deployment, just replace any references to that path as you follow this guide.

## Deploy Project Calico on the Linux master ##
On the Linux master node, we will generate a new manifest file for Calico and we will then use that manifest to install Calico in policy-only mode.

### Copy supporting scripts
Use the following steps on your Linux master to copy down the supporting scripts which we will be using to install Calico:

```bash
$ mkdir ~/kube/calico
$ cd ~/kube/calico
$ <insert steps to get the Setup/Linux/generate.py copied locally>
```

### Prepare the Calico Manifest
Execute the supporting python script, passing your *full* cluster CIDR. Please note that 192.168.0.0/16 may need to be changed to match the cluster CIDR you selected when deploying your Kubernetes cluster:

```bash
$ python2 generate.py 192.168.0.0/16
```

This will generate a new manifest file in the same directory named *calico.yaml*

### Install Calico
The following command will use kubectl to install Calico using the manifest file which we generated in the previous step:

```bash
$ ~/kube/bin/kubectl apply -f ~/kube/calico/calico.yaml
```

After a few seconds, you should a new pod with a name similar to "calico-node-xxxx" being created on your Linux master (under the kube-system namespace). 

You can use the following command to check the status of this pod:

```bash
$ ~/kube/bin/kubectl get pods --all-namespaces
NAMESPACE     NAME                                   READY     STATUS    RESTARTS   AGE
kube-system   calico-node-92fn2                      2/2       Running   0          52s
```

Please wait for this pod to have a STATUS="Running" before continuing to the next step of this guide. It should not take longer than a minute for this pod to enter the Running state.

## Deploy Project Calico on the Windows worker node

On the Windows node, we will copy some supporting files locally and then launch the Calico Felix hostagent.

### Copy supporting files
Use the following steps on your Windows node to copy down the supporting scripts which we will be using to run Calico:

```bash
PS> <insert steps to copy down Setup/Windows/Start-Calico.ps1 and Calico-Felix.exe to the local C:\k directory>
```

### Run Calico Felix

In a Powershell window, simply run:

```bash
PS> cd c:\k
PS> .\start-calico.ps1
```

The Calico Felix hostagent process should now be started. You will see logging output to the Powershell window and there will also be a log file generated at *C:\var\log\calico\felix.log* 

## Create a Network Policy

For testing purposes, let's apply an example network policy to our deployment.

### Create a default deny policy

On your Linux master node, you can execute the following to create a 'default deny' network policy. Once created, this policy will block all inbound and outbound traffic from all pods running in the default namespace.

```bash
$ ~/kube/bin/kubectl create --validate=false -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector:
  policyTypes:
  - Ingress
  - Egress
EOF
```

*TODO: Ask Calico why --validate=false is required for the default deny policy in 1.8*

You can see your network policies using the following command:

```bash
$ ~/kube/bin/kubectl -n default get netpol
NAME           POD-SELECTOR   AGE
default-deny   <none>         3s
```

Optionally, if you want to remove this policy (to allow all of your pods in the default namespace to accept inbound/outbound traffic again) then you can execute the following command:

```bash
$ ~/kube/bin/kubectl -n default delete netpol default-deny
```
