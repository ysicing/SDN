# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
<#
.SYNOPSIS 
    Deploys and configures the Microsoft SDN infrastructure, 
    including creation of the network controller, Software Load Balancer MUX 
    and gateway VMs.  Then the VMs and Hyper-V hosts are configured to be 
    used by the Network Controller.  When this script completes the SDN 
    infrastructure is ready to be fully used for workload deployments.
.EXAMPLE
    .\SDNExpress.ps1 -ConfigurationDataFile .\MyConfig.psd1
    Reads in the configuration from a PSD1 file that contains a hash table 
    of settings data.
.EXAMPLE
    .\SDNExpress -ConfigurationData $MyConfigurationData
    Uses the hash table that is passed in as the configuration data.  This 
    parameter set is useful when programatically generating the 
    configuration data.
.EXAMPLE
    .\SDNExpress 
    Displays a user interface for interactively defining the configuraiton 
    data.  At the end you have the option to save as a configuration file
    before deploying.
.NOTES
    Prerequisites:
    * All Hyper-V hosts must have Hyper-V enabled and the Virtual Switch 
    already created.
    * All Hyper-V hosts must be joined to Active Directory.
    * The physical network must be preconfigured for the necessary subnets and 
    VLANs as defined in the configuration data.
    * The VHD specified in the configuration data must be reachable from the 
    computer where this script is run. 
#>

[CmdletBinding(DefaultParameterSetName="NoParameters")]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null,
    [Switch] $SkipValidation,
    [Switch] $SkipDeployment,
    [PSCredential] $DomainJoinCredential = $null,
    [PSCredential] $NCCredential = $null,
    [PSCredential] $LocalAdminCredential = $null
    )    


# Script version, should be matched with the config files
$ScriptVersion = "2.0"

$feature = get-windowsfeature "RSAT-NetworkController"
if ($feature -eq $null) {
    throw "SDN Express requires Windows Server 2016 or later."
}
if (!$feature.Installed) {
    add-windowsfeature "RSAT-NetworkController"
}

import-module networkcontroller
import-module .\SDNExpressModule.psm1 -force

write-SDNExpressLog "*** Begin SDN Express Deployment ***"
write-SDNExpressLog "ParameterSet: $($psCmdlet.ParameterSetName)" 
write-SDNExpressLog "  -ConfigurationDataFile: $ConfigurationDataFile"
write-SDNExpressLog "  -ConfigurationData: $ConfigurationData"
write-SDNExpressLog "  -SkipValidation: $SkipValidation"
write-SDNExpressLog "  -SkipDeployment: $SkipValidation"

if ($psCmdlet.ParameterSetName -eq "NoParameters") {
    write-sdnexpresslog "Begin interactive mode."    

    import-module .\SDNExpressUI.psm1 -force
    $configData = SDNExpressUI  
    if ($configData -eq $null)
    {
        # user cancelled
        exit
    }

} elseif ($psCmdlet.ParameterSetName -eq "ConfigurationFile") {
    write-sdnexpresslog "Using configuration file passed in by parameter."    
    $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
} elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") {
    write-sdnexpresslog "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) {
    write-error "Configuration file version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express.  Please update your config file to match the version $scriptversion example."
    return
}

function GetPassword 
{
    param(
        [String] $SecurePasswordText,
        [PSCredential] $Credential,
        [String] $Message,
        [String] $UserName
    )
    if ([String]::IsNullOrEmpty($SecurePasswordText) -and ($Credential -eq $null)) {
        write-sdnexpresslog "No credentials found on command line or in config file.  Prompting."    
        $Credential = get-Credential -Message $Message -UserName $UserName
    }

    if ($Credential -ne $null) {
        write-sdnexpresslog "Using credentials from the command line."    
        return $Credential.GetNetworkCredential().Password
    }

    try {
        write-sdnexpresslog "Using credentials from config file."    
        $securepassword = $SecurePasswordText | convertto-securestring -erroraction Ignore
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    } catch {
        write-sdnexpresslog "Unable to decrpypt credentials in config file.  Could be from a different user or generated on different computer.  Prompting instead."    
        $Credential = get-Credential -Message $Message -UserName $UserName
        if ($credential -eq $null) {
            write-sdnexpresslog "User cancelled credential input.  Exiting."    
            exit
        }
        return $Credential.GetNetworkCredential().Password
    }

}

$DomainJoinPassword = GetPassword $ConfigData.DomainJoinSecurePassword $DomainJoinCredential "Enter credentials for joining VMs to the AD domain." $configdata.DomainJoinUserName
$NCPassword = GetPassword $ConfigData.NCSecurePassword $NCCredential "Enter credentials for the Network Controller to use." $configdata.NCUserName
$LocalAdminPassword = GetPassword $ConfigData.LocalAdminSecurePassword $LocalAdminCredential "Enter the password for the local administrator of newly created VMs.  Username is ignored." "Administrator"

$NCSecurePassword = $NCPassword | convertto-securestring -AsPlainText -Force

$credential = New-Object System.Management.Automation.PsCredential($ConfigData.NCUsername, $NCSecurePassword)

$ManagementSubnetBits = $ConfigData.ManagementSubnet.Split("/")[1]
$PASubnetBits = $ConfigData.PASubnet.Split("/")[1]
$DomainJoinUserNameDomain = $ConfigData.DomainJoinUserName.Split("\")[0]
$DomainJoinUserNameName = $ConfigData.DomainJoinUserName.Split("\")[1]
$LocalAdminDomainUserDomain = $ConfigData.LocalAdminDomainUser.Split("\")[0]
$LocalAdminDomainUserName = $ConfigData.LocalAdminDomainUser.Split("\")[1]

if ($ConfigData.VMProcessorCount -eq $null) {$ConfigData.VMProcessorCount = 8}
if ($ConfigData.VMMemory -eq $null) {$ConfigData.VMMemory = 8GB}

write-SDNExpressLog "STAGE 1: Create VMs"

$params = @{
    'ComputerName'='';
    'VMLocation'=$ConfigData.VMLocation;
    'VMName'='';
    'VHDSrcPath'=$ConfigData.VHDPath;
    'VHDName'=$ConfigData.VHDFile;
    'VMMemory'=$ConfigData.VMMemory;
    'VMProcessorCount'=$ConfigData.VMProcessorCount;
    'Nics'=@();
    'CredentialDomain'=$DomainJoinUserNameDomain;
    'CredentialUserName'=$DomainJoinUserNameName;
    'CredentialPassword'=$DomainJoinPassword;
    'JoinDomain'=$ConfigData.JoinDomain;
    'LocalAdminPassword'=$LocalAdminPassword;
    'DomainAdminDomain'=$LocalAdminDomainUserDomain;
    'DomainAdminUserName'=$LocalAdminDomainUserName;
    'SwitchName'=$ConfigData.SwitchName
}

if (![String]::IsNullOrEmpty($ConfigData.ProductKey)) {
    $params.ProductKey = $ConfigData.ProductKey
}
if (![String]::IsNullOrEmpty($ConfigData.Locale)) {
    $params.Locale = $ConfigData.Locale
}
if (![String]::IsNullOrEmpty($ConfigData.TimeZone)) {
    $params.TimeZone = $ConfigData.TimeZone
}

write-SDNExpressLog "STAGE 1.1: Create NC VMs"
foreach ($NC in $ConfigData.NCs) {
    $params.ComputerName=$NC.HostName;
    $params.VMName=$NC.ComputerName;
    $params.Nics=@(
        @{Name="Management"; MacAddress=$NC.MacAddress; IPAddress="$($NC.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID}
    );

    New-SDNExpressVM @params
}

write-SDNExpressLog "STAGE 1.2: Create Mux VMs"

foreach ($Mux in $ConfigData.Muxes) {
    $params.ComputerName=$mux.HostName;
    $params.VMName=$mux.ComputerName;
    $params.Nics=@(
        @{Name="Management"; MacAddress=$Mux.MacAddress; IPAddress="$($Mux.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID},
        @{Name="HNVPA"; MacAddress=$Mux.PAMacAddress; IPAddress="$($Mux.PAIPAddress)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID; IsMuxPA=$true}
    );

    New-SDNExpressVM @params
}

write-SDNExpressLog "STAGE 1.3: Create Gateway VMs"

foreach ($Gateway in $ConfigData.Gateways) {
    $params.ComputerName=$Gateway.HostName;
    $params.VMName=$Gateway.ComputerName;
    $params.Nics=@(
        @{Name="Management"; MacAddress=$Gateway.MacAddress; IPAddress="$($Gateway.ManagementIP)/$ManagementSubnetBits"; Gateway=$ConfigData.ManagementGateway; DNS=$ConfigData.ManagementDNS; VLANID=$ConfigData.ManagementVLANID}
        @{Name="FrontEnd"; MacAddress=$Gateway.FrontEndMac; IPAddress="$($Gateway.FrontEndIp)/$PASubnetBits"; VLANID=$ConfigData.PAVLANID},
        @{Name="BackEnd"; MacAddress=$Gateway.BackEndMac; VLANID=$ConfigData.PAVLANID}
    );

    New-SDNExpressVM @params
}

write-SDNExpressLog "STAGE 2: Network Controller Configuration"

$NCNodes = @()
foreach ($NC in $ConfigData.NCs) {
    $NCNodes += $NC.ComputerName
}

WaitforComputertobeready $NCNodes $false

New-SDNExpressNetworkController -ComputerNames $NCNodes -RESTName $ConfigData.RestName -Credential $Credential

write-SDNExpressLog "STAGE 2.1: Getting REST cert thumbprint in order to find it in local root store."
$NCHostCertThumb = invoke-command -ComputerName $NCNodes[0] { 
    param(
        $RESTName
    )
    return (get-childitem "cert:\localmachine\my" | where {$_.Subject -eq "CN=$RestName"}).Thumbprint
} -ArgumentList $ConfigData.RestName

$NCHostCert = get-childitem "cert:\localmachine\root\$NCHostCertThumb"

$params = @{
    'RestName' = $ConfigData.RestName;
    'MacAddressPoolStart' = $ConfigData.SDNMacPoolStart;
    'MacAddressPoolEnd' = $ConfigData.SDNMacPoolEnd;
    'NCHostCert' = $NCHostCert
    'NCUsername' = $ConfigData.NCUsername;
    'NCPassword' = $NCPassword
}
New-SDNExpressVirtualNetworkManagerConfiguration @Params

$params = @{
    'RestName' = $ConfigData.RestName;
    'PrivateVIPPrefix' = $ConfigData.PrivateVIPSubnet;
    'PublicVIPPrefix' = $ConfigData.PublicVIPSubnet
}

New-SDNExpressLoadBalancerManagerConfiguration @Params

$params = @{
        'RestName' = $ConfigData.RestName;
        'AddressPrefix' = $ConfigData.PASubnet;
        'VLANID' = $ConfigData.PAVLANID;
        'DefaultGateways' = $ConfigData.PAGateway;
        'IPPoolStart' = $ConfigData.PAPoolStart;
        'IPPoolEnd' = $ConfigData.PAPoolEnd
}
Add-SDNExpressVirtualNetworkPASubnet @params

write-SDNExpressLog "STAGE 3: Host Configuration"

foreach ($h in $ConfigData.hypervhosts) {
    Add-SDNExpressHost -ComputerName $h -RestName $ConfigData.RestName -HostPASubnetPrefix $ConfigData.PASubnet -NCHostCert $NCHostCert -Credential $Credential -VirtualSwitchName $ConfigData.SwitchName
}

write-SDNExpressLog "STAGE 4: Mux Configuration"

foreach ($Mux in $ConfigData.muxes) {
    Add-SDNExpressMux -ComputerName $Mux.ComputerName -PAMacAddress $Mux.PAMacAddress -LocalPeerIP $Mux.PAIPAddress -MuxASN $ConfigData.SDNASN -Routers $ConfigData.Routers -RestName $ConfigData.RestName -NCHostCert $NCHostCert -Credential $Credential
}

write-SDNExpressLog "STAGE 5: Gateway Configuration"

New-SDNExpressGatewayPool -IsTypeAll -PoolName $ConfigData.PoolName -Capacity $ConfigData.Capacity -GreSubnetAddressPrefix $ConfigData.GreSubnet -RestName $ConfigData.RestName -Credential $Credential

foreach ($G in $ConfigData.Gateways) {
    $params = @{
        'RestName'=$ConfigData.RestName
        'ComputerName'=$g.computername
        'HostName'=$g.Hostname
        'NCHostCert'= $NCHostCert
        'PoolName'=$ConfigData.PoolName
        'FrontEndIp'=$G.FrontEndIP
        'FrontEndLogicalNetworkName'='HNVPA'
        'FrontEndAddressPrefix'=$ConfigData.PASubnet
        'FrontEndMac'=$G.FrontEndMac
        'BackEndMac'=$G.BackEndMac
        'RouterASN'=$ConfigData.Routers[0].RouterASN
        'RouterIP'=$ConfigData.Routers[0].RouterIPAddress
        'LocalASN'=$ConfigData.SDNASN
    }
    New-SDNExpressGateway @params
}


<<<<<<< HEAD
        Script ConfigureWindowsFirewall
        {
            SetScript = {
                # Firewall-REST    
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-REST" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for NCHostAgent Rest";
                    New-NetFirewallRule -Name "Firewall-REST" -DisplayName "Network Controller Host Agent REST" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-REST" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-REST Rule Failed on $($using:node.NodeName)"
                }
            
                # Firewall-OVSDB
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for NCHostAgent OVSDB";
                    New-NetFirewallRule -Name "Firewall-OVSDB" -DisplayName "Network Controller Host Agent OVSDB" -Group "NcHostAgent" -Action Allow -Protocol TCP -LocalPort 6640 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-OVSDB Rule Failed on $($using:node.NodeName)"
                }
                
                # Firewall-HostAgent-TCP-IN
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for Firewall-HostAgent-TCP-IN";
                    New-NetFirewallRule -Name "Firewall-HostAgent-TCP-IN" -DisplayName "Network Controller Host Agent (TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort Any -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-HostAgent-TCP-IN Rule Failed on $($using:node.NodeName)"
                }
                
                # Firewall-HostAgent-WCF-TCP-IN  
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for Firewall-HostAgent-WCF-TCP-IN";
                    New-NetFirewallRule -Name "Firewall-HostAgent-WCF-TCP-IN" -DisplayName "Network Controller Host Agent WCF(TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort 80 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-HostAgent-WCF-TCP-IN Rule Failed on $($using:node.NodeName)"
                }
                
                # Firewall-HostAgent-TLS-TCP-IN
                
                $fwrule = Get-NetFirewallRule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue
                if ($fwrule -eq $null) {
                    Write-Verbose "Create Firewall rule for Firewall-HostAgent-TLS-TCP-IN";
                    New-NetFirewallRule -Name "Firewall-HostAgent-TLS-TCP-IN" -DisplayName "Network Controller Host Agent WCF over TLS (TCP-In)" -Group "Network Controller Host Agent Firewall Group" -Action Allow -Protocol TCP -LocalPort 443 -Direction Inbound -Enabled True
                }

                if((get-netfirewallrule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue) -eq $null)
                {
                    throw "Create Firewall-HostAgent-TLS-TCP-IN Rule Failed on $($using:node.NodeName)"
                }            
            }
            TestScript = {
                if(((get-netfirewallrule -Name "Firewall-REST" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-OVSDB" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-HostAgent-TCP-IN" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-HostAgent-WCF-TCP-IN" -ErrorAction SilentlyContinue) -eq $null) -or
                   ((get-netfirewallrule -Name "Firewall-HostAgent-TLS-TCP-IN" -ErrorAction SilentlyContinue) -eq $null))
                {
                    return $false
                }

                return $true
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script CleanupCerts
        {
            SetScript = {
                # Host Cert in My
                $store = new-object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
                $store.open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $fqdn = "$($using:node.fqdn)".ToUpper()
                $certs = $store.Certificates | Where {$_.Subject.ToUpper().Contains($fqdn)}
                foreach($cert in $certs) {
                    $store.Remove($cert)
                }
                $store.Dispose()
                
                # NC Cert in Root
                $store = new-object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
                $store.open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $fqdn = "$($using:node.fqdn)".ToUpper()
                $certs = $store.Certificates | Where {$_.Subject.ToUpper().Contains($fqdn)}
                foreach($cert in $certs) {
                    $store.Remove($cert)
                }
                $store.Dispose()
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script InstallHostCert
        {
            SetScript = {
                Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
                . "$($using:node.HostInstallSrcDir)\Scripts\CertHelpers.ps1"
                
                write-verbose "Querying self signed certificate ...";
                $cn = "$($using:node.NodeName).$($node.fqdn)".ToUpper()
                $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")} | Select -First 1
                if ($cert -eq $null) {
                    $certName = "$($using:node.nodename).$($using:node.FQDN)".ToUpper()
                    $certPath = "c:\$($using:node.certfolder)"
                    $certPwd = $using:node.HostPassword
                    write-verbose "Adding Host Certificate to trusted My Store from [$certpath\$certName]"
                    AddCertToLocalMachineStore "$($certPath)\$($certName).pfx" "My" "$($certPwd)"

                    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where {$_.Subject.ToUpper().StartsWith("CN=$($cn)")} | Select -First 1
                }
                    
                write-verbose "Giving permission to network service for the host certificate $($cert.Subject)"
                GivePermissionToNetworkService $cert
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
            PSDSCRunAsCredential = $psCred
        }  

        Script InstallNCCert
        {
            SetScript = {
                write-verbose "Adding Network Controller Certificates to trusted Root Store"
                . "$($using:node.HostInstallSrcDir)\Scripts\CertHelpers.ps1"
                
                $certPath = "c:\$($using:node.CertFolder)\$($using:node.NetworkControllerRestName).pfx"
                $certPwd = "secret"
                
                write-verbose "Adding $($certPath) to Root Store"
                AddCertToLocalMachineStore "$($certPath)" "Root" "$($certPwd)"
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        Script RestartHostAgent
        {
            SetScript = {
                $service = Get-Service -Name NCHostAgent
                Stop-Service -InputObject $service -Force
                Set-Service -InputObject $service -StartupType Automatic
                Start-Service -InputObject $service
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        } 
 
        Script EnableVFP
        {
            SetScript = {
                $switch = $using:node.vSwitchName
                Enable-VmSwitchExtension -VMSwitchName $switch -Name "Microsoft Azure VFP Switch Extension"

                Write-Verbose "Wait 40 seconds for the VFP extention to be enabled"
                sleep 40
            
                if((get-vmswitchextension -VMSwitchName $switch -Name "Microsoft Azure VFP Switch Extension").Enabled -ne $true)
                {
                    throw "EnableVFP Failed on $($using:node.NodeName)"
                }
            }
            TestScript = {
                return (get-vmswitchextension -VMSwitchName $using:node.vSwitchName -Name "Microsoft Azure VFP Switch Extension").Enabled                 
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureSLBHostAgent
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        . "$($node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword
        $slbmVip = (Get-NCLoadbalancerManager).properties.loadbalancermanageripaddress

        Script CreateSLBConfigFile
        {
            SetScript = {
                $slbhpconfigtemplate = @'
<?xml version="1.0" encoding="utf-8"?>
<SlbHostPluginConfiguration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SlbManager>
        <HomeSlbmVipEndpoints>
            <HomeSlbmVipEndpoint>{0}:8570</HomeSlbmVipEndpoint>
        </HomeSlbmVipEndpoints>
        <SlbmVipEndpoints>
            <SlbmVipEndpoint>{1}:8570</SlbmVipEndpoint>
        </SlbmVipEndpoints>
        <SlbManagerCertSubjectName>{2}</SlbManagerCertSubjectName>
    </SlbManager>
    <SlbHostPlugin>
        <SlbHostPluginCertSubjectName>{3}</SlbHostPluginCertSubjectName>
    </SlbHostPlugin>
    <NetworkConfig>
        <MtuSize>0</MtuSize>
        <JumboFrameSize>4088</JumboFrameSize>
        <VfpFlowStatesLimit>500000</VfpFlowStatesLimit>
    </NetworkConfig>
</SlbHostPluginConfiguration>
'@

                $hostFQDN = "$($using:node.NodeName).$($using:node.fqdn)".ToLower()
                $ncFQDN = "$($using:node.NetworkControllerRestName)".ToLower()
                
                $slbhpconfig = $slbhpconfigtemplate -f $using:slbmVip, $using:slbmVip, $ncFQDN, $hostFQDN
                write-verbose $slbhpconfig
                set-content -value $slbhpconfig -path 'c:\windows\system32\slbhpconfig.xml' -encoding UTF8
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        Script RestartSLBHostAgent
        {
            SetScript = {
                #this should be temporary fix
                $tracingpath = "C:\Windows\tracing"
                if((test-path $tracingpath) -ne $true) {
                    mkdir $tracingpath
                }

                $service = Get-Service -Name SlbHostAgent
                Stop-Service -InputObject $service -Force
                Set-Service -InputObject $service -StartupType Automatic
                Start-Service -InputObject $service
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureServers
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    # This executes from the NC as the 
    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        foreach ($hostNode in $AllNodes.Where{$_.Role -eq "HyperVHost"})
        {
            Script "AddHostToNC_$($hostNode.NodeName)"
            {
                SetScript = {
                    $verbosepreference = "Continue"
                  
                    . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
            
                    $serverResourceId = Get-ServerResourceId -ComputerName $using:hostNode.NodeName
                    write-verbose "Server ResourceId (VMswitch[0]): $serverResourceId"

                    $hostcred = Get-NCCredential -ResourceId $using:hostNode.HostCredentialResourceId
                    write-verbose "NC Host Credential: $($hostcred)"

                    $nccred = get-nccredential -ResourceId $using:hostNode.NCCredentialResourceId
                    write-verbose "NC NC Credential: $($nccred)";
            
                    $hostFQDN = "$($using:hostNode.NodeName).$($using:hostNode.fqdn)".ToLower()
                    $ipaddress = [System.Net.Dns]::GetHostByName($hostFQDN).AddressList[0].ToString()
        
                    $connections = @()
                    $connections += New-NCServerConnection -ComputerNames @($ipaddress, $hostFQDN) -Credential $hostcred -Verbose
                    $connections += New-NCServerConnection -ComputerNames @($ipaddress, $hostFQDN) -Credential $nccred -Verbose
        
                    $ln = Get-NCLogicalNetwork -ResourceId $using:hostNode.PALogicalNetworkResourceId -Verbose
            
                    $pNICs = @()
                    $pNICs += New-NCServerNetworkInterface -LogicalNetworksubnets ($ln.properties.subnets) -Verbose

                    $certPath = "$($using:hostNode.InstallSrcDir)\$($using:hostNode.CertFolder)\$($hostFQDN).cer"
                    write-verbose "Getting cert file content: $($certPath)"
                    $file = Get-Content $certPath -Encoding Byte
                    write-verbose "Doing conversion to base64"
                    $base64 = [System.Convert]::ToBase64String($file)
            
                    $server = New-NCServer -ResourceId $serverResourceId -Connections $connections -PhysicalNetworkInterfaces $pNICs -Certificate $base64 -Verbose
            
                    $serverObj = Get-NCServer -ResourceId $serverResourceId
                    if(!$serverObj)
                    {
                        throw "Adding Host to NC Failed on $($using:hostNode.NodeName)"
                    }
                }
                TestScript = {
                    return $false
                }
                GetScript = {
                    return @{ result = $true }
                }
            }
        }
    }
}

Configuration ConfigureHostAgent
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        # This block executes locally on the deployment machine as some hosts are not able to make REST calls (e.g. Nano)

        . "$($node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestName -UserName $node.NCClusterUserName -Password $node.NCClusterPassword

        $serverResourceId = Get-ServerResourceId -ComputerName $node.NodeName
        $serverObj = Get-NCServer -ResourceId $serverResourceId
        $serverInstanceId = $serverObj.instanceId

        # The following Registry/script configurations execute on the actual hosts

        Registry SetHostId
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters"
            ValueName = "HostId"
            ValueData = $serverInstanceId
            ValueType = "String"
        }

        Script RestartHostAgents
        {
            SetScript = {
<<<<<<< HEAD
                $dnsproxy = get-service DNSProxy -ErrorAction Ignore
                if ($dnsproxy -ne $null) {
                    Write-Verbose "Stopping DnsProxy service."
                    Stop-Service DnsProxy -Force
                }
=======
                <#Write-Verbose "Restarting NcHostAgent.";
                Restart-Service NCHostAgent -Force
            
                Write-Verbose "Restarting SlbHostAgent.";
                Restart-Service SlbHostAgent -Force#>
                
                # Workaround for DnsProxy
>>>>>>> 86ad7fc... RS3 changes to remove DNSProxy service from SDNExpress.ps1

                Write-Verbose "Stopping SlbHostAgent service."
                Stop-Service SlbHostAgent -Force                
                Write-Verbose "Stopping NcHostAgent service."
                Stop-Service NcHostAgent -Force

                Write-Verbose "Starting NcHostAgent service."
                Start-Service NcHostAgent
                Write-Verbose "Starting SlbHostAgent service."
                Start-Service SlbHostAgent
<<<<<<< HEAD

                if ($dnsproxy -ne $null) {                
                    $i = 0
                    while ($i -lt 10) {
                        try {
                            Start-Sleep -Seconds 10
                            Write-Verbose "Starting DnsProxy service (Attempt: $i)."
                            Start-Service DnsProxy -ErrorAction Stop
                            break
                        }
                        catch {
                            Write-Verbose "DnsProxy service can't be started. Will retry."
                            $i++
                            if($i -ge 10) {
                                Write-Verbose "DnsProxy serivce can't be started after $i attempts. Exception: $_"
                                throw $_
                            }
                        }
                    }   
                }           
=======
>>>>>>> 86ad7fc... RS3 changes to remove DNSProxy service from SDNExpress.ps1
            }

            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Configuration ConfigureIDns
{    
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.ServiceFabricRingMembers -ne $null}.NodeName
    {
        Script CreateiDnsCredentials
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword                 
                $hostcred = New-NCCredential -ResourceId $node.iDNSCredentialResourceId -UserName $using:node.iDNSAdminUsername -Password $using:node.iDNSAdminPassword
            }

            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $obj = Get-NCCredential -ResourceId $using:node.iDNSCredentialResourceId
                if ($obj -ne $null)	{
                    Write-verbose "Get NC creds: object already exists. returning true."
                    return $true
                }
                else {
                    Write-verbose "Get NC creds: object does not exist. returning false."
                    return $false
                }
            }

            GetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $obj = Get-NCCredential -ResourceId $using:node.iDNSCredentialResourceId
                return @{ result = $obj }
            }
        }
             
        Script PutiDnsConfiguration
        {
            SetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $cred = Get-NCCredential -ResourceId $using:node.iDNSCredentialResourceId
                write-verbose "Adding IP address: $($using:node.iDNSAddress) to the DNSConfig"
                $connections = @()
                $connections += New-NCServerConnection -ComputerNames @($using:node.iDNSAddress) -Credential $cred -Verbose
                write-verbose "Adding zone $($using:node.iDNSZoneName) to the DNSConfig"
                $iDnsConfig = Add-iDnsConfiguration -Connections $connections -ZoneName $using:node.iDNSZoneName
            }

            TestScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                try { $iDnsObj = Get-iDnsConfiguration } catch { $iDnsObj = $null }
                if ($iDnsObj -ne $null) {
                    Write-verbose "Get iDNS: object already exists. Returning true."
                    return $true
                }
                else {
                    Write-verbose "Get iDNS: object does not exist. Returning false."
                    return $false
                }
            }

            GetScript = {
                . "$($using:node.InstallSrcDir)\Scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $using:node.NetworkControllerRestName -UserName $using:node.NCClusterUserName -Password $using:node.NCClusterPassword
                $iDnsObj = Get-iDnsConfiguration
                return @{ result = $iDnsObj }
            }
        }
    }
}

Configuration ConfigureIDnsProxy
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost"}.NodeName
    {
        #iDNS Proxy Registry Hives
        $iDnsVfpPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService"                                                                                          
        $iDnsProxyPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNSProxy\Parameters"

        Registry SetDnsPort
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "Port"
            ValueData = 53
            ValueType = "Dword"
        }

        Registry SetDnsProxyPort
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "ProxyPort"
            ValueData = 53
            ValueType = "Dword"
        }

        Registry SetDnsIPAddress
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "IP"
            ValueData = "169.254.169.254"
            ValueType = "String"
        }

        Registry SetDnsMacAddress
        {
            Ensure = "Present"
            Key = $iDnsVfpPath
            ValueName = "MAC"
            ValueData = $node.iDNSMacAddress
            ValueType = "String"
        }

        Registry SetDnsForwarder
        {
            Ensure = "Present"
            Key = $iDnsProxyPath
            ValueName = "Forwarders"
            ValueData = $node.iDNSAddress
            ValueType = "String"
        }

        Script SetupDNSProxy
        {
            SetScript = {

                # Enable firewall rules for DNS proxy service
                Write-verbose "Enable DNS Proxy Service firewall rule group"
                Enable-NetFirewallRule -DisplayGroup 'DNS Proxy Firewall'

                Write-Verbose "Stopping NcHostAgent service."
                Stop-Service NcHostAgent -Force

                Write-Verbose "Starting NcHostAgent service."
                Start-Service NcHostAgent
            }

            TestScript = {
                $ncHostAgentState = $false;
                Write-verbose "Get NCHostAgent service running state"
                $ncHostAgentState = Get-Service -Name "NcHostAgent"
                $ncHostAgentState = ($ncHostAgentState.status -eq "Running")
                return $ncHostAgentState            
            }

            GetScript = {
                Write-verbose "Get NcHostAgent service "
                $ncHostAgentState = Get-Service -Name "NcHostAgent"
                return @{ result = $true }
            }
        }
    }
}

Configuration CleanUp
{  
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.NodeName
    {
        script "RemoveCertsDirectory"
        {
            SetScript = {
                write-verbose "Removing contents of Certs directory"
                rm -recurse -force "$($env:systemdrive)\$($Using:node.CertFolder)\*"
            }
            TestScript = {
                return ((Test-Path "$($env:systemdrive)\$($Using:node.CertFolder)") -ne $True)
            }
            GetScript = {
                return @{ result = $true }
            }
        }    
    }
}

function GetOrCreate-PSSession
{
    param ([Parameter(mandatory=$false)][string]$ComputerName,
           [PSCredential]$Credential = $null )

    # Get or create PS Session to the HyperVHost
    $PSSessions = @(Get-PSSession | ? {$_.ComputerName -eq $ComputerName})

    foreach($session in $PSSessions)
    {
        if ($session.State -ne "Opened" -and $session.Availability -ne "Available")
        { $session | remove-pssession -Confirm:$false -ErrorAction ignore }
        else
        { return $session }        
    }

    # No valid PSSession found, create a new one
    if ($Credential -eq $null)
    { return (New-PSSession -ComputerName $ComputerName -ErrorAction Ignore) }
    else
    { return (New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Ignore) }
}

function WaitForComputerToBeReady
{
    param(
        [string[]] $ComputerName,
        [Switch]$CheckPendingReboot
    )


    foreach ($computer in $computername) {        
        write-verbose "Waiting for $Computer to become active."
        
        $continue = $true
        while ($continue) {
            try {
                $ps = $null
                $result = ""
                
                klist purge | out-null  #clear kerberos ticket cache 
                Clear-DnsClientCache    #clear DNS cache in case IP address is stale
                
                write-verbose "Attempting to contact $Computer."
                $ps = GetOrCreate-pssession -computername $Computer -erroraction ignore
                if ($ps -ne $null) {
                    if ($CheckPendingReboot) {                        
                        $result = Invoke-Command -Session $ps -ScriptBlock { 
                            if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                                "Reboot pending"
                            } 
                            else {
                                hostname 
                            }
                        }
                    }
                    else {
                        try {
                            $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
                        } catch { }
                    }
                }
                if ($result -eq $Computer) {
                    $continue = $false
                    break
                }
                if ($result -eq "Reboot pending") {
                    write-verbose "Reboot pending on $Computer.  Waiting for restart."
                }
            }
            catch 
            {
            }
            write-verbose "$Computer is not active, sleeping for 10 seconds."
            sleep 10
        }
    write-verbose "$Computer IS ACTIVE.  Continuing with deployment."
    }
}

function GetRoleMembers
{
    param(
        [Object] $ConfigData,
        [String[]] $RoleNames
    )
    $results = @()

    foreach ($node in $configdata.AllNodes) {
        if ($node.Role -in $RoleNames) {
            $results += $node.NodeName
        }
    }
    if ($results.count -eq 0) {
        throw "No node with NetworkController role found in configuration data"
    }
    return $results
}

function RestartRoleMembers
{
    param(
        [Object] $ConfigData,
        [String[]] $RoleNames,
        [Switch] $Wait,
        [Switch] $Force
    )
    $results = @()

    foreach ($node in $configdata.AllNodes) {
        if ($node.Role -in $RoleNames) {
                write-verbose "Restarting $($node.NodeName)"
                $ps = GetOrCreate-pssession -ComputerName $($node.NodeName)
                Invoke-Command -Session $ps -ScriptBlock { 
                    if ($using:Force -or (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")) {
                        Restart-computer -Force -Confirm:$false
                    }
                }
        }
    }
    
    sleep 10

    if ($wait.IsPresent) {
        WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController")) -CheckPendingReboot
    }
}

function GatherCerts
{
    param(
        [Object] $ConfigData
    )
    $nccertname = $ConfigData.allnodes[0].NetworkControllerRestName

    write-verbose "Finding NC VM with REST cert."
    foreach ($n in $configdata.allnodes) {
        if (($n.role -eq "NetworkController") -and ($n.ServiceFabricRingMembers -ne $null)) {
            write-verbose "NC REST host is $($n.nodename)."
            $ncresthost = $n.nodename

            Write-Verbose "Copying all certs to the installation sources cert directory."
            $NCCertSource = "\\$($ncresthost)\c$\$($nccertname)"
            $NCCertDestination = "$($configData.AllNodes[0].installsrcdir)\$($configData.AllNodes[0].certfolder)"

            write-verbose ("Copying REST cert from [{0}] to [{1}]" -f $NCCertSource, $NCCertDestination)
            copy-item -path $NCCertSource -Destination $NCCertDestination

            if(Test-Path "$NCCertSource.pfx") {
                write-verbose ("Copying REST cert pfx from [{0}] to [{1}]" -f "$NCCertSource.pfx", $NCCertDestination)
                copy-item -path "$NCCertSource.pfx" -Destination $NCCertDestination
            }

            foreach ($n2 in $configdata.allnodes) {
                if ($n2.role -eq "NetworkController") {
                    $NCCertSource = '\\{0}\c$\{1}.{2}.pfx' -f $ncresthost, $n2.NodeName, $nccertname
                    $fulldest = "$($NCCertDestination)\$($n2.NodeName).$($nccertname).pfx"

                    write-verbose ("Copying NC Node cert pfx from [{0}] to [{1}]" -f $NCCertSource, $fulldest)
                    copy-item -path $NCCertSource -Destination $fulldest
                }
                elseif ($n2.role -eq "HyperVHost") {
                    $CertName = "$($n2.nodename).$($n2.FQDN)".ToUpper()
                    $HostCertSource = '\\{0}\c$\{1}' -f $ncresthost, $CertName
                    $fulldest = "$($NCCertDestination)\$($CertName)"

                    write-verbose ("Copying Host Node cert from [{0}] to [{1}]" -f "$HostCertSource.cer", "$fulldest.cer")
                    copy-item -path "$HostCertSource.cer" -Destination "$fulldest.cer"

                    write-verbose ("Copying Host Node cert pfx from [{0}] to [{1}]" -f "$HostCertSource.pfx", "$fulldest.pfx")
                    copy-item -path "$HostCertSource.pfx" -Destination "$fulldest.pfx"
                }
            }

            break
        }
    }
}

function CheckCompatibility
{
    param(
        [String] $ScriptVer,
        [String] $ConfigVer
    )
    write-verbose ("Script version is $ScriptVer and FabricConfig version is $ConfigVer")

    if ($scriptVer -ine $ConfigVer) {
        $error = "The Fabric configuration file which was provided is not compatible with this version of the script. "
        $error += "To avoid compatibility issues, please use only the version of FabricConfig.psd1 which came with this version of the SDNExpress.ps1 script"

        throw $error
    }
}


function PopulateDefaults
{
    param(
        [Object] $AllNodes
    )

    write-verbose "Populating defaults into parameters that were not set in config file."

    #Set Logical Network resourceids based on name
    foreach ($ln in $AllNodes[0].LogicalNetworks)
    {
        if ([string]::IsNullOrEmpty($ln.ResourceId)) {
            $ln.ResourceId = $ln.Name
        }

        foreach ($subnet in $ln.subnets) {
            if ($subnet.DNS -eq $null) {
                $subnet.DNS = @()
            }
        }
    }

    #Set NetworkInterface ResourceIds if not specified
    foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
        foreach ($VMInfo in $node.VMs) {
            foreach ($nic in $VMInfo.NICs) {
                if ([String]::IsNullOrEmpty($nic.Name)) {
                    $nic.Name = $nic.LogicalNetwork
                }
            }
        }
    }

    #Populate mac addresses if not specified for each VM

    if (![string]::IsNullOrEmpty($AllNodes[0].VMMACAddressPoolStart)) 
    {
        $nextmac = ($AllNodes[0].VMMACAddressPoolStart -replace '[\W]', '')
        write-verbose "Starting MAC is $nextmac"

        foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
            foreach ($VMInfo in $node.VMs) {
                foreach ($nic in $VMInfo.NICs) {

                    if ([String]::IsNullOrEmpty($nic.MacAddress)) {
                        $nic.MacAddress = $nextmac
                        $intmac = [long]::Parse($nextmac, [System.Globalization.NumberStyles]::HexNumber)
                        $nextmac = "{0:x12}" -f ($intmac + 1) 
                        write-verbose "Assigned MAC $($nic.MacAddress) to [$($vminfo.VMname)] [$($nic.Name)]"
                    } else {
                        $nic.MacAddress = $nic.MacAddress -replace '[\W]', ''
                    }

                    # Normalize the Mac Addresses
                    $nic.MacAddress = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
                }
            }
        }
    }

    #Set NetworkInterface ResourceIds if not specified
    foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
        foreach ($VMInfo in $node.VMs) {
            foreach ($nic in $VMInfo.NICs) {
                if ([String]::IsNullOrEmpty($nic.PortProfileId)) {
                    $vmnode = $AllNodes.Where{$_.NodeName -eq $vminfo.VMName}
                    
                    switch ($vmnode.Role)
                    { 
                        "NetworkController" {
                            write-verbose "VM $($vminfo.vmname) is a Network Controller"
                            $nic.PortProfileId = [System.Guid]::Empty.Guid
                            $nic.PortProfileData = 1
                        }
                        "SLBMUX" {
                            write-verbose "VM $($vminfo.VMname) is a MUX"
                            $nic.PortProfileId = [System.Guid]::Empty.Guid
                            $nic.PortProfileData = 2
                        }
                        default {
                            write-verbose "VM $($vminfo.VMname) is a Gateway or Other"
                            $nic.PortProfileId = "$($VMInfo.VMName)_$($nic.Name)"
                            $nic.PortProfileData = 1
                        }
                    }

                }
            }
        }
    }

    $IsFirst = $true
    $RingMembers = @()
    foreach ($node in $AllNodes.Where{$_.Role -eq "NetworkController"}) {
        if ($IsFirst) {
            $firstnode = $node
            $IsFirst = $false
        }
        $RingMembers += $node.NodeName
    }

    if ($firstnode.ServiceFabricRingMembers -eq $null) {
        write-verbose "Service Fabric ring members: $RingMembers"
        $firstnode.ServiceFabricRingMembers = $RingMembers
    }

    foreach ($node in $AllNodes.Where{$_.Role -eq "SLBMUX"}) {
        If ([String]::IsNullOrEmpty($node.MuxVirtualServerResourceId)) 
        {
            write-verbose "Setting a MuxVirtualServerResourceId to $($node.NodeName)"
            $node.MuxVirtualServerResourceId = $node.NodeName
        }
        If ([String]::IsNullOrEmpty($node.MuxResourceId)) 
        {
            write-verbose "Setting a MuxResourceId to $($node.NodeName)"
            $node.MuxResourceId = $node.NodeName
        }
        If ([String]::IsNullOrEmpty($node.HnvPaMac)) 
        {
            foreach ($hvnode in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
                foreach ($VMInfo in $hvnode.VMs) {
                    if ($VMInfo.VMName -eq $node.NodeName) {
                        foreach ($nic in $VMInfo.NICs) {
                            if ($nic.Name -eq $node.InternalNicName) {
                                write-verbose "Setting Mux HnvPaMac to $($nic.MAcAddress)"
                                $node.HnvPaMac = $nic.MacAddress
                            }
                        }
                    }
                }
            }
        }

        # Normalize the Mac Addresses
        $node.HnvPaMac = [regex]::matches($node.HnvPaMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
    }

    foreach ($node in $AllNodes.Where{$_.Role -eq "Gateway"}) {
        
        foreach ($hvnode in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
            foreach ($VMInfo in $hvnode.VMs) {
                if ($VMInfo.VMName -eq $node.NodeName) {
                    $VMInfo.VMRole = "Gateway"
                    
                    foreach ($nic in $VMInfo.NICs) {
                        if ($nic.Name -eq $node.InternalNicName)
                        {
                            If ([String]::IsNullOrEmpty($node.InternalNicMAC)) 
                            {
                                write-verbose "Setting a InternalNicMAC to $($nic.MAcAddress)"
                                $node.InternalNicMac = $nic.MacAddress
                            }
                        }
                        elseif ($nic.Name -eq $node.ExternalNicName)
                        {
                            If ([String]::IsNullOrEmpty($node.ExternalNicMAC)) 
                            {
                                write-verbose "Setting a ExternalNicMAC to $($nic.MacAddress)"
                                $node.ExternalNicMac = $nic.MacAddress
                            } 

                            If ([String]::IsNullOrEmpty($node.ExternalIPAddress)) 
                            {
                                write-verbose "Setting a ExternalIPAddress to $($nic.IPAddress)"
                                $node.ExternalIPAddress = $nic.IPAddress
                            }

                            write-verbose "Setting a ExternalLogicalNetwork to $($nic.LogicalNetwork)"
                            $node.ExternalLogicalNetwork = $nic.LogicalNetwork
                        }

                    }
                    if ([string]::IsNullOrEmpty($VMInfo.InternalNicPortProfileId)) {
                        write-verbose "Setting gateway VM InternalNicPortProfileId to $($node.NodeName)_Internal"
                        $VMInfo.InternalNicPortProfileId = $node.NodeName+"_Internal"
                    }
                    if ([string]::IsNullOrEmpty($VMInfo.ExternalNicPortProfileId)) {
                        write-verbose "Setting gateway VM ExternalNicPortProfileId to $($node.NodeName)_external"
                        $VMInfo.ExternalNicPortProfileId = $node.NodeName+"_External"
                    }
                }
            }
        }

        write-verbose "Gateway Internal MAC is $($node.InternalNicMac) before normalization."
        write-verbose "Gateway External MAC is $($node.ExternalNicMac) before normalization."

        # Normalize the Mac Addresses
        $node.InternalNicMac = [regex]::matches($node.InternalNicMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
        $node.ExternalNicMac = [regex]::matches($node.ExternalNicMac.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"
        
        If ([String]::IsNullOrEmpty($node.InternalNicPortProfileId)) 
        {
            write-verbose "Setting gateway node InternalNicPortProfileId to $($node.NodeName)_Internal"
            $node.InternalNicPortProfileId = $node.NodeName+"_Internal"
        }
        If ([String]::IsNullOrEmpty($node.ExternalNicPortProfileId)) 
        {
            write-verbose "Setting gateway node ExternalNicPortProfileId to $($node.NodeName)_External"
            $node.ExternalNicPortProfileId = $node.NodeName+"_External"
        }
    }

    write-verbose "Finished populating defaults."
}

function PreDeploymentValidation
{
    param(
        [Object] $AllNodes
    )

    write-verbose "--------------------------------------------"
    write-verbose "--- Performing pre-deployment validation ---"
    write-verbose "--------------------------------------------"
    $errors = 0

    ##### TEST: Verify Network Controller DNS registration

    $RestName = $AllNodes[0].NetworkControllerRestName
    $RestIP = $AllNodes[0].NetworkControllerRestIP
    
    $result = resolve-dnsname $restname
    if ($result.count -eq 1) {
        if ($result.IPAddress -eq $RestIP) {
            write-verbose "PASSED: network controller DNS registration test."
        } else {
            write-host -foregroundcolor RED  "FAILED: network controller DNS registration test."
            write-host -foregroundcolor RED  "REASON: DNS record '$($result.IPAddress)' for NetworkControllerRestName '$restname' does not match NetworkControllerRestIP '$restip'."
            write-host -foregroundcolor RED  "ACTION: (1) Verify NetworkControllerRestIP is correct in config file."
            write-host -foregroundcolor RED  "ACTION: (2) Verify IP registered to '$restname' in DNS is correct."
            $errors++
        }
    }
    elseif ($result.count -eq 0) {
        write-host -foregroundcolor RED  "FAILED: network controller DNS registration test."
        write-host -foregroundcolor RED  "REASON: Unable to resolve network controller REST name in DNS."
        write-host -foregroundcolor RED  "ACTION: (1) Verify '$RestName' is the correct value for NetworkControllerRestName in config file."
        write-host -foregroundcolor RED  "ACTION: (2) Manually create an entry in your DNS server that assigns '$restip' to '$restname'."
        $errors++
    }
    else {
        write-host -foregroundcolor RED  "FAILED network controller DNS registration test."
        write-host -foregroundcolor RED  "REASON: Network Controller REST name '$RestName' has more than one entry in DNS."
        write-host -foregroundcolor RED  "ACTION: Manually remove all entries for '$RestName' from DNS except for the entry for '$restip'."
        $errors++
    }


    foreach ($node in $AllNodes.Where{$_.Role -eq "HyperVHost"}) {
        $computer = $node.NodeName

        ##### TEST: Test Host DNS registration

        $result = resolve-dnsname $computer
        if ($result.count -eq 1) {
            write-verbose "PASSED: DNS lookup test for host name '$computer'."
        } 
        elseif ($result.count -eq 0) {
            write-host -foregroundcolor RED  "FAILED: DNS lookup test for host name: '$computer'."
            write-host -foregroundcolor RED  "REASON: Unable to resolve '$computer' in DNS."
            write-host -foregroundcolor RED  "ACTION: (1) Make sure management adapter on host '$computer' is configured to register itself in DNS."
            write-host -foregroundcolor RED  "ACTION: (2) Use ipconfig /registerdns to force the computer to re-register."
            $errors++
        }
        else {
            write-host -foregroundcolor RED  "FAILED: DNS lookup test for host name: '$computer'."
            write-host -foregroundcolor RED  "REASON: $computer has more than one entry in DNS this will cause SLB to not function correctly."
            write-host -foregroundcolor RED  "ACTION: (1) Make sure management adapter on host '$computer' is the only adapter configured to register itself in DNS."
            write-host -foregroundcolor RED  "ACTION: (2) Use ipconfig /registerdns on '$computer' to force it to re-register."
            write-host -foregroundcolor RED  "ACTION: (3) Use ipconfig /flushdns to flush entries from this computer's DNS cache."
            write-host -foregroundcolor RED  "ACTION: (4) Verify that only one address is returned from 'resolve-dnsname $computer' cmdlet."
            $errors++
        }

        ##### TEST: Test Host WINRM reachability

        $result = Test-netconnection -computername $computer -commontcpport WINRM -informationlevel Detailed

        if ($result.TcpTestSucceeded) {
            write-verbose "PASSED: WINRM reachability test to '$computer'."
        }
        else {
            write-host -foregroundcolor RED  "FAILED: WINRM reachability test to '$computer'."
            write-host -foregroundcolor RED  "REASON: 'Test-netconnection -computername $computer -commontcpport WINRM' failed."
            write-host -foregroundcolor RED  "ACTION: (1) Verify that WINRM is enabled on '$computer'"
            write-host -foregroundcolor RED  "ACTION: (2) Verify that the firewall on '$computer' is not blocking access to WINRM."
            write-host -foregroundcolor RED  "ACTION: (3) Verify that the DNS entry for '$computer' resolves to the correct name."
            write-host -foregroundcolor RED  "ACTION: (4) Verify that the '$computer' can be reached across the network from this computer."
            write-host -foregroundcolor RED  "ACTION: (5) Verify that the '$computer' is turned on."
            write-host -foregroundcolor RED  "ACTION: (6) Verify that the '$computer' should be used as a Hyper-V host in the config file."
            $errors++
        }            

        ##### TEST: Test host remote powershell

        $ps = GetOrCreate-pssession -computername $Computer -erroraction ignore
        if ($ps -ne $null) {
            $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
        }
        if ($result -eq $Computer) {
            write-verbose "PASSED: Remote powershell test to '$computer'."
        }
        else {
            write-host -foregroundcolor RED  "FAILED: remote powershell test to '$computer'."
            write-host -foregroundcolor RED  "REASON: Unable to successfully issue command: 'Invoke-Command -ComputerName $computer -ScriptBlock { hostname }'"
            write-host -foregroundcolor RED  "ACTION: (1) Verify that the current user has permission to log into '$computer' via remote powershell."
            write-host -foregroundcolor RED  "ACTION: (2) Manually verify that 'Invoke-Command -ComputerName $computer -ScriptBlock { hostname }' is successful and returns '$computer'"
            
            $errors++
        }
    }        

    write-verbose "--------------------------------------------"
    write-verbose "---  Pre-deployment validation complete  ---"
    write-verbose "---     Validation found $("{0:00}" -f $errors) error(s).    ---"
    write-verbose "--------------------------------------------"

    return ($errors -eq 0)
}

function CleanupMOFS
{  
    Remove-Item .\SetHyperVWinRMEnvelope -Force -Recurse 2>$null
    Remove-Item .\DeployVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureNetworkControllerVMs -Force -Recurse 2>$null
    Remove-Item .\ConfigureMuxVMs -Force -Recurse 2>$null
    Remove-Item .\CreateControllerCert -Force -Recurse 2>$null
    Remove-Item .\InstallControllerCerts -Force -Recurse 2>$null
    Remove-Item .\EnableNCTracing -Force -Recurse 2>$null
    Remove-Item .\DisableNCTracing -Force -Recurse 2>$null    
    Remove-Item .\ConfigureNetworkControllerCluster -Force -Recurse 2>$null
    Remove-Item .\ConfigureGatewayPoolsandPublicIPAddress -Force -Recurse 2>$null
    Remove-Item .\ConfigureSLBMUX -Force -Recurse 2>$null
    Remove-Item .\ConfigureGatewayVMs -Force -Recurse 2>$null
    Remove-Item .\AddGatewayNetworkAdapters -Force -Recurse 2>$null
    Remove-Item .\ConfigureGatewayNetworkAdapterPortProfiles -Force -Recurse 2>$null
    Remove-Item .\ConfigureGateway -Force -Recurse 2>$null
    Remove-Item .\CopyToolsAndCerts -Force -Recurse 2>$null
    Remove-Item .\CleanUp -Force -Recurse 2>$null
    Remove-Item .\ConfigureSLBHostAgent -Force -Recurse 2>$null
    Remove-Item .\ConfigureServers -Force -Recurse 2>$null
    Remove-Item .\ConfigureHostAgent -Force -Recurse 2>$null
    Remove-ITem .\ConfigureHostNetworkingPreNCSetup -Force -Recurse 2>$null 
    Remove-ITem .\ConfigureIDns -Force -Recurse 2>$null
    Remove-ITem .\ConfigureIDnsProxy -Force -Recurse 2>$null 
}

function CompileDSCResources
{
    SetHyperVWinRMEnvelope -ConfigurationData $ConfigData -verbose
    DeployVMs -ConfigurationData $ConfigData -verbose
    ConfigureNetworkControllerVMs -ConfigurationData $ConfigData -verbose
    ConfigureMuxVMs -ConfigurationData $ConfigData -verbose
    CreateControllerCert -ConfigurationData $ConfigData -verbose
    InstallControllerCerts -ConfigurationData $ConfigData -verbose
    EnableNCTracing -ConfigurationData $ConfigData -verbose
    DisableNCTracing -ConfigurationData $Configdata -verbose
    ConfigureNetworkControllerCluster -ConfigurationData $ConfigData -verbose
    ConfigureGatewayPoolsandPublicIPAddress -ConfigurationData $ConfigData -verbose
    ConfigureSLBMUX -ConfigurationData $ConfigData -verbose 
    ConfigureGatewayVMs -ConfigurationData $ConfigData -verbose
    AddGatewayNetworkAdapters -ConfigurationData $ConfigData -verbose 
    ConfigureGatewayNetworkAdapterPortProfiles  -ConfigurationData $ConfigData -verbose 
    ConfigureGateway -ConfigurationData $ConfigData -verbose
    CopyToolsAndCerts -ConfigurationData $ConfigData -verbose
    CleanUp -ConfigurationData $ConfigData -verbose
    ConfigureServers -ConfigurationData $ConfigData -verbose
    ConfigureHostNetworkingPreNCSetup -ConfigurationData $ConfigData -verbose   
    ConfigureIDns -ConfigurationData $ConfigData -verbose 
    ConfigureIDnsProxy -ConfigurationData $ConfigData -verbose
}



if ($psCmdlet.ParameterSetName -ne "NoParameters") {

    $global:stopwatch = [Diagnostics.Stopwatch]::StartNew()

    switch ($psCmdlet.ParameterSetName) 
    {
        "ConfigurationFile" {
            Write-Verbose "Using configuration from file [$ConfigurationDataFile]"
            $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
        }
        "ConfigurationData" {
            Write-Verbose "Using configuration passed in from parameter"
            $configdata = $configurationData 
        }
    }

    $originalExecutionPolicy = Get-ExecutionPolicy

    try
    {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
        Set-Item WSMan:\localhost\MaxEnvelopeSizekb -Value 7000

        write-verbose "STAGE 1: Housekeeping"

        CheckCompatibility -ScriptVer $ScriptVersion -ConfigVer $configData.AllNodes[0].ConfigFileVersion
        CleanupMOFS
        PopulateDefaults $ConfigData.AllNodes

        klist purge | out-null  #clear kerberos ticket cache 
        Clear-DnsClientCache    #clear DNS cache in case IP address is stale

        if (!$skipvalidation) {
            $valid = PreDeploymentValidation $configdata.AllNodes
            if (!$valid) {
                write-verbose "Exiting due to validation errors.  Use -skipvalidation to ignore errors."
                Exit
            }
        }

        if (!$skipDeployment) {
            write-verbose "STAGE 2.1: Compile DSC resources"

            CompileDSCResources
        
            write-verbose "STAGE 2.2: Set WinRM envelope size on hosts"

            Start-DscConfiguration -Path .\SetHyperVWinRMEnvelope -Wait -Force -Verbose -Erroraction Stop
            WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("HyperVHost")) -checkpendingreboot

            write-verbose "STAGE 3: Deploy VMs"

            Start-DscConfiguration -Path .\DeployVMs -Wait -Force -Verbose -Erroraction Stop
            WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController", "SLBMUX", "Gateway"))

            write-verbose "STAGE 4: Install Network Controller nodes"

            Start-DscConfiguration -Path .\ConfigureNetworkControllerVMs -Wait -Force -Verbose -Erroraction Stop
            Start-DscConfiguration -Path .\ConfigureMuxVMs -Wait -Force -Verbose -Erroraction Stop
            
            WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("NetworkController", "SLBMUX")) -CheckPendingReboot 

            write-verbose "STAGE 5.1: Generate controller certificates"
            
            Start-DscConfiguration -Path .\CreateControllerCert -Wait -Force -Verbose -Erroraction Stop

            write-verbose "STAGE 5.2: Gather controller certificates"
            
            GatherCerts -ConfigData $ConfigData

            write-verbose "STAGE 6: Distribute Tools and Certs to all nodes"

            Start-DscConfiguration -Path .\CopyToolsAndCerts -Wait -Force -Verbose -Erroraction Stop

            write-verbose "STAGE 7: Install controller certificates"

            Start-DscConfiguration -Path .\InstallControllerCerts -Wait -Force -Verbose -Erroraction Stop

            write-verbose "STAGE 8: Configure Hyper-V host networking (Pre-NC)"

            Start-DscConfiguration -Path .\ConfigureHostNetworkingPreNCSetup -Wait -Force -Verbose -Erroraction Stop
        
            try
            {

                write-verbose "STAGE 9.1: Configure NetworkController cluster"
                
                Start-DscConfiguration -Path .\EnableNCTracing -Wait -Force  -Verbose -Erroraction Ignore
                Start-DscConfiguration -Path .\ConfigureNetworkControllerCluster -Wait -Force -Verbose -Erroraction Stop

                write-verbose "STAGE 9.2: ConfigureGatewayPools and PublicIPAddress"        
                Start-DscConfiguration -Path .\ConfigureGatewayPoolsandPublicIPAddress -Wait -Force -Verbose -Erroraction Stop
                
                write-verbose ("Importing NC Cert to trusted root store of deployment machine" )
                $scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
                . "$($scriptPath)\certhelpers.ps1"
                AddCertToLocalMachineStore "$($configData.AllNodes[0].installsrcdir)\$($configData.AllNodes[0].certfolder)\$($configData.AllNodes[0].NetworkControllerRestName)" "Root"

                if (![string]::IsNullOrEmpty($configData.AllNodes[0].iDNSCredentialResourceId)) {
                    write-verbose "STAGE 10.1: Configure IDNS on NC"
                    ConfigureIDns -ConfigurationData $ConfigData -verbose
                    Start-DscConfiguration -Path .\ConfigureIDns -Wait -Force -Verbose -ErrorAction Stop

                    write-verbose "STAGE 10.2: Configure Host for IDNS"
                    ConfigureIDnsProxy -ConfigurationData $ConfigData -verbose
                    Start-DscConfiguration -Path .\ConfigureIDnsProxy -Wait -Force -Verbose -ErrorAction Stop
                }

                write-verbose "STAGE 11: Configure Hyper-V host networking (Post-NC)"
                write-verbose "STAGE 11: Configure Servers and HostAgents"

                ConfigureSLBHostAgent -ConfigurationData $ConfigData -verbose
                Start-DscConfiguration -Path .\ConfigureSLBHostAgent -Wait -Force -Verbose -Erroraction Stop

                Start-DscConfiguration -Path .\ConfigureServers -Wait -Force -Verbose -Erroraction Stop

                ConfigureHostAgent -ConfigurationData $ConfigData -verbose
                Start-DscConfiguration -Path .\ConfigureHostAgent -Wait -Force -Verbose -Erroraction Stop
            
                write-verbose "STAGE 12: Configure SLBMUXes"
                
                if ((Get-ChildItem .\ConfigureSLBMUX\).count -gt 0) {
                    Start-DscConfiguration -Path .\ConfigureSLBMUX -wait -Force -Verbose -Erroraction Stop
                } else {
                    write-verbose "No muxes defined in configuration."
                }
            
                write-verbose "STAGE 13: Configure Gateways"
                if ((Get-ChildItem .\ConfigureGateway\).count -gt 0) {

                    write-verbose "STAGE 13.1: Configure Gateway VMs"

                    Start-DscConfiguration -Path .\ConfigureGatewayVMs -Wait -Force -Verbose -Erroraction Stop

                    write-verbose "STAGE 13.2: Add additional Gateway Network Adapters"
            
                    Start-DscConfiguration -Path .\AddGatewayNetworkAdapters -Wait -Force -Verbose -Erroraction Stop
                    WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("Gateway"))

                    # This is a quick fix to make sure we get stable PS Sessions for GW VMs
                    RestartRoleMembers -ConfigData $ConfigData -RoleNames @("Gateway") -Wait -Force
                    WaitForComputerToBeReady -ComputerName $(GetRoleMembers $ConfigData @("Gateway"))

                    Write-verbose "Sleeping for 60 sec before starting Gateway configuration"
                    Sleep 60
                    
                    write-verbose "STAGE 13.3: Configure Gateways"

                    Start-DscConfiguration -Path .\ConfigureGateway -wait -Force -Verbose -Erroraction Stop
                    
                    Write-verbose "Sleeping for 30 sec before plumbing the port profiles for Gateways"
                    Sleep 30
                    
                    write-verbose "STAGE 13.4: Configure Gateway Network Adapter Port profiles"

                    Start-DscConfiguration -Path .\ConfigureGatewayNetworkAdapterPortProfiles -wait -Force -Verbose -Erroraction Stop
                } else {
                    write-verbose "No gateways defined in configuration."
                }
            }
            catch {
                Write-Verbose "Exception: $_"
                throw
            }
            finally
            {
                Write-Verbose "Disabling tracing for NC."
                Start-DscConfiguration -Path .\DisableNCTracing -Wait -Force -Verbose -Erroraction Ignore
            }

            Write-Verbose "Cleaning up."
            Start-DscConfiguration -Path .\CleanUp -Wait -Force -Verbose -Erroraction Ignore

            CleanupMOFS
        }
        else {
            write-verbose "Exiting due to -SkipDeployment being specified on command line."
        }

        $global:stopwatch.stop()
        write-verbose "TOTAL RUNNING TIME: $($global:stopwatch.Elapsed.ToString())"
    }
    finally {
        Set-ExecutionPolicy -ExecutionPolicy $originalExecutionPolicy -Scope Process
    }
}
=======
write-SDNExpressLog "SDN Express deployment complete."
>>>>>>> upstream01/master
