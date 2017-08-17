

##############################################################################################
# credentials
##############################################################################################
$username = "administrator"
$password = "P@ssw0rd!"
$secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd
# variables  
$vms =      @("DC1","DC2", "App1","App2", "Sql1","Sql2","DSCN1")
$ipadress = @("192.168.0.50","192.168.0.51", "192.168.0.52","192.168.0.53", "192.168.0.54","192.168.0.55","192.168.0.56")
$i=0  #vm increment in hash array
$2GB_template_path="D:\Hyper-V\Template\Win2016_2GB_20GB_HDD\Virtual Machines\1F5CC09B-D967-4BC4-B146-6F4D8A580A4F.vmcx"
$4GB_template_path="D:\Hyper-V\Template\Win2016_4GB_40GB_HDD\Virtual Machines\71CA9206-7F8E-4D04-B812-45C263199337.vmcx" 
##############################################################################################
#export sysprepd images Win2016_4GB_40GB_HDD,Win2016_2GB_20GB_HDD 
# path D:\Hyper-V\Template\
#############################################################################################



function createTemplates_deleteVMs() {

if (!(Test-Path -Path  D:\Hyper-V\Template\ ))
        {
        mkdir -Force D:\Hyper-V\Template\ 
        }
Export-VM -Name Win2016_2GB_20GB_HDD -Path D:\Hyper-V\Template\
Export-VM -Name Win2016_4GB_40GB_HDD -Path D:\Hyper-V\Template\


############################################################################################
#delete vms after sucessfull export
#############################################################################################


STOP-VM -VMNAME Win2016_2GB_20GB_HDD -Turnoff:$true -Confirm:$False
GET-VM -VMName Win2016_2GB_20GB_HDD  | Get-VMHardDiskDrive | Foreach { Remove-item -path $_.Path -Recurse -Force -Confirm:$False}
Remove-VM -VMName Win2016_2GB_20GB_HDD -force

STOP-VM -VMNAME Win2016_4GB_40GB_HDD -Turnoff:$true -Confirm:$False
GET-VM -VMName Win2016_4GB_40GB_HDD  | Get-VMHardDiskDrive | Foreach { Remove-item -path $_.Path -Recurse -Force -Confirm:$False}
Remove-VM -VMName Win2016_4GB_40GB_HDD -force

}
############################################################################################
#i have ssd on C:\ so i am going create stack there in C:\Projects\LAB
#############################################################################################

function deployStack() {

Write-Host -ForegroundColor Yellow "Going to create stack : DC1,DC2, App1, App2, SQL1,SQL2,DSCN1 "

foreach ( $vm in $vms ){
$folderexists = Test-Path "C:\Projects\LAB\$vm"
if ((Test-Path "C:\Projects\LAB\$vm"))
                    {
                        Write-Host "folder exists.. do you want to delete [y/n] "
                         
                        $Readhost = Read-Host " ( y / n ) " 
                        Switch ($ReadHost) 
                         { 
                           Y {      Stop-VM -VMName $vm  -Force
                                    Remove-VM -VMName $vm -Force
                                    Remove-Item -Recurse -Path "C:\Projects\LAB\$vm" -Force
                              } 
                           N {Write-Host "Exiting..";exit} 
                            
                         } 

                    }
}  

foreach ( $vm in $vms )
        {
            mkdir C:\Projects\LAB\$vm
            if(($vm -eq "DC1")-or($vm -eq "DC2")){
            Import-VM -Path $2GB_template_path `
             -Copy -GenerateNewId -VhdDestinationPath C:\Projects\LAB\$vm -VirtualMachinePath C:\Projects\LAB\$vm
             }else {
            Import-VM -Path $4GB_template_path `
             -Copy -GenerateNewId -VhdDestinationPath C:\Projects\LAB\$vm -VirtualMachinePath C:\Projects\LAB\$vm

             }
            Rename-VM -VM (Get-VM   | Where-Object { $_.Path -eq "C:\Projects\LAB\$vm"  }  ) -NewName $vm
      

            Start-VM -VMName $vm
            Start-Sleep -Seconds 55

            Invoke-Command -VMName $vm -Credential $credentials -ArgumentList $vm,$ipadress[$i]   -ScriptBlock { 
  
                 $IP = $args[1]
                $MaskBits = 24 # This means subnet mask = 255.255.255.0
                $Gateway = "192.168.0.254"
                $Dns = "192.168.130.100"
                $IPType = "IPv4"
                # Retrieve the network adapter that you want to configure
                $adapter = Get-NetAdapter | ? {$_.Status -eq "up"}
                # Remove any existing IP, gateway from our ipv4 adapter
                                                If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
 $adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
    }
                If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
                $adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
                }
                 # Configure the IP address and default gateway
                $adapter | New-NetIPAddress `
                 -AddressFamily $IPType `
                 -IPAddress $IP `
                 -PrefixLength $MaskBits `
                 -DefaultGateway $Gateway
                # Configure the DNS client server IP addresses
                $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS 
                
                #enableRDP
                (Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
                (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null
                Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true
                Start-Sleep -Seconds 22
                #write-host -ForegroundColor Yellow " enter new vm name.. : "

 
                 Rename-Computer -NewName $args[0]  -Restart
 
 
 
 }


             $i++

        }
   }


 
    Write-Host -ForegroundColor Yellow "Are the templates already prepared ? : [Y/N] "
    $Readhost = Read-Host " ( y / n ) " 
    Switch ($ReadHost) 
     { 
       Y { deployStack } 
       N { createTemplates_deleteVMs
           deployStack  
       
          } 
       Default {exit} 
     } 

