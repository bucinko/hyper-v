Import-Module Hyper-V 
 
# Take a look at the virtual switches you have available to provide networking
# to the new VM. I have one for my home network already, if you don't you'll
# need to create one with New-VMSwitch.
Get-VMSwitch | Format-Table
#############################################################################################################
#variables
#############################################################################################################
$iso="D:\Projects\WindowsServer2016\ISO\en_windows_server_2016_x64_dvd.ISO"
$virt_switch_name="LAN"
$username = "administrator"
$password = "P@ssw0rd!"
$secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd

#############################################################################################################
# The configuration of our new VM.
$template_2GB_20GBHDD = @{
  "Name" = "Win2016_2GB_20GB_HDD";
  "MemoryStartupBytes" = 2GB;
  "BootDevice" = "VHD";
  "Path" = "D:\Hyper-V";
  "NewVHDSizeBytes" = 20GB;
  "NewVHDPath" = "D:\Projects\template\Win2016_2GB_20GB_HDD\Win2016_2GB_20GB_HDD.vhdx"
  "Generation" = 2;
  "Switch" = $virt_switch_name; # Substitute with the name of your VMSwitch.
}


$template_4GB_40GBHDD = @{
  "Name" = "Win2016_4GB_40GB_HDD";
  "MemoryStartupBytes" = 4GB;
  "BootDevice" = "VHD";
  "Path" = "D:\Hyper-V";
  "NewVHDSizeBytes" = 40GB;
  "NewVHDPath" = "D:\Projects\template\Win2016_4GB_40GB_HDD\Win2016_4GB_40GB_HDD.vhdx"
  "Generation" = 2;
  "Switch" = $virt_switch_name; # Substitute with the name of your VMSwitch.
}
 
# Create the VM for template Win2016_4GB_40GB_HDD and Win2016_2GB_20GB_HDD
$vm1 = New-VM @template_4GB_40GBHDD
$vm2 = New-VM @template_2GB_20GBHDD
 
# Mount our installation media (.iso) on the VM.
Add-VMDvdDrive -VMName Win2016_4GB_40GB_HDD -Path $iso
Add-VMDvdDrive -VMName Win2016_2GB_20GB_HDD -Path $iso

# Start VM
$vm1 | Start-VM
$vm2 | Start-VM

#############################################################################################################
#manual installation have to boot dvd and install win2016
#set administrator password 
#############################################################################################################
#after installation we have to tune installed windows. invoke session with set password


#############################################################################################################

Write-Host -ForegroundColor Yellow " is Win2016_2GB_20GB_HDD and Win2016_4GB_40GB_HDD installed and set administrator password ? "
$answer = Read-Host 

    if ($answer -eq "y" ) 
        { 

            Invoke-Command -VMName Win2016_4GB_40GB_HDD -Credential $credentials   -ScriptBlock {
 
            # Disable UAC by setting the correct registry property.
            New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
 
            # Disable password complexity requirements. There isn't a PowerShell-like way of doing this at the moment, so we have to use secedit to export the
            # configuration, replace a value and reapply it.
            secedit /export /cfg .\secedit.cfg
 
            (Get-Content -Path .\secedit.cfg).Replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File -FilePath .\secedit.cfg
 
            secedit /configure /db C:\Windows\security\local.sdb /cfg .\secedit.cfg /areas SECURITYPOLICY
 
 
            # If you've opted out of using the GUI version of Windows Server you can ignore the below commands.
 
            # Disable shutdown reason dialog.
            New-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonOn -PropertyType DWord -Value 0 -Force
            New-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonUI -PropertyType DWord -Value 0 -Force
            New-ItemProperty -Path "HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonOn -PropertyType DWord -Value 0 -Force
            New-ItemProperty -Path "HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonUI -PropertyType DWord -Value 0 -Force
 
            # Disable ServerManager startup on login.
            New-ItemProperty -Path HKLM:Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWord -Value 1 -Force
 
            # Enable Remote Desktop Connections
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -PropertyType DWord -Value 0 -Force
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

            winrm quickconfig -q
            winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}'
            winrm set winrm/config '@{MaxTimeoutms="1800000"}'
            winrm set winrm/config/service '@{AllowUnencrypted="true"}'
            winrm set winrm/config/service/auth '@{Basic="true"}'
            Set-Service -Name WinRM -StartupType Automatic
 
            }
            Start-Sleep -Seconds 10
           Invoke-Command -VMName Win2016_2GB_20GB_HDD -Credential $credentials   -ScriptBlock {
 
            # Disable UAC by setting the correct registry property.
            New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
 
            # Disable password complexity requirements. There isn't a PowerShell-like way of doing this at the moment, so we have to use secedit to export the
            # configuration, replace a value and reapply it.
            secedit /export /cfg .\secedit.cfg
 
            (Get-Content -Path .\secedit.cfg).Replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File -FilePath .\secedit.cfg
 
            secedit /configure /db C:\Windows\security\local.sdb /cfg .\secedit.cfg /areas SECURITYPOLICY
 
 
            # If you've opted out of using the GUI version of Windows Server you can ignore the below commands.
 
            # Disable shutdown reason dialog.
            New-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonOn -PropertyType DWord -Value 0 -Force
            New-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonUI -PropertyType DWord -Value 0 -Force
            New-ItemProperty -Path "HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonOn -PropertyType DWord -Value 0 -Force
            New-ItemProperty -Path "HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Reliability" -Name ShutdownReasonUI -PropertyType DWord -Value 0 -Force
 
            # Disable ServerManager startup on login.
            New-ItemProperty -Path HKLM:Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWord -Value 1 -Force
 
            # Enable Remote Desktop Connections
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -PropertyType DWord -Value 0 -Force
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

            winrm quickconfig -q
            winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}'
            winrm set winrm/config '@{MaxTimeoutms="1800000"}'
            winrm set winrm/config/service '@{AllowUnencrypted="true"}'
            winrm set winrm/config/service/auth '@{Basic="true"}'
            Set-Service -Name WinRM -StartupType Automatic
 
            }
        }
     else { exit }


#############################################################################################################
# copy unnatenden xml to c:\
#############################################################################################################


$PSSession1 = New-PSSession -VMName "Win2016_4GB_40GB_HDD" -Credential $credentials
$PSSession2 = New-PSSession -VMName "Win2016_2GB_20GB_HDD" -Credential $credentials

Copy-Item -ToSession $PSSession1 -Path .\unattend.xml -Destination C:\ -Force
Copy-Item -ToSession $PSSession2 -Path .\unattend.xml -Destination C:\ -Force



# Generalize the image and shutdown
 Invoke-Command -VMName Win2016_4GB_40GB_HDD -Credential $credentials   -ScriptBlock 
             {
             Set-Location -Path C:\Windows\System32\Sysprep
            .\sysprep.exe /generalize /oobe /unattend:C:/unattend.xml /shutdown
             }
 Invoke-Command -VMName Win2016_2GB_20GB_HDD -Credential $credentials   -ScriptBlock 
             {
            Set-Location -Path C:\Windows\System32\Sysprep
            .\sysprep.exe /generalize /oobe /unattend:C:/unattend.xml /shutdown
             }


################################################################################################
#templates created
################################################################################################