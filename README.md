# AnsibleSetupWindows
Configures a Windows workstation or server to be managed by Ansible over SSH.  
`Install-SshForAnsible.ps1` configures the SSH Server on Windows for public key authentication and denies SSH password authentication.  By default the SSH port is "22" but there is a parameter to change it to a TCP port of your choosing.  Run `Get-Help .\Install-SshForAnsible.ps1` for more details about script usage.
`Add-AnsibleLocalAdmin.ps1` adds a local admin for Ansible to use as a service account.  By default the username is "ansible" but there is a parameter for the script if you wish to change it.  If Ansible will be using an existing local or domain admin account you don't have to run this script. Run `Get-Help .\Add-AnsibleLocalAdmin.ps1` for more details about script usage.

## Usage

Configure SSH Server on a Windows computer.
```powershell
.\Install-SshForAnsible.ps1 -AnsibleServerPublicKey (Get-Content "C:\path\to\ansible\server's\public\key\ansible_ed25519.pub")
```

Add an 'ansible' local admin service account.
```powershell
$SecurePassword = ConvertTo-SecureString -String "Example-Password-Do-Not-Use" -AsPlainText -Force
.\Add-AnsibleLocalAdmin -PasswordSecureString $SecurePassword
```

If the scripts do not run due to PowerShell's execution policy you can bypass execution policy by running this command first:  
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

## Compatible Windows Versions

The `Install-SshForAnsible.ps1` script relies on OpenSSH Server being available to be installed with `Add-WindowsCapability`.  
The following versions of Windows can install OpenSSH Server:
- Windows 11
- Windows 10 (starting with 1803)
- Windows Server 2025
- Windows Server 2022
- Windows Server 2019
- Windows Server 2016