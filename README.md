# AnsibleSetupWindows
Configures a Windows workstation or server to be managed by Ansible over SSH with minimal effort using PowerShell.
`Install-SshForAnsible.ps1` configures the SSH Server on Windows for public key authentication and denies SSH password authentication.  By default the SSH port is "22" but there is a parameter to change it to a TCP port of your choosing.  Run `Get-Help .\Install-SshForAnsible.ps1` for more details about script usage.
`Add-AnsibleLocalAdmin.ps1` adds a local admin for Ansible to use as a service account.  By default the username is "ansible" but there is a parameter for the script if you wish to change it.  If Ansible will be using an existing local or domain admin account you don't have to run this script. Run `Get-Help .\Add-AnsibleLocalAdmin.ps1` for more details about script usage.

## Instructions

### Enable SSH on a Windows computer

1. Open PowerShell with the "Run as Administrator" option.
2. Download the `Install-SshForAnsible.ps1` script.
```powershell
irm https://raw.githubusercontent.com/ManzellaTech/AnsibleSetupWindows/refs/heads/main/Install-SshForAnsible.ps1 | Set-Content Install-SshForAnsible.ps1
```
3. Review the script unless you're comfortable running arbitrary code written by strangers on the internet.
4. Run the script to install and configure SSH Server on a Windows computer.
```powershell
.\Install-SshForAnsible.ps1 -AnsibleServerPublicKey (Get-Content "C:\path\to\ansible\server's\public\key\ansible_ed25519.pub")
```

### Add Ansible service account

Adds an 'ansible' local admin service account.  These steps are not necessary if you're planning to use an existing domain or local admin account.  
1. Open PowerShell with the "Run as Administrator" option.
2. Download the `Add-AnsibleLocalAdmin.ps1` script.
```powershell
irm https://raw.githubusercontent.com/ManzellaTech/AnsibleSetupWindows/refs/heads/main/Add-AnsibleLocalAdmin.ps1 | Set-Content Add-AnsibleLocalAdmin.ps1
```
3. Review the script unless you're comfortable running arbitrary code written by strangers on the internet.
4. Run the script to create the 'ansible' local admin service account.
```powershell
.\Add-AnsibleLocalAdmin -PasswordSecureString (Read-Host -AsSecureString)
```

## Ansible host_vars example

On the Ansible server create a file in `group_vars` or `host_vars` for the Windows computer.  Example content:
```yaml
ansible_connection: ssh
ansible_ssh_private_key_file: ~/.ssh/ansible_ed25519.pub
ansible_shell_type: powershell
ansible_user: ansible
ansible_password: example_password!_replace_this_with_your_desired_password!
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