<#
.SYNOPSIS
    Script to allow a Windows workstation or server to be configured by Ansible.
    Script adds firewall rules to allow SSH inbound, sets up SSH server, configures public key encryption only for SSH, starts SSH Server service, and creates a Windows local user account for Ansible to use.  
.DESCRIPTION
    This script takes in one mandatory parameter, 'AnsibleServerPublicKey', and an optional parameter, 'PasswordSecureString'.
    If a parameter 'PasswordSecureString' is not passed to this script then it will create a random password for the Ansible account and return it as output. 
.PARAMETER AnsibleServerPublicKey
    A mandatory parameter of type string.
.PARAMETER PasswordSecureString
    An optional parameter of type SecureString.
.EXAMPLE
    .\Install-OpensshAndAnsibleServiceAccount.ps1 -AnsibleServerPublicKey "Ad8239f87239478348908as..."
    $SecurePassword = ConvertTo-SecureString -String "ExamplePassword" -AsPlainText -Force; .\Install-OpensshAndAnsibleServiceAccount.ps1 -AnsibleServerPublicKey "Ad8239f87239478348908as..." -PasswordSecureString $SecurePassword
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$AnsibleServerPublicKey,

    [Parameter(Mandatory = $false)]
    [SecureString]$PasswordSecureString
)

function Test-IsAdmin() {
    return (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-SshServer() {
    $SshServerPackageName = OpenSSH.Server~~~~0.0.1.0
    Add-WindowsCapability -Online -Name $SshServerPackageName
}

function Enable-SshServerService() {
    # Start the sshd service
    $SshServerServiceName = 'sshd'
    Start-Service $SshServerServiceName
    Set-Service -Name $SshServerServiceName -StartupType 'Automatic'
}

function Set-FirewallAllowSshInbound() {
    $RuleName = "Allow SSH Inbound - TCP 22"
    if (!(Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Host "Firewall Rule '$($RuleName)' does not exist, creating it..."
        New-NetFirewallRule -Name $RuleName -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
        Write-Host "Firewall rule '$($RuleName)' already exists."
    }
}

function Write-PubKeyToAuthorizedKeysFile() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AnsibleServerPublicKey
    )
    $AuthorizedKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"
    Add-Content -Path $AuthorizedKeysPath -Value $AnsibleServerPublicKey
}

function New-RandomPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Length = 16
    )
    if ($Length -lt 4) {
        throw "Password length must be at least 4 to satisfy complexity requirements."
    }
    $upperCase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $lowerCase   = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $digits      = "0123456789".ToCharArray()
    $specials    = "!@#$%^&*()-_=+[]{};:,.<>?".ToCharArray()
    $passwordChars = @()
    $passwordChars += $upperCase | Get-Random -Count 1
    $passwordChars += $lowerCase | Get-Random -Count 1
    $passwordChars += $digits    | Get-Random -Count 1
    $passwordChars += $specials  | Get-Random -Count 1
    $allChars = $upperCase + $lowerCase + $digits + $specials
    $remainingLength = $Length - $passwordChars.Count
    for ($i = 0; $i -lt $remainingLength; $i++) {
        $passwordChars += $allChars | Get-Random -Count 1
    }
    $password = ($passwordChars | Sort-Object { Get-Random }) -join ''
    return $password
}

function Add-LocalUserAccountForAnsible() {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$PasswordSecureString
    )
    $Username = "ansible"
    $NewUserParams = @{
        Name = $Username
        Password = $PasswordSecureString
        FullName = "Ansible"
        Description = "Ansible Service Account"
        AccountNeverExpires = $true
        PasswordNeverExpires = $true
    }
    New-LocalUser @NewUserParams
    Add-LocalGroupMember -Group "Administrators" -Member $Username
    Remove-LocalGroupMember -Group "Users" -Member $Username
}

function Set-SshdConfig() {
    $sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (!(Test-Path $sshdConfigPath)) {
        Write-Error "Error: sshd_config file not found at '$($sshdConfigPath)' foo."
        return
    }
    Copy-Item -Path $sshdConfigPath -Destination "$($sshdConfigPath).original.bak"
    $sshdConfig = Get-Content $sshdConfigPath

    # Remove lines
    $removeLines = @(
        '^PubkeyAuthentication',
        '^ChallengeResponseAuthentication',
        '^PasswordAuthentication',
        '^PermitEmptyPasswords',
        '^#MaxAuthTries',
        '^#MaxSessions'
    )
    foreach ($removeLine in $removeLines) {
        $sshdConfig = $sshdConfig | Where-Object { $_ -notmatch $removeLine }
    }

    # Add the new lines to the configuration
    $newLines = @(
        'PubkeyAuthentication yes',
        'ChallengeResponseAuthentication no',
        'PasswordAuthentication no',
        'PermitEmptyPasswords yes',
        'MaxAuthTries 6',
        'MaxSessions 10'
    )

    # Combine the original content with the new lines
    $sshdConfig += $newLines

    # Write the updated content back to the file
    $sshdConfig | Set-Content $sshdConfigPath

    Write-Host "sshd_config file updated successfully."
}

function Set-SshDefaultShellToPowerShell() {
    $shellParams = @{
        Path         = 'HKLM:\SOFTWARE\OpenSSH'
        Name         = 'DefaultShell'
        Value        = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        PropertyType = 'String'
        Force        = $true
    }
    New-ItemProperty @shellParams
}

if (-not(Test-IsAdmin)) {
    Write-Error "This script must be run with administrator privileges.  Exiting..."
    Exit
}
Install-SshServer
Enable-SshServerService
Set-FirewallAllowSshInbound
Write-PubKeyToAuthorizedKeysFile $AnsibleServerPublicKey
if ($null -eq $PasswordSecureString) {
    $ClearTextPassword = New-RandomPassword
    $PasswordSecureString = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
    # If a PasswordSecureString was not provided as a parameter the clear text password of the Ansible local Windows user account will be returned.
    # The password can then be stored (securely) with Ansible for "become" privilege escalation.
    Write-Output $ClearTextPassword
}
Add-LocalUserAccountForAnsible $PasswordSecureString 
Set-SshdConfig
Set-SshDefaultShellToPowerShell