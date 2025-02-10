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
    Write-Host "Installing SSH Server..."
    $SshServerPackageName = "OpenSSH.Server~~~~0.0.1.0"
    try {
        Add-WindowsCapability -Online -Name $SshServerPackageName -ErrorAction Stop 2>$null
    } catch {
        Write-Error "Failed to add Windows capability: $_"
        Exit
    }
}

function Enable-SshServerService() {
    Write-Host "Starting SSH Server Service..."
    $SshServerServiceName = 'sshd'
    Start-Service $SshServerServiceName
    Set-Service -Name $SshServerServiceName -StartupType 'Automatic'
}

function Set-FirewallAllowSshInbound() {
    $PortNumber = 22
    $RuleName = "Allow SSH Inbound - TCP $($PortNumber)"
    if (!(Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Host "Firewall Rule '$($RuleName)' does not exist, creating it..."
        try {
            New-NetFirewallRule -Name $RuleName -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $PortNumber  -ErrorAction Stop 2>$null
        } catch {
            Write-Error "Failed to add firewall rule to allow inbound SSH connections on TCP port $($PortNumber): $_"
            Exit
        }
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

function Test-LocalUserExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    
    try {
        $user = Get-LocalUser -Name $Username -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-UserInLocalGroup {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$Group
    )
    
    try {
        $group = Get-LocalGroupMember -Group $Group -ErrorAction Stop
        return ($group.Name -contains $Username)
    } catch {
        return $false
    }
}

function Add-LocalUserAccountForAnsible() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
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

    try {
        New-LocalUser @NewUserParams -ErrorAction Stop 2>$null
    } catch {
        Write-Error "Failed to add local user: $_"
        Exit
    }
}

function Add-LocalUserToAdministrators() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $Group = "Administrators"

    if (Test-UserInLocalGroup -Username $Username -Group $Group) {
        Write-Host "User: $($Username) is already a member of the $($Group) group."
        return
    }

    try {
        Write-Host "Adding user: $($Username) to the $($Group) group."
        Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop 2>$null
    } catch {
        Write-Error "Failed to add user to group: $_"
        Exit
    }
}

function Remove-LocalUserFromUsersGroup() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $Group = "Users"

    if (-not(Test-UserInLocalGroup -Username $Username -Group $Group)) {
        Write-Host "User: $($Username) is not a member of the $($Group) group."
        return
    }

    try {
        Write-Host "Removing user: $($Username) from the $($Group) group."
        Remove-LocalGroupMember -Group "Users" -Member $Username -ErrorAction Stop 2>$null
    }
    catch {
        Write-Error "Failed to remove user from group: $_"
        Exit
    }
}

function Set-SshdConfig() {
    $sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (!(Test-Path $sshdConfigPath)) {
        Write-Error "Error: sshd_config file not found at '$($sshdConfigPath)' foo."
        Exit
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

    $newLines = @(
        'PubkeyAuthentication yes',
        'ChallengeResponseAuthentication no',
        'PasswordAuthentication no',
        'PermitEmptyPasswords yes',
        'MaxAuthTries 6',
        'MaxSessions 10'
    )

    $sshdConfig += $newLines
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
    try {
        Write-Host "Setting default shell to PowerShell in Registry."
        New-ItemProperty @shellParams -ErrorAction Stop 2>$null
    } catch {
        Write-Error "Failed to set default shell to PowerShell in Registry: $_"
        Exit
    }
}

$Username = "ansible"
if (-not(Test-IsAdmin)) {
    Write-Error "This script must be run with administrator privileges.  Exiting..."
    Exit
}
Install-SshServer
Enable-SshServerService
Set-FirewallAllowSshInbound
Write-PubKeyToAuthorizedKeysFile $AnsibleServerPublicKey
if (-not(Test-LocalUserExists -Username $Username)) {
    if ($null -eq $PasswordSecureString) {
        $ClearTextPassword = New-RandomPassword
        $PasswordSecureString = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
        Write-Output $ClearTextPassword
    }
    Add-LocalUserAccountForAnsible -Username $Username -PasswordSecureString $PasswordSecureString 
}
else {
    Write-Host "Local User: $($Username) already exists."
}
Add-LocalUserToAdministrators -Username $Username
Remove-LocalUserFromUsersGroup -Username $Username
Set-SshdConfig
Set-SshDefaultShellToPowerShell