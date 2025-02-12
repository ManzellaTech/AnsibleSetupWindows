<#
.SYNOPSIS
    Script to allow a Windows workstation or server to be configured by Ansible.
    Script installs SSH, adds firewall rules to allow SSH inbound, configures SSH server, and starts SSH Server service.  
.DESCRIPTION
    This script takes in one mandatory parameter, 'AnsibleServerPublicKey', and an optional parameter, 'SshPortNumber'.
    If a parameter 'SshPortNumber' is not passed to this script then it will assign the default of "22".
    SSH is configured for public key authentication.  SSH password authentication is not permitted.
.PARAMETER AnsibleServerPublicKey
    A mandatory parameter of type string.
.PARAMETER SshPortNumber
    An optional parameter of type int.
.EXAMPLE
    .\Install-SshForAnsible.ps1 -AnsibleServerPublicKey (Get-Content ansible_ed25519.pub)
    .\Install-SshForAnsible.ps1 -AnsibleServerPublicKey (Get-Content ansible_ed25519.pub) -SshPortNumber 9182
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$AnsibleServerPublicKey,

    [Parameter(Mandatory = $false)]
    [int]$SshPortNumber = 22
)

function Test-RunningScriptAsAdmin() {
    return (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SshServerInstalled() {
    $SshServerPackageName = "OpenSSH.Server~~~~0.0.1.0"
    $Software = Get-WindowsCapability -Online | Where-Object { $_.Name -eq $SshServerPackageName }
    if ($Software -and $Software.State -eq 'Installed') {
        return $true
    }
    else {
        return $false
    }
}

function Install-SshServer() {
    $SshServerPackageName = "OpenSSH.Server~~~~0.0.1.0"
    try {
        Add-WindowsCapability -Online -Name $SshServerPackageName -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Failed to add Windows capability: $_"
        Exit
    }
}

function Enable-SshServerService() {
    $SshServerServiceName = 'sshd'
    Start-Service $SshServerServiceName
    Set-Service -Name $SshServerServiceName -StartupType 'Automatic'
}

function Restart-SshServerService() {
    $SshServerServiceName = 'sshd'
    Restart-Service $SshServerServiceName
}

function Test-FirewallRuleExists() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RuleName
    )
    if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | Select-Object Name, Enabled) {
        return $true
    }
    else {
        return $false
    }
}

function Get-FirewallRuleNameFromSshPort() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SshPortNumber
    )
    $RuleName = "SSH Inbound Allow - TCP $($SshPortNumber)"
    return $RuleName
}

function Set-FirewallAllowTcpInbound() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PortNumber,

        [Parameter(Mandatory = $true)]
        [string]$RuleName
    )
    try {
        New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $PortNumber  -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to add firewall rule to allow inbound connections on TCP port $($PortNumber): $_"
        Exit
    }
}

function Add-LinesToText() {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Text,
        [Parameter(Mandatory = $true)]
        [string[]]$LinesToAdd
    )
    $Text += $LinesToAdd
    return $Text
}

function Remove-LinesFromText() {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Text,
        [Parameter(Mandatory = $true)]
        [string[]]$LinesToRemove
    )
    foreach ($LineToRemove in $LinesToRemove) {
        $Text = $Text | Where-Object { $_ -notmatch $LineToRemove }
    }
    return $Text
}

function Test-LineExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [string]$LineToFind
    )
    return ($Text -split "`r?`n" -contains $LineToFind)
}

function Test-PubKeyInAuthorizedKeysFile() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AnsibleServerPublicKey
    )
    $AuthorizedKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"
    return Test-LineExists -Text (Get-Content $AuthorizedKeysPath) -LineToFind $AnsibleServerPublicKey
}

function Write-PubKeyToAuthorizedKeysFile() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AnsibleServerPublicKey
    )
    $AuthorizedKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"
    Add-Content -Path $AuthorizedKeysPath -Value $AnsibleServerPublicKey
}
function Test-AuthorizedKeysFileExists() {
    $AuthorizedKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"
    return [System.IO.File]::Exists($AuthorizedKeysPath)
}
function Test-SshdConfigFileExists() {
    $SshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    return [System.IO.File]::Exists($SshdConfigPath)
}

function Update-LinesInString() {
    param (
        [string]$Text,
        [hashtable]$Replacements  # Key: Start of line, Value: Replacement text
    )
    for ($i = 0; $i -lt $Text.Length; $i++) {
        foreach ($key in $Replacements.Keys) {
            if ($Text[$i] -match "^$key") {
                $Text[$i] = $Replacements[$key]
                break
            }
        }
    }
    return $Text
}

function Set-SshdConfig() {
    param (
        [Parameter(Mandatory = $false)]
        [string]$SshPortNumber = 22
    )

    $SshdConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (!(Test-Path $SshdConfigPath)) {
        Write-Error "Error: sshd_config file not found at '$($SshdConfigPath)'."
        Exit
    }
    $SshdConfigPathBackup = "$($SshdConfigPath).original.bak"
    if (-not(Test-Path -Path $SshdConfigPathBackup)) {
        Copy-Item -Path $SshdConfigPath -Destination $SshdConfigPathBackup
    }
    $SshdConfig = Get-Content $SshdConfigPath

    $Replacements = @{
        "^PubkeyAuthentication" = "PubkeyAuthentication yes";
        "^ChallengeResponseAuthentication" = "ChallengeResponseAuthentication no";
        "^PasswordAuthentication" = "PasswordAuthentication no";
        "^PermitEmptyPasswords" = "PermitEmptyPasswords yes";
        "^#MaxAuthTries" = "MaxAuthTries 6";
        "^MaxAuthTries" = "MaxAuthTries 6";
        "^MaxSessions" = "MaxSessions 10";
        "^#MaxSessions" = "MaxSessions 10";
    }

    $UpdatedSshdConfig = Replace-LinesInFile -Text $SshdConfig -Replacements $Replacements
    $UpdatedSshdConfig | Set-Content $SshdConfigPath
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
        New-ItemProperty @shellParams -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to set default shell to PowerShell in Registry: $_"
        Exit
    }
}

if (-not(Test-RunningScriptAsAdmin)) {
    Write-Error "This script must be run with administrator privileges.  Exiting..."
    Exit
}

if (-not(Test-SshServerInstalled)) {
    Write-Host "Installing SSH Server..."
    Install-SshServer
}
else {
    Write-Host "SSH Server is already installed."
}

Write-Host "Starting SSH Server Service and setting startup type to 'Automatic'..."
Enable-SshServerService

$RuleName = Get-FirewallRuleNameFromSshPort -SshPortNumber $SshPortNumber
if (-not(Test-FirewallRuleExists -RuleName $RuleName)) {
    Write-Host "Firewall Rule '$($RuleName)' does not exist, creating it..."
    Set-FirewallAllowTcpInbound -PortNumber $SshPortNumber -RuleName $RuleName
}
else {
    Write-Host "Firewall rule '$($RuleName)' already exists."
}

if ((-not(Test-AuthorizedKeysFileExists)) -or (-not(Test-PubKeyInAuthorizedKeysFile -AnsibleServerPublicKey $AnsibleServerPublicKey))) {
    Write-Host "Adding Ansible Server public key to the 'administrators_authorized_keys' file."
    Write-PubKeyToAuthorizedKeysFile $AnsibleServerPublicKey
}
else {
    Write-Host "Ansible Server public key already exists in the 'administrators_authorized_keys' file."
}

Write-Host "Configuring SSH config for public key authentication and deny password authentication."
Set-SshdConfig -SshPortNumber $SshPortNumber
if ($SshPortNumber -ne 22) {
    Restart-SshServerService
}

Write-Host "Setting default shell to PowerShell in Registry."
Set-SshDefaultShellToPowerShell