<#
.SYNOPSIS
    Script creates a Windows local administrator to be used as a service account for Ansible to manage the computer.
.DESCRIPTION
    This script takes in two optional parameters, 'PasswordSecureString' and 'AnsibleServiceAccountUsername'.
    If a parameter 'PasswordSecureString' is not passed to this script then it will create a random password for the Ansible account and return it as output. 
    If a parameter 'AnsibleServiceAccountUsername' is not passed to this script then it will use the default of "ansible".
.PARAMETER PasswordSecureString
    An optional parameter of type SecureString.
.PARAMETER AnsibleServiceAccountUsername
    A mandatory parameter of type string.
.EXAMPLE
    .\Add-AnsibleLocalAdmin
    $SecurePassword = ConvertTo-SecureString -String "ExamplePasswordDoNotUseInProduction" -AsPlainText -Force; .\Add-AnsibleLocalAdmin -PasswordSecureString $SecurePassword
    .\Add-AnsibleLocalAdmin -AnsibleServiceAccountUsername "AliceAnAnsibleAdministrator"
#>

param (
    [Parameter(Mandatory = $false)]
    [SecureString]$PasswordSecureString,

    [Parameter(Mandatory = $false)]
    [string]$AnsibleServiceAccountUsername = "ansible"
)

function Test-RunningScriptAsAdmin() {
    return (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ComputerName() {
    return (Get-CimInstance -ClassName Win32_ComputerSystem).Name
}

function Test-LocalUserExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    
    try {
        Get-LocalUser -Name $Username -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
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
    
    $FullUsername = "$(Get-ComputerName)\$($Username)"
    try {
        $group = Get-LocalGroupMember -Group $Group -ErrorAction Stop
        return ($group.Name -contains $FullUsername)
    }
    catch {
        Write-Error "Unable to check $($Group) group membership: $_"
        Exit
    }
}
function Test-UserInLocalAdministrators {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $Group = "Administrators" 
    return Test-UserInLocalGroup -Username $Username -Group $Group
}

function Test-UserInLocalUsers {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $Group = "Users" 
    return Test-UserInLocalGroup -Username $Username -Group $Group
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
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [SecureString]$PasswordSecureString
    )
    $FullName = (Get-Culture).TextInfo.ToTitleCase($Username.ToLower())
    $Description = "Ansible Service Account"
    $NewUserParams = @{
        Name = $Username
        Password = $PasswordSecureString
        FullName = $FullName
        Description = $Description
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

    try {
        Write-Host "Adding user: $($Username) to the $($Group) group."
        Add-LocalGroupMember -Group $Group -Member $Username -ErrorAction Stop 2>$null
    } catch {
        Write-Error "Failed to add user to $($Group) group: $_"
        Exit
    }
}

function Remove-LocalUserFromUsersGroup() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    $Group = "Users"

    try {
        Write-Host "Removing user: $($Username) from the $($Group) group."
        Remove-LocalGroupMember -Group "Users" -Member $Username -ErrorAction Stop 2>$null
    }
    catch {
        Write-Error "Failed to remove user from group: $_"
        Exit
    }
}

if (-not(Test-RunningScriptAsAdmin)) {
    Write-Error "This script must be run with administrator privileges.  Exiting..."
    Exit
}

if (-not(Test-LocalUserExists -Username $AnsibleServiceAccountUsername)) {
    if ($null -eq $PasswordSecureString) {
        $ClearTextPassword = New-RandomPassword
        $PasswordSecureString = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
        Write-Output $ClearTextPassword
    }
    Write-Host "Adding Ansible local user service account with username: $($AnsibleServiceAccountUsername)"
    Add-LocalUserAccountForAnsible -Username $AnsibleServiceAccountUsername -PasswordSecureString $PasswordSecureString 
}
else {
    Write-Host "Local user: $($AnsibleServiceAccountUsername) already exists."
}

if (-not(Test-UserInLocalAdministrators -Username $AnsibleServiceAccountUsername)) {
    Write-Host "Adding $($AnsibleServiceAccountUsername) to local Administrators group."
    Add-LocalUserToAdministrators -Username $AnsibleServiceAccountUsername
}
else {
    Write-Host "User: $($Username) is already a member of the local Administrators group."
}

if (Test-UserInLocalUsers -Username $AnsibleServiceAccountUsername) {
    Write-Host "Removing $($AnsibleServiceAccountUsername) from local Users group."
    Remove-LocalUserFromUsersGroup -Username $AnsibleServiceAccountUsername
}