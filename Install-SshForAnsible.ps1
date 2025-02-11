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

function Install-SshServer() {
    $SshServerPackageName = "OpenSSH.Server~~~~0.0.1.0"
    try {
        Add-WindowsCapability -Online -Name $SshServerPackageName -ErrorAction Stop | Out-Null
    } catch {
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
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [string[]]$LinesToAdd
    )
    $Text += $LinesToAdd
    return $Text
}

function Remove-LinesFromText() {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text,
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
    Copy-Item -Path $SshdConfigPath -Destination "$($SshdConfigPath).bak"
    $SshdConfig = Get-Content $SshdConfigPath
    Write-Host $SshdConfig.GetType()

    $LinesToRemove = @(
        '^PubkeyAuthentication',
        '^ChallengeResponseAuthentication',
        '^PasswordAuthentication',
        '^PermitEmptyPasswords',
        '^#MaxAuthTries',
        '^MaxAuthTries',
        '^#MaxSessions',
        '^MaxSessions'
    )
    if ($SshPortNumber -ne 22) {
        $LinesToRemove += "#Port 22"
    }
    $SshdConfig = Remove-LinesFromText -Text $SshdConfig -LinesToRemove $LinesToRemove

    Write-Host $SshdConfig.GetType()
    $LinesToAdd = @(
        'PubkeyAuthentication yes',
        'ChallengeResponseAuthentication no',
        'PasswordAuthentication no',
        'PermitEmptyPasswords yes',
        'MaxAuthTries 6',
        'MaxSessions 10'
    )
    if ($SshPortNumber -ne 22) {
        $LinesToAdd += "Port $($SshPortNumber)"
    }
    $SshdConfig = Add-LinesToText -Text $SshdConfig -LinesToAdd $LinesToAdd
    Write-Host $SshdConfig.GetType()
    
    $SshdConfig | Set-Content $SshdConfigPath
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
        New-ItemProperty @shellParams -ErrorAction Stop 2>$null
    } catch {
        Write-Error "Failed to set default shell to PowerShell in Registry: $_"
        Exit
    }
}

if (-not(Test-RunningScriptAsAdmin)) {
    Write-Error "This script must be run with administrator privileges.  Exiting..."
    Exit
}

Write-Host "Installing SSH Server..."
Install-SshServer

Write-Host "Starting SSH Server Service..."
Enable-SshServerService

$RuleName = Get-FirewallRuleNameFromSshPort -SshPortNumber $SshPortNumber
if (-not(Test-FirewallRuleExists -RuleName $RuleName)) {
    Write-Host "Firewall Rule '$($RuleName)' does not exist, creating it..."
    Set-FirewallAllowTcpInbound -PortNumber $SshPortNumber -RuleName $RuleName
}
else {
    Write-Host "Firewall rule '$($RuleName)' already exists."
}

for ($i=1; $i -le 10; $i++) {
    if (-not(Test-AuthorizedKeysFileExists)) {
        Write-Host "authorized keys has not yet been created. Sleeping..."
        Start-Sleep -Seconds 1
    }
    else {
        break
    }
}
for ($i=1; $i -le 10; $i++) {
    if (-not(Test-SshdConfigFileExists)) {
        Write-Host "sshd_config file has not yet been created. Sleeping..."
        Start-Sleep -Seconds 1
    }
    else {
        break
    }
}

if (-not(Test-PubKeyInAuthorizedKeysFile -AnsibleServerPublicKey $AnsibleServerPublicKey)) {
    Write-Host "Adding Ansible Server public key to the '$($AuthorizedKeysPath)' file."
    Write-PubKeyToAuthorizedKeysFile $AnsibleServerPublicKey
}
else {
    Write-Host "Ansible Server public key already exists in the '$($AuthorizedKeysPath)' file."
}

Write-Host "Configuring SSH config for public key authentication and deny password authentication."
Set-SshdConfig

Write-Host "Setting default shell to PowerShell in Registry."
Set-SshDefaultShellToPowerShell
# SIG # Begin signature block
# MIIb0QYJKoZIhvcNAQcCoIIbwjCCG74CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCocNyyE1vXLW4W
# 942pbD7sLcpmYDc+IgJQppXCwMk5r6CCFhswggMUMIIB/KADAgECAhBA9Su8oTQf
# rkCv+bWIR3brMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF1Bvd2VyU2hlbGwg
# Q29kZSBTaWduaW5nMB4XDTI1MDIxMDE0MzMwNVoXDTI2MDIxMDE0NTMwNVowIjEg
# MB4GA1UEAwwXUG93ZXJTaGVsbCBDb2RlIFNpZ25pbmcwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCvur9MGNjrohG3WpXXjtbv0WwyBE2LgABE1lVnIkWV
# dYMCXUJPuXxQEtyQhBelJvs4BGuQ3s9G6/FQeUcqPnl+GDCkIT0RLzoEAvRRtBuL
# mdv34qrplgwAz0HEG6gh+M6TGiWuAcVdvDPn2jOHxz8eJQumgYJ6sF2wXMCTT/w/
# ZL/7jqBMfJj02MMO2nWzacoPAxL7lpcIMheNi007bUQezzYkm94EkobiGI3LmQsy
# BTaOEhXULKdPEVP9zDFiNr5/gZATYio1S9vS6XeRS67Tb5E7jVZtoibS/5/DygIX
# EFBIhFcJcj8fNMZoiSxdFX9IMavqRjuH6fk4EIbxvFZRAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0SR8HdYi
# HWCSBgcmyIFY5SjiLo0wDQYJKoZIhvcNAQELBQADggEBAKCpHP3xv5mjQxeBIb+e
# bIFtJL9fJN0FMMW533ntX6/CR06RODei/ezYdYiABTkYkMkt/cASGqMOPDWIFwiH
# 8soqYu+RM8TK2kWY5qntqvzRNhD0XOZdEmb8OB0dtiVHZl4XXjPlz4i1GKASOULl
# USvYN6lcNFwLEzpqNh0N6MK1i7w9WW5XRZxASWws96dbyMuhVNX0IP86hd9n23JU
# PZ77h71HKX+EBAd+jtzh32qDOPxC4ySROXviNmGgg2mILMHs//z6xwhLnJqjK6kA
# nBr0fXelmUM8G8Lw6VEi6jEYHCVIxIEZHXH3bBaQps1tsb9ImvpDV7vyIsiVjzmQ
# 3BowggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwggauMIIElqADAgEC
# AhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMw
# MDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0
# MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la
# 9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4r
# gISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/Z
# kIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y
# 3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6ws
# OeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz
# 9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4
# xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB
# 7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhK
# WD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8e
# CXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQAB
# o4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYD
# VR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGsw
# aTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUF
# BzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# Um9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeB
# DAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQi
# AX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+Vc
# W9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/
# q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6Wvep
# ELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoar
# CkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJS
# pzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrk
# nq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f5
# 6PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2Bn
# FqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ
# 8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW
# +6kvRBVK5xMOHds3OBqhK/bt1nz8MIIGvDCCBKSgAwIBAgIQC65mvFq6f5WHxvnp
# BOMzBDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5
# NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTI0MDkyNjAwMDAwMFoXDTM1MTEy
# NTIzNTk1OVowQjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSAwHgYD
# VQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyNDCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAL5qc5/2lSGrljC6W23mWaO16P2RHxjEiDtqmeOlwf0KMCBD
# Er4IxHRGd7+L660x5XltSVhhK64zi9CeC9B6lUdXM0s71EOcRe8+CEJp+3R2O8oo
# 76EO7o5tLuslxdr9Qq82aKcpA9O//X6QE+AcaU/byaCagLD/GLoUb35SfWHh43rO
# H3bpLEx7pZ7avVnpUVmPvkxT8c2a2yC0WMp8hMu60tZR0ChaV76Nhnj37DEYTX9R
# eNZ8hIOYe4jl7/r419CvEYVIrH6sN00yx49boUuumF9i2T8UuKGn9966fR5X6kgX
# j3o5WHhHVO+NBikDO0mlUh902wS/Eeh8F/UFaRp1z5SnROHwSJ+QQRZ1fisD8UTV
# DSupWJNstVkiqLq+ISTdEjJKGjVfIcsgA4l9cbk8Smlzddh4EfvFrpVNnes4c16J
# idj5XiPVdsn5n10jxmGpxoMc6iPkoaDhi6JjHd5ibfdp5uzIXp4P0wXkgNs+CO/C
# acBqU0R4k+8h6gYldp4FCMgrXdKWfM4N0u25OEAuEa3JyidxW48jwBqIJqImd93N
# Rxvd1aepSeNeREXAu2xUDEW8aqzFQDYmr9ZONuc2MhTMizchNULpUEoA6Vva7b1X
# CB+1rxvbKmLqfY/M/SdV6mwWTyeVy5Z/JkvMFpnQy5wR14GJcv6dQ4aEKOX5AgMB
# AAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFJ9X
# LAN3DigVkGalY17uT5IfdqBbMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1l
# U3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAD2tHh92mVvjOIQS
# R9lDkfYR25tOCB3RKE/P09x7gUsmXqt40ouRl3lj+8QioVYq3igpwrPvBmZdrlWB
# b0HvqT00nFSXgmUrDKNSQqGTdpjHsPy+LaalTW0qVjvUBhcHzBMutB6HzeledbDC
# zFzUy34VarPnvIWrqVogK0qM8gJhh/+qDEAIdO/KkYesLyTVOoJ4eTq7gj9UFAL1
# UruJKlTnCVaM2UeUUW/8z3fvjxhN6hdT98Vr2FYlCS7Mbb4Hv5swO+aAXxWUm3Wp
# ByXtgVQxiBlTVYzqfLDbe9PpBKDBfk+rabTFDZXoUke7zPgtd7/fvWTlCs30VAGE
# sshJmLbJ6ZbQ/xll/HjO9JbNVekBv2Tgem+mLptR7yIrpaidRJXrI+UzB6vAlk/8
# a1u7cIqV0yef4uaZFORNekUgQHTqddmsPCEIYQP7xGxZBIhdmm4bhYsVA6G2WgNF
# YagLDBzpmk9104WQzYuVNsxyoVLObhx3RugaEGru+SojW4dHPoWrUhftNpFC5H7Q
# EY7MhKRyrBe7ucykW7eaCuWBsBb4HOKRFVDcrZgdwaSIqMDiCLg4D+TPVgKx2EgE
# deoHNHT9l3ZDBD+XgbF+23/zBjeCtxz+dL/9NWR6P2eZRi7zcEO1xwcdcqJsyz/J
# ceENc2Sg8h3KeFUCS7tpFk7CrDqkMYIFDDCCBQgCAQEwNjAiMSAwHgYDVQQDDBdQ
# b3dlclNoZWxsIENvZGUgU2lnbmluZwIQQPUrvKE0H65Ar/m1iEd26zANBglghkgB
# ZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8G
# CSqGSIb3DQEJBDEiBCDDH36osRtbISkMVcQD2Z6KD1CSTBNJLaqcecMZXF9JvTAN
# BgkqhkiG9w0BAQEFAASCAQAewzlXGaqi5itOKBAiP5WDlhGuIIwG0Wy5LHzuFxLa
# a4Dl/s8TD9N9k3uZ2WGqFTKNO+GjVsOXXEhWkk+niSKC9jnOXvlePGhcTcVSIlqG
# iG/u5rSeCDjSrn7ZiohvdqZ+dPlYHeoZfcs+AnrAAU1jJcJGMD3H+vFWvwipMe6r
# RvphAoZLQt3om3CDB+dT9OeOJI5Whg2O6+ulT0nUgCxBF+iSOz2Bkqtbo4FspdiM
# FTVDaNb7GG+i+Py1pFqWs6HhxIqHu1T90B3qmLklCJFS2anY+rKjicEAD968NJ/D
# Xdiakh6AbWrqQzPfUkds9iAMiY6KaFFEzX1gOY9Mb0FtoYIDIDCCAxwGCSqGSIb3
# DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYg
# U0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgB
# ZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkF
# MQ8XDTI1MDIxMTE0NDUwNlowLwYJKoZIhvcNAQkEMSIEIPTtAUr1dOFT3w/v7Cns
# wiSn64N+lLAyWNLDTieymcDLMA0GCSqGSIb3DQEBAQUABIICAI0lX+twjUmhG53H
# UQFeIWmG6ifH5iNcBwADwH9040SXnPAS1PhqWoxSMu5qqH33ke0tMWjmLvzlJIDG
# ulxNSrwxJ4cUijZcqc5INQ/scUJaR1OJ6R1UGt+Mje0eIW2IrAl3qpH2JAM0Ahq1
# +LRuFLOKZPg3GFmGXvaMV54EQo8s6WOJkSlasKMhfFTa6CGNKtqRXNRPy17UjpdM
# aNIt2NU2TCoHrJ7Vdz1ALVYcj2+NFPP+C/j79of77fWrqVijFWXNQ0fXmOV2eDsC
# 4kPQE4N8o8vQemqErnd686051hnRZpxRwGs685sPJobHpiUqjkn49QBEyhPNdv8L
# lmAmlBoksJNF/KUKzLYtBywHboaMTxxeT6ImD32c8iUXHKesCB3tY8BM9v9GjXxd
# 7x2c9JgFeHWv67u6iAIaBiXgkI4XwTotCWGOxNTwxw+FeSlnbi3ly6qx0UJkWAXr
# WYarP3rnDzqxH0xqpkK1GZCCCqVCPgfivHGRdY/k08QzOGV2VRjHrnt6XS2yAG7k
# EY4LvcaEv/saso6YEvMwkD4wtQ6imiWw0LIe7a0/xW1t16Sm40GA4G+yCg8VcSL+
# q1poLNyETfGnvG5JEITyCBdG1e0gAnxJ18KnrH0ryJJWTA0kvEPrQpn39ZnIv6MT
# GVK23dcv1qgaRwgwnuzEKhAEWwCO
# SIG # End signature block
