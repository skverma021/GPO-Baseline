# Define the expected policies and their registry paths or secedit names
$policyDefinitions = @(
    # User Rights Assignments (from secedit)
    @{Policy="Access Credential Manager as a trusted caller"; SecEditName="SeTrustedCredManAccessPrivilege"; Expected=""},
    @{Policy="Access this computer from the network"; SecEditName="SeNetworkLogonRight"; Expected="NT AUTHORITY\Authenticated Users, BUILTIN\Administrators"},
    @{Policy="Allow log on locally"; SecEditName="SeInteractiveLogonRight"; Expected="BUILTIN\Administrators"},
    @{Policy="Allow log on through Terminal Services"; SecEditName="SeRemoteInteractiveLogonRight"; Expected="BUILTIN\Remote Desktop Users, BUILTIN\Administrators"},
    @{Policy="Back up files and directories"; SecEditName="SeBackupPrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Change the system time"; SecEditName="SeSystemtimePrivilege"; Expected="BUILTIN\Administrators, NT AUTHORITY\LOCAL SERVICE"},
    @{Policy="Create a pagefile"; SecEditName="SeCreatePagefilePrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Debug programs"; SecEditName="SeDebugPrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Deny access to this computer from the network"; SecEditName="SeDenyNetworkLogonRight"; Expected="NT AUTHORITY\Local account and member of Administrators group, BUILTIN\Guests"},
    @{Policy="Deny log on locally"; SecEditName="SeDenyInteractiveLogonRight"; Expected="DEV-ENT\GADI-SvcAcctRestrict, BUILTIN\Guests"},
    @{Policy="Force shutdown from a remote system"; SecEditName="SeRemoteShutdownPrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Load and unload device drivers"; SecEditName="SeLoadDriverPrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Manage auditing and security log"; SecEditName="SeSecurityPrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Restore files and directories"; SecEditName="SeRestorePrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Shut down the system"; SecEditName="SeShutdownPrivilege"; Expected="BUILTIN\Administrators"},
    @{Policy="Take ownership of files or other objects"; SecEditName="SeTakeOwnershipPrivilege"; Expected="BUILTIN\Administrators, DEV-ENT\Object Recovery"},

    # Account Policies (from secedit)
    @{Policy="Account lockout duration"; SecEditName="LockoutDuration"; Expected="30 minutes"},
    @{Policy="Account lockout threshold"; SecEditName="LockoutThreshold"; Expected="5 invalid logon attempts"},
    @{Policy="Reset account lockout counter after"; SecEditName="ResetLockoutCount"; Expected="5 minutes"},
    @{Policy="Enforce password history"; SecEditName="PasswordHistorySize"; Expected="24 passwords remembered"},
    @{Policy="Maximum password age"; SecEditName="MaximumPasswordAge"; Expected="60 days"},
    @{Policy="Minimum password age"; SecEditName="MinimumPasswordAge"; Expected="3 days"},
    @{Policy="Minimum password length"; SecEditName="MinimumPasswordLength"; Expected="14 characters"},
    @{Policy="Password must meet complexity requirements"; SecEditName="PasswordComplexity"; Expected="Enabled"},
    @{Policy="Store passwords using reversible encryption"; SecEditName="ClearTextPassword"; Expected="Disabled"},

    # Security Options (from registry)
    @{Policy="Accounts: Block Microsoft accounts"; RegPath="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; RegValue="NoConnectedUser"; Expected=1; RegType="DWord"},
    @{Policy="Accounts: Guest account status"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; RegValue="UserAccountControl"; Expected=0x15; RegType="DWord"; Transform={if ($_ -band 0x10) { "Disabled" } else { "Enabled" }}},
    @{Policy="Accounts: Limit local account use of blank passwords to console logon only"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; RegValue="LimitBlankPasswordUse"; Expected=1; RegType="DWord"; Transform={if ($_ -eq 1) { "Enabled" } else { "Disabled" }}},
    @{Policy="Accounts: Rename administrator account"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; RegValue="AdministratorAccountName"; Expected="wilsonjp"; RegType="String"},
    @{Policy="Accounts: Rename guest account"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; RegValue="GuestAccountName"; Expected="jameskm"; RegType="String"},
    @{Policy="Interactive logon: Do not require CTRL+ALT+DEL"; RegPath="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; RegValue="DisableCAD"; Expected=0; RegType="DWord"; Transform={if ($_ -eq 1) { "Enabled" } else { "Disabled" }}},
    @{Policy="Interactive logon: Smart card removal behavior"; RegPath="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; RegValue="ScRemoveOption"; Expected="1"; RegType="String"; Transform={switch ($_) { "0" { "No Action" } "1" { "Lock Workstation" } "2" { "Force Logoff" } default { $_ }}}},
    @{Policy="MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon"; RegPath="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; RegValue="AutoAdminLogon"; Expected="0"; RegType="String"},
    @{Policy="Network access: Allow anonymous SID/Name translation"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; RegValue="TurnOffAnonymousBlock"; Expected=0; RegType="DWord"; Transform={if ($_ -eq 1) { "Enabled" } else { "Disabled" }}},
    @{Policy="Network security: LAN Manager authentication level"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; RegValue="LmCompatibilityLevel"; Expected=5; RegType="DWord"; Transform={switch ($_) { 0 { "Send LM & NTLM responses" } 1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" } 2 { "Send NTLM response only" } 3 { "Send NTLMv2 response only" } 4 { "Send NTLMv2 response only\refuse LM" } 5 { "Send NTLMv2 response only\refuse LM & NTLM" } default { $_ }}}},
    @{Policy="System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"; RegPath="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"; RegValue="Enabled"; Expected=0; RegType="DWord"; Transform={if ($_ -eq 1) { "Enabled" } else { "Disabled" }}}
)

# Initialize results array
$results = @()

# Get all security policies once (for secedit policies)
$securityPolicies = @{}
$seceditOutput = secedit /export /cfg $env:TEMP\secpol.cfg /areas SECURITYPOLICY
$secpolContent = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

if ($secpolContent) {
    foreach ($line in $secpolContent) {
        if ($line -match "^\s*([^=]+)\s*=\s*(.*)") {
            $securityPolicies[$matches[1].Trim()] = $matches[2].Trim().Trim('"')
        }
    }
}

# Function to get the winning GPO for a specific policy
function Get-WinningGPO {
    param (
        [string]$PolicyName
    )
    
    try {
        $gpoResult = gpresult /r /scope:computer | Select-String -Pattern $PolicyName -Context 0,5
        if ($gpoResult) {
            $gpoLine = $gpoResult.ToString().Split("`n") | Where-Object { $_ -match "GPO:" }
            if ($gpoLine) {
                return ($gpoLine -split "GPO:")[1].Trim()
            }
        }
        return "Local Policy"
    }
    catch {
        return "Unknown"
    }
}

# Process each policy definition
foreach ($policyDef in $policyDefinitions) {
    $policyName = $policyDef.Policy
    $expectedSetting = $policyDef.Expected
    $currentSetting = $null
    $source = "Unknown"
    
    # Check if it's a registry policy
    if ($policyDef.ContainsKey("RegPath")) {
        try {
            $regValue = Get-ItemProperty -Path $policyDef.RegPath -Name $policyDef.RegValue -ErrorAction Stop | Select-Object -ExpandProperty $policyDef.RegValue
            $source = "Registry"
            
            # Apply transformation if defined
            if ($policyDef.ContainsKey("Transform")) {
                $currentSetting = & $policyDef.Transform $regValue
            } else {
                $currentSetting = $regValue
            }
        } catch {
            $currentSetting = "Not Configured"
        }
    }
    # Otherwise it's a security policy
    elseif ($policyDef.ContainsKey("SecEditName")) {
        if ($securityPolicies.ContainsKey($policyDef.SecEditName)) {
            $currentSetting = $securityPolicies[$policyDef.SecEditName]
            $source = "Security Policy"
        } else {
            $currentSetting = "Not Configured"
        }
    }
    
    # Determine compliance status
    if ($currentSetting -eq $expectedSetting) {
        $status = "Compliant"
    }
    elseif ($expectedSetting -eq "" -and $currentSetting -eq "Not Configured") {
        $status = "Compliant"
    }
    else {
        $status = "NonCompliant"
    }
    
    # Get winning GPO (only for non-compliant policies to save time)
    $winningGPO = if ($status -eq "NonCompliant") { Get-WinningGPO -PolicyName $policyName } else { "N/A" }
    
    # Add to results
    $results += [PSCustomObject]@{
        "Policy" = $policyName
        "Setting" = $currentSetting
        "Expected Setting" = $expectedSetting
        "Applied Setting" = $currentSetting
        "Status" = $status
        "Source" = $source
        "Winning GPO Name" = $winningGPO
    }
}

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = "$env:TEMP\PolicyComplianceReport_$timestamp.csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "Policy compliance report generated at: $outputPath"