# Define the expected policies and settings
$expectedPolicies = @{
    "Access Credential Manager as a trusted caller" = ""
    "Access this computer from the network" = "NT AUTHORITY\Authenticated Users, BUILTIN\Administrators"
    "Account lockout duration" = "30 minutes"
    "Account lockout threshold" = "5 invalid logon attempts"
    "Accounts: Block Microsoft accounts" = "Users can't add or log on with Microsoft accounts"
    "Accounts: Guest account status" = "Disabled"
    "Accounts: Limit local account use of blank passwords to console logon only" = "Enabled"
    "Accounts: Rename administrator account" = "wilsonjp"
    "Accounts: Rename guest account" = "jameskm"
    "Act as part of the operating system" = ""
    "Adjust memory quotas for a process" = "BUILTIN\Administrators, NT AUTHORITY\LOCAL SERVICE, NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\SERVICE"
    "Allow log on locally" = "BUILTIN\Administrators"
    "Allow log on through Terminal Services" = "BUILTIN\Remote Desktop Users, BUILTIN\Administrators"
    "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" = "Enabled"
    "Audit: Shut down system immediately if unable to log security audits" = "Disabled"
    "Back up files and directories" = "BUILTIN\Administrators"
    "Bypass traverse checking" = "NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE, BUILTIN\Backup Operators, NT AUTHORITY\Authenticated Users, BUILTIN\Administrators"
    "Change the system time" = "BUILTIN\Administrators, NT AUTHORITY\LOCAL SERVICE"
    "Change the time zone" = "BUILTIN\Administrators, NT AUTHORITY\LOCAL SERVICE"
    "Create a pagefile" = "BUILTIN\Administrators"
    "Create a token object" = ""
    "Create global objects" = "NT AUTHORITY\SERVICE, NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE, BUILTIN\Administrators"
    "Create permanent shared objects" = ""
    "Create symbolic links" = "BUILTIN\Administrators"
    "Debug programs" = "BUILTIN\Administrators"
    "Deny access to this computer from the network" = "NT AUTHORITY\Local account and member of Administrators group, BUILTIN\Guests"
    "Deny log on as a batch job" = "BUILTIN\Guests"
    "Deny log on as a service" = "BUILTIN\Guests"
    "Deny log on locally" = "DEV-ENT\GADI-SvcAcctRestrict, BUILTIN\Guests"
    "Deny log on through Terminal Services" = "DEV-ENT\GADI-SvcAcctRestrict, BUILTIN\Guests, NT AUTHORITY\Local account"
    "Devices: Allow undock without having to log on" = "Disabled"
    "Devices: Allowed to format and eject removable media" = "Administrators"
    "Devices: Prevent users from installing printer drivers" = "Enabled"
    "Devices: Restrict CD-ROM access to locally logged-on user only" = "Enabled"
    "Devices: Restrict floppy access to locally logged-on user only" = "Enabled"
    "Domain member: Digitally encrypt or sign secure channel data (always)" = "Enabled"
    "Domain member: Digitally encrypt secure channel data (when possible)" = "Enabled"
    "Domain member: Digitally sign secure channel data (when possible)" = "Enabled"
    "Domain member: Disable machine account password changes" = "Disabled"
    "Domain member: Maximum machine account password age" = "30 days"
    "Domain member: Require strong (Windows 2000 or later) session key" = "Enabled"
    "Enable computer and user accounts to be trusted for delegation" = ""
    "Enforce password history" = "24 passwords remembered"
    "Force shutdown from a remote system" = "BUILTIN\Administrators"
    "Generate security audits" = "NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE"
    "Impersonate a client after authentication" = "NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE, NT AUTHORITY\SERVICE, BUILTIN\Administrators"
    "Increase scheduling priority" = "BUILTIN\Administrators"
    "Interactive logon: Display user information when the session is locked" = "Do not display user information"
    "Interactive logon: Do not require CTRL+ALT+DEL" = "Disabled"
    "Interactive logon: Machine inactivity limit" = "900 seconds"
    "Interactive logon: Number of previous logons to cache (in case domain controller is not available)" = "0 logons"
    "Interactive logon: Require Domain Controller authentication to unlock workstation" = "Disabled"
    "Interactive logon: Smart card removal behavior" = "Lock Workstation"
    "Load and unload device drivers" = "BUILTIN\Administrators"
    "Lock pages in memory" = ""
    "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon" = "0"
    "Manage auditing and security log" = "BUILTIN\Administrators"
    "Maximum password age" = "60 days"
    "Microsoft network client: Digitally sign communications (always)" = "Enabled"
    "Microsoft network client: Digitally sign communications (if server agrees)" = "Enabled"
    "Microsoft network client: Send unencrypted password to third-party SMB servers" = "Disabled"
    "Microsoft network server: Amount of idle time required before suspending session" = "15 minutes"
    "Microsoft network server: Digitally sign communications (always)" = "Enabled"
    "Microsoft network server: Digitally sign communications (if client agrees)" = "Enabled"
    "Microsoft network server: Server SPN target name validation level" = "Accept if provided by client"
    "Minimum password age" = "3 days"
    "Minimum password length" = "14 characters"
    "Modify an object label" = ""
    "Modify firmware environment values" = "BUILTIN\Administrators"
    "Network access: Allow anonymous SID/Name translation" = "Disabled"
    "Network access: Do not allow anonymous enumeration of SAM accounts" = "Enabled"
    "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = "Enabled"
    "Network access: Let Everyone permissions apply to anonymous users" = "Disabled"
    "Network access: Named Pipes that can be accessed anonymously" = ""
    "Network access: Remotely accessible registry paths" = "System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion"
    "Network access: Remotely accessible registry paths and sub-paths" = "Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog"
    "Network access: Restrict anonymous access to Named Pipes and Shares" = "Enabled"
    "Network access: Restrict clients allowed to make remote calls to SAM" = "O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;S-1-5-21-1292428093-1770027372-839522115-1413499)"
    "Network access: Shares that can be accessed anonymously" = ""
    "Network access: Sharing and security model for local accounts" = "Classic - local users authenticate as themselves"
    "Network security: Allow Local System to use computer identity for NTLM" = "Enabled"
    "Network security: Allow LocalSystem NULL session fallback" = "Disabled"
    "Network security: Allow PKU2U authentication requests to this computer to use online identities." = "Disabled"
    "Network security: Do not store LAN Manager hash value on next password change" = "Enabled"
    "Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM"
    "Network security: LDAP client signing requirements" = "Negotiate signing"
    "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" = "Enabled"
    "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" = "Enabled"
    "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" = "Enable auditing for all accounts"
    "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" = "Audit all"
    "Password must meet complexity requirements" = "Enabled"
    "Perform volume maintenance tasks" = "BUILTIN\Administrators"
    "Profile single process" = "BUILTIN\Administrators"
    "Profile system performance" = "BUILTIN\Administrators"
    "Recovery console: Allow automatic administrative logon" = "Disabled"
    "Recovery console: Allow floppy copy and access to all drives and all folders" = "Disabled"
    "Replace a process level token" = "NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE"
    "Require 128-bit encryption" = "Enabled"
    "Require NTLMv2 session security" = "Enabled"
    "Reset account lockout counter after" = "5 minutes"
    "Restore files and directories" = "BUILTIN\Administrators"
    "Shut down the system" = "BUILTIN\Administrators"
    "Shutdown: Allow system to be shut down without having to log on" = "Disabled"
    "Store passwords using reversible encryption" = "Disabled"
    "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" = "Disabled"
    "System objects: Require case insensitivity for non-Windows subsystems" = "Enabled"
    "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" = "Enabled"
    "Take ownership of files or other objects" = "BUILTIN\Administrators, DEV-ENT\Object Recovery"
}

# Initialize results array
$results = @()

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

# Check each policy
foreach ($policy in $expectedPolicies.Keys) {
    $expectedSetting = $expectedPolicies[$policy]
    
    # Get the current setting
    try {
        if ($policy -match "MACHINE\\") {
            # Registry policy
            $regPath = $policy -replace "MACHINE\\", "HKLM:\"
            $regKey = Split-Path $regPath -Parent
            $regValue = Split-Path $regPath -Leaf
            $currentSetting = (Get-ItemProperty -Path $regKey -Name $regValue -ErrorAction Stop).$regValue
        }
        else {
            # Security policy
            $seceditOutput = secedit /export /cfg C:\tempsecpol.cfg /areas SECURITYPOLICY
            $secpolContent = Get-Content C:\tempsecpol.cfg
            Remove-Item C:\tempsecpol.cfg -Force
            
            $policyLine = $secpolContent | Where-Object { $_ -match "^$policy\s*=" }
            if ($policyLine) {
                $currentSetting = ($policyLine -split "=")[1].Trim().Trim('"')
            }
            else {
                $currentSetting = "Not Configured"
            }
        }
    }
    catch {
        $currentSetting = "Error retrieving setting"
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
    
    # Get winning GPO
    $winningGPO = Get-WinningGPO -PolicyName $policy
    
    # Add to results
    $result = [PSCustomObject]@{
        "Policy" = $policy
        "Setting" = $currentSetting
        "Expected Setting" = $expectedSetting
        "Applied Setting" = $currentSetting
        "Status" = $status
        "Winning GPO Name" = $winningGPO
    }
    
    $results += $result
}

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = "C:\Temp\PolicyComplianceReport_$timestamp.csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "Policy compliance report generated at: $outputPath"