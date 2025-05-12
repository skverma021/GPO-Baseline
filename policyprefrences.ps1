# Define the registry values to check (from your file)
$registryChecks = @(
    @{
        Policy = "Internet Explorer Settings";
        Section = "AutoConfig";
        Path = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel";
        ValueName = "AutoConfig";
        ExpectedValue = 1;
        ValueType = "DWORD";
        GPO = "Internet Explorer Policies"
    },
    @{
        Policy = "Internet Settings";
        Section = "AutoConfigURL";
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        ValueName = "AutoConfigURL";
        ExpectedValue = "";
        ValueType = "SZ";
        GPO = "Internet Settings Policies"
    },
    @{
        Policy = "Internet Settings";
        Section = "AutoConfigURL";
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
        ValueName = "AutoConfigURL";
        ExpectedValue = "";
        ValueType = "SZ";
        GPO = "Internet Settings Policies"
    },
    @{
        Policy = "Internet Settings";
        Section = "AutoDetect";
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        ValueName = "AutoDetect";
        ExpectedValue = 0;
        ValueType = "DWORD";
        GPO = "Internet Settings Policies"
    },
    @{
        Policy = "Internet Explorer Settings";
        Section = "Proxy";
        Path = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel";
        ValueName = "Proxy";
        ExpectedValue = 1;
        ValueType = "DWORD";
        GPO = "Internet Explorer Policies"
    },
    @{
        Policy = "Internet Settings";
        Section = "ProxyEnable";
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        ValueName = "ProxyEnable";
        ExpectedValue = 0;
        ValueType = "DWORD";
        GPO = "Internet Settings Policies"
    },
    @{
        Policy = "Event Log";
        Section = "Windows PowerShell Log Size";
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell";
        ValueName = "MaxSize";
        ExpectedValue = 134217728;
        ValueType = "DWORD";
        GPO = "Event Log Policies"
    },
    @{
        Policy = "Event Log";
        Section = "Windows PowerShell Log Security";
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell";
        ValueName = "CustomSD";
        ExpectedValue = "O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x1;;;S-1-5-32-573)";
        ValueType = "SZ";
        GPO = "Event Log Policies"
    },
    @{
        Policy = "Event Log";
        Section = "PowerShell Operational Log Size";
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational";
        ValueName = "MaxSize";
        ExpectedValue = 134217728;
        ValueType = "DWORD";
        GPO = "Event Log Policies"
    },
    @{
        Policy = "Event Log";
        Section = "PowerShell Operational Log Security";
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational";
        ValueName = "ChannelAccess";
        ExpectedValue = "O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x1;;;S-1-5-32-573)";
        ValueType = "SZ";
        GPO = "Event Log Policies"
    },
    @{
        Policy = "Memory Management";
        Section = "Feature Settings";
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
        ValueName = "FeatureSettingsOverride";
        ExpectedValue = 72;
        ValueType = "DWORD";
        GPO = "System Performance Policies"
    },
    @{
        Policy = "Memory Management";
        Section = "Feature Settings Mask";
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
        ValueName = "FeatureSettingsOverrideMask";
        ExpectedValue = 3;
        ValueType = "DWORD";
        GPO = "System Performance Policies"
    },
    @{
        Policy = "Security";
        Section = "WDigest";
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
        ValueName = "UseLogonCredential";
        ExpectedValue = 0;
        ValueType = "DWORD";
        GPO = "Security Policies"
    },
    @{
        Policy = "Telemetry";
        Section = "Data Collection";
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection";
        ValueName = "AllowTelemetry";
        ExpectedValue = 0;
        ValueType = "DWORD";
        GPO = "Privacy Policies"
    }
)

# Function to check registry values
function Test-RegistryValue {
    param (
        [string]$Path,
        [string]$ValueName,
        $ExpectedValue,
        [string]$ValueType
    )

    try {
        $regValue = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop
        
        switch ($ValueType) {
            "DWORD" {
                $currentValue = [int]$regValue.$ValueName
                return $currentValue -eq $ExpectedValue
            }
            "SZ" {
                $currentValue = $regValue.$ValueName
                return $currentValue -eq $ExpectedValue
            }
            default {
                return $false
            }
        }
    }
    catch {
        return $false
    }
}

# Check each registry value and collect results
$results = @()

foreach ($check in $registryChecks) {
    $status = Test-RegistryValue -Path $check.Path -ValueName $check.ValueName -ExpectedValue $check.ExpectedValue -ValueType $check.ValueType
    
    try {
        $currentValue = (Get-ItemProperty -Path $check.Path -Name $check.ValueName -ErrorAction Stop).$check.ValueName
    }
    catch {
        $currentValue = "Not Found"
    }
    
    $result = [PSCustomObject]@{
        Policy = $check.Policy
        Section = $check.Section
        Path = $check.Path
        ExpectedValue = $check.ExpectedValue
        CurrentValue = $currentValue
        Status = if ($status) { "Compliant" } else { "Non-Compliant" }
        GPO = $check.GPO
    }
    
    $results += $result
}

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "RegistryPolicyValidation_$timestamp.csv"
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "Validation completed. Results saved to $outputFile"