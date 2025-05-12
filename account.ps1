<#
.SYNOPSIS
    Validates applied GPO settings against a baseline and exports results to CSV.
.DESCRIPTION
    This script checks the current computer's applied GPO settings against a baseline configuration
    and exports the comparison results to a CSV file.
.NOTES
    File Name      : Validate-GPOSettings.ps1
    Author         : Your Name
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges
#>

# Parameters
$OutputCSV = "C:\Temp\GPO_Validation_Results.csv"
$BaselineGPO = "Windows_2022_Baseline"  # Name of the baseline GPO to validate against

# Function to get current GPO settings
function Get-CurrentGPOSettings {
    # Get all applied GPOs
    $appliedGPOs = Get-GPResultantSetOfPolicy -ReportType Xml -Computer $env:COMPUTERNAME
    
    # Extract settings from the applied GPOs
    $settings = @()
    
    # Process Computer Configuration settings
    $computerSettings = $appliedGPOs.GPO.Computer.ExtensionData.Extension
    foreach ($extension in $computerSettings) {
        if ($extension.Type -eq "Registry") {
            foreach ($setting in $extension.Setting) {
                $settings += [PSCustomObject]@{
                    GPO = $appliedGPOs.GPO.Name
                    Section = "Computer Configuration"
                    Policy = $setting.Name
                    Setting = $setting.State
                    Path = $setting.Key
                    Value = $setting.Value
                }
            }
        }
        elseif ($extension.Type -eq "Security") {
            foreach ($setting in $extension.Setting) {
                $settings += [PSCustomObject]@{
                    GPO = $appliedGPOs.GPO.Name
                    Section = "Computer Configuration"
                    Policy = $setting.Name
                    Setting = $setting.State
                    Path = "Security Settings"
                    Value = $setting.Value
                }
            }
        }
    }
    
    # Process User Configuration settings (if needed)
    # Similar logic as above for user settings
    
    return $settings
}

# Function to get baseline GPO settings (from your HTML report)
function Get-BaselineGPOSettings {
    # This is a simplified version - you would need to parse your HTML report
    # Here we're creating a sample baseline for demonstration
    
    $baselineSettings = @(
        # Password Policy
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Enforce password history"
            ExpectedValue = "24 passwords remembered"
            Path = "Account Policies/Password Policy"
        },
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Maximum password age"
            ExpectedValue = "60 days"
            Path = "Account Policies/Password Policy"
        },
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Minimum password length"
            ExpectedValue = "14 characters"
            Path = "Account Policies/Password Policy"
        },
        
        # Account Lockout Policy
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Account lockout duration"
            ExpectedValue = "30 minutes"
            Path = "Account Policies/Account Lockout Policy"
        },
        
        # Security Options
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Accounts: Guest account status"
            ExpectedValue = "Disabled"
            Path = "Local Policies/Security Options/Accounts"
        },
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Interactive logon: Do not require CTRL+ALT+DEL"
            ExpectedValue = "Disabled"
            Path = "Local Policies/Security Options/Interactive Logon"
        },
        
        # Windows Defender Firewall
        [PSCustomObject]@{
            Section = "Computer Configuration"
            Policy = "Windows Defender Firewall: Protect all network connections"
            ExpectedValue = "Enabled"
            Path = "Network/Network Connections/Windows Defender Firewall/Domain Profile"
        }
    )
    
    return $baselineSettings
}

# Main script execution
try {
    # Get current and baseline settings
    $currentSettings = Get-CurrentGPOSettings
    $baselineSettings = Get-BaselineGPOSettings
    
    # Compare settings
    $results = @()
    
    foreach ($baseline in $baselineSettings) {
        $current = $currentSettings | Where-Object {
            $_.Policy -eq $baseline.Policy -and $_.Section -eq $baseline.Section
        }
        
        $status = if ($current) {
            if ($current.Setting -eq $baseline.ExpectedValue) {
                "Compliant"
            } else {
                "Non-Compliant"
            }
        } else {
            "Not Found"
        }
        
        $results += [PSCustomObject]@{
            Policy = $baseline.Policy
            Section = $baseline.Section
            Path = $baseline.Path
            ExpectedValue = $baseline.ExpectedValue
            CurrentValue = if ($current) { $current.Setting } else { "N/A" }
            Status = $status
            GPO = if ($current) { $current.GPO } else { "N/A" }
        }
    }
    
    # Export results to CSV
    $results | Export-Csv -Path $OutputCSV -NoTypeInformation -Force
    
    Write-Host "Validation complete. Results exported to $OutputCSV" -ForegroundColor Green
    
    # Display summary
    $compliant = ($results | Where-Object { $_.Status -eq "Compliant" }).Count
    $nonCompliant = ($results | Where-Object { $_.Status -eq "Non-Compliant" }).Count
    $notFound = ($results | Where-Object { $_.Status -eq "Not Found" }).Count
    
    Write-Host "Summary:"
    Write-Host "  Compliant settings: $compliant"
    Write-Host "  Non-Compliant settings: $nonCompliant"
    Write-Host "  Settings not found: $notFound"
    
    # Return non-zero exit code if any non-compliant settings found
    if ($nonCompliant -gt 0 -or $notFound -gt 0) {
        exit 1
    }
}
catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
    exit 1
}