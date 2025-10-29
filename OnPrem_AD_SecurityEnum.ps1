# On-Premises Active Directory Security Enumeration
# Collects security-relevant data from on-premises AD for analysis
# Requires: Domain Admin or equivalent permissions for comprehensive enumeration

param(
    [string]$Domain = $env:USERDNSDOMAIN,
    [switch]$SkipDCEnum = $false,
    [switch]$QuickScan = $false
)

# Import required modules
$requiredModules = @('ActiveDirectory')
foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Host "[-] Required module missing: $module" -ForegroundColor Red
        Write-Host "    Install with: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Yellow
        exit
    }
    Import-Module $module -ErrorAction SilentlyContinue
}

# Create output directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "OnPrem_AD_Security_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ON-PREMISES AD SECURITY ENUMERATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Domain: $Domain" -ForegroundColor Green
Write-Host "Output: $outputDir" -ForegroundColor Green
Write-Host ""

# Function to safely execute and save results
function Save-ADReport {
    param(
        [string]$Title,
        [string]$FileName,
        [scriptblock]$Command
    )
    
    Write-Host "[*] Collecting: $Title" -ForegroundColor Yellow
    
    try {
        $data = & $Command
        $filePath = Join-Path $outputDir $FileName
        
        if ($data -and $data.Count -gt 0) {
            $data | Export-Csv -Path "$filePath.csv" -NoTypeInformation -ErrorAction SilentlyContinue
            $data | Format-Table -AutoSize | Out-File -FilePath "$filePath.txt" -Width 300
            Write-Host "    [+] Saved: $($data.Count) items" -ForegroundColor Green
        } else {
            "No data found for $Title" | Out-File "$filePath.txt"
            Write-Host "    [!] No data found" -ForegroundColor Yellow
        }
    } catch {
        "Error collecting $Title : $_" | Out-File "$filePath.txt"
        Write-Host "    [-] Error: $_" -ForegroundColor Red
    }
}

# 1. Domain Controllers
if (-not $SkipDCEnum) {
    Save-ADReport -Title "Domain Controllers" -FileName "01_Domain_Controllers" -Command {
        Get-ADDomainController -Filter * | Select-Object Name, Site, OperatingSystem, OperatingSystemVersion, IPv4Address, IsGlobalCatalog, IsReadOnly, Enabled
    }
}

# 2. Users with SPN (Kerberoasting candidates)
Save-ADReport -Title "Users with Service Principal Names" -FileName "02_Users_With_SPN" -Command {
    Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, LastLogonDate, PasswordLastSet, AdminCount, PasswordNeverExpires | 
    Select-Object Name, SamAccountName, ServicePrincipalName, LastLogonDate, PasswordLastSet, AdminCount, PasswordNeverExpires, Enabled
}

# 3. Users with PreAuth disabled (ASREPRoast candidates)
Save-ADReport -Title "Users with Pre-Authentication Disabled" -FileName "03_PreAuth_Disabled_Users" -Command {
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, LastLogonDate, PasswordLastSet, AdminCount, PasswordNeverExpires |
    Select-Object Name, SamAccountName, DoesNotRequirePreAuth, LastLogonDate, PasswordLastSet, AdminCount, PasswordNeverExpires, Enabled
}

# 4. Privileged Users (Domain Admins, Enterprise Admins, etc.)
Save-ADReport -Title "Privileged Domain Users" -FileName "04_Privileged_Users" -Command {
    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins", 
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators"
    )
    
    $privilegedUsers = @()
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
            foreach ($member in $members) {
                if ($member.objectClass -eq "user") {
                    $user = Get-ADUser $member.SamAccountName -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires -ErrorAction SilentlyContinue
                    $privilegedUsers += [PSCustomObject]@{
                        Group = $group
                        Name = $user.Name
                        SamAccountName = $user.SamAccountName
                        LastLogonDate = $user.LastLogonDate
                        PasswordLastSet = $user.PasswordLastSet
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        Enabled = $user.Enabled
                    }
                }
            }
        } catch {
            Write-Warning "Could not enumerate group: $group"
        }
    }
    $privilegedUsers
}

# 5. Computer accounts (potential for delegation attacks)
Save-ADReport -Title "Computer Accounts with Delegation" -FileName "05_Computer_Delegation" -Command {
    Get-ADComputer -Filter {TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true} -Properties TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, LastLogonDate, OperatingSystem |
    Select-Object Name, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, LastLogonDate, OperatingSystem, Enabled
}

# 6. Stale computer accounts
Save-ADReport -Title "Stale Computer Accounts" -FileName "06_Stale_Computers" -Command {
    $cutoffDate = (Get-Date).AddDays(-90)
    Get-ADComputer -Filter {LastLogonDate -lt $cutoffDate -and Enabled -eq $true} -Properties LastLogonDate, OperatingSystem, OperatingSystemVersion |
    Select-Object Name, LastLogonDate, OperatingSystem, OperatingSystemVersion, Enabled | Sort-Object LastLogonDate
}

# 7. Users with AdminCount=1 (potential orphaned privileges)
Save-ADReport -Title "Users with AdminCount Flag" -FileName "07_AdminCount_Users" -Command {
    Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, LastLogonDate, PasswordLastSet, MemberOf |
    Select-Object Name, SamAccountName, AdminCount, LastLogonDate, PasswordLastSet, Enabled
}

# 8. Password policy analysis
Save-ADReport -Title "Domain Password Policy" -FileName "08_Password_Policy" -Command {
    Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled, LockoutDuration, LockoutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, MinPasswordLength, PasswordHistoryCount, ReversibleEncryptionEnabled
}

# 9. Fine-grained password policies
Save-ADReport -Title "Fine-Grained Password Policies" -FileName "09_Fine_Grained_Policies" -Command {
    Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, ComplexityEnabled, LockoutDuration, LockoutThreshold, MaxPasswordAge, MinPasswordAge, MinPasswordLength, PasswordHistoryCount, Precedence
}

# 10. GPO analysis (basic)
if (-not $QuickScan) {
    Save-ADReport -Title "Group Policy Objects" -FileName "10_Group_Policies" -Command {
        Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime, Description
    }
}

# 11. Trust relationships
Save-ADReport -Title "Domain Trusts" -FileName "11_Domain_Trusts" -Command {
    Get-ADTrust -Filter * | Select-Object Name, Direction, DisallowTransivity, ForestTransitive, IntraForest, IsTreeParent, IsTreeRoot, SelectiveAuthentication, SIDFilteringForestAware, SIDFilteringQuarantined, TGTDelegation, TrustAttributes, TrustType, UplevelOnly
}

# 12. DNS records that could be exploited
Save-ADReport -Title "Dangerous DNS Records" -FileName "12_DNS_Records" -Command {
    # Look for wildcard and potentially dangerous DNS records
    try {
        $dnsZones = Get-DnsServerZone -ErrorAction SilentlyContinue
        $dangerousRecords = @()
        foreach ($zone in $dnsZones) {
            $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue | Where-Object {
                $_.HostName -eq "*" -or 
                $_.HostName -like "*admin*" -or
                $_.HostName -like "*test*" -or
                $_.HostName -like "*dev*"
            }
            foreach ($record in $records) {
                $dangerousRecords += [PSCustomObject]@{
                    Zone = $zone.ZoneName
                    HostName = $record.HostName
                    RecordType = $record.RecordType
                    RecordData = $record.RecordData
                }
            }
        }
        $dangerousRecords
    } catch {
        Write-Warning "DNS enumeration failed - may require DNS admin rights"
        @()
    }
}

# 13. Service accounts analysis
Save-ADReport -Title "Potential Service Accounts" -FileName "13_Service_Accounts" -Command {
    Get-ADUser -Filter {Name -like "*service*" -or Name -like "*svc*" -or SamAccountName -like "*service*" -or SamAccountName -like "*svc*"} -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, ServicePrincipalName |
    Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, PasswordNeverExpires, ServicePrincipalName, Enabled
}

# 14. Accounts with passwords that never expire
Save-ADReport -Title "Accounts with Non-Expiring Passwords" -FileName "14_NonExpiring_Passwords" -Command {
    Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires, PasswordLastSet, LastLogonDate, AdminCount |
    Select-Object Name, SamAccountName, PasswordLastSet, LastLogonDate, AdminCount, PasswordNeverExpires, Enabled
}

# 15. Recently created accounts (potential backdoors)
Save-ADReport -Title "Recently Created Accounts" -FileName "15_Recent_Accounts" -Command {
    $recentDate = (Get-Date).AddDays(-30)
    Get-ADUser -Filter {Created -gt $recentDate} -Properties Created, LastLogonDate, PasswordLastSet, AdminCount |
    Select-Object Name, SamAccountName, Created, LastLogonDate, PasswordLastSet, AdminCount, Enabled | Sort-Object Created -Descending
}

# Generate summary report
Write-Host "[*] Generating summary..." -ForegroundColor Cyan

$summaryReport = @"
========================================
ON-PREMISES AD SECURITY ENUMERATION SUMMARY
========================================
Date: $(Get-Date)
Domain: $Domain
Enumeration ID: $timestamp

KEY SECURITY INDICATORS:
========================

Files Generated:
- 01_Domain_Controllers.csv - Domain controller inventory
- 02_Users_With_SPN.csv - Kerberoasting candidates  
- 03_PreAuth_Disabled_Users.csv - ASREPRoasting candidates
- 04_Privileged_Users.csv - High-privilege account inventory
- 05_Computer_Delegation.csv - Computers with delegation (potential attacks)
- 06_Stale_Computers.csv - Inactive computer accounts
- 07_AdminCount_Users.csv - Users with administrative flags
- 08_Password_Policy.csv - Domain password policy settings
- 09_Fine_Grained_Policies.csv - Granular password policies
- 10_Group_Policies.csv - GPO inventory
- 11_Domain_Trusts.csv - Trust relationship analysis
- 12_DNS_Records.csv - Potentially dangerous DNS records
- 13_Service_Accounts.csv - Service account inventory
- 14_NonExpiring_Passwords.csv - Accounts with permanent passwords
- 15_Recent_Accounts.csv - Recently created accounts

SECURITY PRIORITIES:
===================
1. Review users with SPNs for Kerberoasting vulnerabilities
2. Check pre-auth disabled users for ASREPRoasting risks
3. Audit privileged account usage and necessity
4. Remove or secure stale computer accounts
5. Review delegation settings on computer accounts
6. Validate password policies meet security requirements
7. Audit trust relationships for unnecessary exposure

========================================
"@

$summaryReport | Out-File (Join-Path $outputDir "00_Security_Summary.txt")

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "ON-PREMISES AD ENUMERATION COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Report saved to: $outputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Critical files to review:" -ForegroundColor Yellow
Write-Host "  - 02_Users_With_SPN.csv (Kerberoasting targets)" -ForegroundColor White
Write-Host "  - 03_PreAuth_Disabled_Users.csv (ASREPRoasting targets)" -ForegroundColor White  
Write-Host "  - 04_Privileged_Users.csv (High-privilege accounts)" -ForegroundColor White
Write-Host "  - 05_Computer_Delegation.csv (Delegation vulnerabilities)" -ForegroundColor White
Write-Host ""
Write-Host "Next: Run AzureAD_SecurityAnalyzer.ps1 with -IncludeOnPrem flag" -ForegroundColor Yellow
Write-Host ""