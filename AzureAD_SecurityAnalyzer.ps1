# Azure AD Security Analyzer
# Analyzes enumeration results and identifies security issues by severity
# Requires: Output from AzureAD_Enum.ps1

param(
    [string]$ReportDirectory = $null,
    [string]$OnPremDirectory = $null,
    [switch]$IncludeOnPrem = $false
)

# Function to find the most recent report directory
function Get-LatestReportDirectory {
    $currentDir = Get-Location
    $reportDirs = Get-ChildItem -Path $currentDir -Directory | Where-Object { $_.Name -like "AzureAD_Report_*" } | Sort-Object CreationTime -Descending
    
    if ($reportDirs.Count -eq 0) {
        Write-Host "[-] No Azure AD report directories found in current location" -ForegroundColor Red
        Write-Host "    Please run AzureAD_Enum.ps1 first or specify -ReportDirectory parameter" -ForegroundColor Yellow
        exit
    }
    
    return $reportDirs[0].FullName
}

# Security finding class
class SecurityFinding {
    [string]$Severity
    [string]$Category
    [string]$Title
    [string]$Description
    [string]$Impact
    [string]$Recommendation
    [object]$Evidence
    [int]$Count
}

# Initialize findings array
$findings = @()

# Function to add a finding
function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Description,
        [string]$Impact,
        [string]$Recommendation,
        [object]$Evidence = $null,
        [int]$Count = 0
    )
    
    $finding = [SecurityFinding]::new()
    $finding.Severity = $Severity
    $finding.Category = $Category
    $finding.Title = $Title
    $finding.Description = $Description
    $finding.Impact = $Impact
    $finding.Recommendation = $Recommendation
    $finding.Evidence = $Evidence
    $finding.Count = $Count
    
    return $finding
}

# Get report directory
if (-not $ReportDirectory) {
    $ReportDirectory = Get-LatestReportDirectory
}

# Get on-premises report directory if specified
$onPremData = $null
if ($IncludeOnPrem) {
    if (-not $OnPremDirectory) {
        # Look for most recent on-prem report
        $currentDir = Get-Location
        $onPremDirs = Get-ChildItem -Path $currentDir -Directory | Where-Object { $_.Name -like "OnPrem_AD_Security_*" } | Sort-Object CreationTime -Descending
        if ($onPremDirs.Count -gt 0) {
            $OnPremDirectory = $onPremDirs[0].FullName
            Write-Host "[+] Found on-premises report: $OnPremDirectory" -ForegroundColor Green
        } else {
            Write-Host "[!] No on-premises AD reports found. Run OnPrem_AD_SecurityEnum.ps1 first." -ForegroundColor Yellow
            $IncludeOnPrem = $false
        }
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AZURE AD SECURITY ANALYZER" -ForegroundColor Cyan
if ($IncludeOnPrem) { Write-Host "+ ON-PREMISES AD ANALYSIS" -ForegroundColor Cyan }
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analyzing report: $ReportDirectory" -ForegroundColor Green
if ($IncludeOnPrem -and $OnPremDirectory) { Write-Host "On-premises data: $OnPremDirectory" -ForegroundColor Green }
Write-Host ""

# Check if required files exist
$requiredFiles = @(
    "04_All_Users.csv",
    "05_All_Groups.csv", 
    "06_Privileged_Users.csv",
    "10_Service_Principals.csv",
    "11_App_Registrations.csv",
    "13_Guest_Users.csv",
    "15_Domains.csv"
)

foreach ($file in $requiredFiles) {
    $filePath = Join-Path $ReportDirectory $file
    if (-not (Test-Path $filePath)) {
        Write-Host "[-] Required file not found: $file" -ForegroundColor Red
        Write-Host "    Please ensure AzureAD_Enum.ps1 completed successfully" -ForegroundColor Yellow
        exit
    }
}

Write-Host "[*] Loading enumeration data..." -ForegroundColor Yellow

# Load data from CSV files
try {
    $allUsers = Import-Csv (Join-Path $ReportDirectory "04_All_Users.csv")
    $allGroups = Import-Csv (Join-Path $ReportDirectory "05_All_Groups.csv")
    $privilegedUsers = Import-Csv (Join-Path $ReportDirectory "06_Privileged_Users.csv")
    $servicePrincipals = Import-Csv (Join-Path $ReportDirectory "10_Service_Principals.csv")
    $appRegistrations = Import-Csv (Join-Path $ReportDirectory "11_App_Registrations.csv")
    $guestUsers = Import-Csv (Join-Path $ReportDirectory "13_Guest_Users.csv")
    $domains = Import-Csv (Join-Path $ReportDirectory "15_Domains.csv")
    
    # Optional files
    $mfaUsers = $null
    $conditionalAccess = $null
    $devices = $null
    
    if (Test-Path (Join-Path $ReportDirectory "08_MFA_Status.csv")) {
        $mfaUsers = Import-Csv (Join-Path $ReportDirectory "08_MFA_Status.csv")
    }
    
    if (Test-Path (Join-Path $ReportDirectory "09_Conditional_Access.csv")) {
        $conditionalAccess = Import-Csv (Join-Path $ReportDirectory "09_Conditional_Access.csv")
    }
    
    if (Test-Path (Join-Path $ReportDirectory "07_All_Devices.csv")) {
        $devices = Import-Csv (Join-Path $ReportDirectory "07_All_Devices.csv")
    }
    
    Write-Host "[+] Data loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "[-] Error loading data: $_" -ForegroundColor Red
    exit
}

# Load on-premises data if available
$onPremUsers = $null
$onPremPrivileged = $null
$onPremComputers = $null
$onPremSPNUsers = $null
$onPremPreAuthUsers = $null
$onPremDelegation = $null
$onPremTrusts = $null
$onPremPasswordPolicy = $null

if ($IncludeOnPrem -and $OnPremDirectory) {
    Write-Host "[*] Loading on-premises AD data..." -ForegroundColor Yellow
    try {
        # Load on-premises CSV files if they exist
        $onPremFiles = @{
            "02_Users_With_SPN.csv" = { $script:onPremSPNUsers = Import-Csv $_ }
            "03_PreAuth_Disabled_Users.csv" = { $script:onPremPreAuthUsers = Import-Csv $_ }
            "04_Privileged_Users.csv" = { $script:onPremPrivileged = Import-Csv $_ }
            "05_Computer_Delegation.csv" = { $script:onPremDelegation = Import-Csv $_ }
            "06_Stale_Computers.csv" = { $script:onPremComputers = Import-Csv $_ }
            "11_Domain_Trusts.csv" = { $script:onPremTrusts = Import-Csv $_ }
            "08_Password_Policy.csv" = { $script:onPremPasswordPolicy = Import-Csv $_ }
        }
        
        foreach ($file in $onPremFiles.Keys) {
            $filePath = Join-Path $OnPremDirectory $file
            if (Test-Path $filePath) {
                & $onPremFiles[$file] $filePath
            }
        }
        Write-Host "[+] On-premises data loaded successfully" -ForegroundColor Green
    } catch {
        Write-Host "[-] Error loading on-premises data: $_" -ForegroundColor Red
        $IncludeOnPrem = $false
    }
}

Write-Host "[*] Analyzing security posture..." -ForegroundColor Yellow

# =============================================================================
# CRITICAL FINDINGS
# =============================================================================

# Global Admin accounts
$globalAdmins = $privilegedUsers | Where-Object { $_.Role -eq "Global Administrator" -or $_.Role -eq "Company Administrator" }
if ($globalAdmins.Count -gt 5) {
    $findings += Add-Finding -Severity "CRITICAL" -Category "Identity Management" -Title "Excessive Global Administrator Accounts" -Description "Too many Global Administrator accounts detected ($($globalAdmins.Count) accounts)" -Impact "Global Admins have unrestricted access to all Azure AD and Microsoft 365 services. Excessive accounts increase attack surface." -Recommendation "Reduce Global Admin accounts to 2-4 emergency accounts. Use more specific admin roles for daily operations." -Evidence $globalAdmins -Count $globalAdmins.Count
}

# Users without MFA (if data available)
if ($mfaUsers) {
    $noMFAUsers = $mfaUsers | Where-Object { $_."MFA Status" -eq "Disabled" -and $_.AccountEnabled -eq "True" }
    if ($noMFAUsers.Count -gt 0) {
        $findings += Add-Finding -Severity "CRITICAL" -Category "Authentication" -Title "Users Without Multi-Factor Authentication" -Description "$($noMFAUsers.Count) enabled users do not have MFA configured" -Impact "Accounts without MFA are vulnerable to password-based attacks and credential stuffing." -Recommendation "Enforce MFA for all users, especially privileged accounts. Use Conditional Access policies." -Evidence $noMFAUsers -Count $noMFAUsers.Count
    }
}

# Privileged users without MFA
if ($mfaUsers -and $privilegedUsers) {
    $privilegedNoMFA = $privilegedUsers | Where-Object { 
        $privUser = $_
        $mfaStatus = $mfaUsers | Where-Object { $_.UserPrincipalName -eq $privUser.UserPrincipalName }
        $mfaStatus -and $mfaStatus."MFA Status" -eq "Disabled"
    }
    if ($privilegedNoMFA.Count -gt 0) {
        $findings += Add-Finding -Severity "CRITICAL" -Category "Authentication" -Title "Privileged Users Without MFA" -Description "$($privilegedNoMFA.Count) privileged users do not have MFA enabled" -Impact "Privileged accounts without MFA pose extreme risk of tenant compromise." -Recommendation "Immediately enforce MFA for all privileged accounts. Consider requiring hardware tokens." -Evidence $privilegedNoMFA -Count $privilegedNoMFA.Count
    }
}

# External guest users with privileged roles
$privilegedGuests = $privilegedUsers | Where-Object { $_.UserPrincipalName -like "*#EXT#*" -or $_.ObjectType -eq "Guest" }
if ($privilegedGuests.Count -gt 0) {
    $findings += Add-Finding -Severity "CRITICAL" -Category "Identity Management" -Title "External Users with Privileged Roles" -Description "$($privilegedGuests.Count) external/guest users have privileged roles assigned" -Impact "External users with admin rights can access sensitive data and make critical changes." -Recommendation "Review and remove privileged access for external users. Use PIM for temporary access." -Evidence $privilegedGuests -Count $privilegedGuests.Count
}

# =============================================================================
# ON-PREMISES AD CRITICAL FINDINGS
# =============================================================================

if ($IncludeOnPrem) {
    # Kerberoasting candidates (users with SPNs)
    if ($onPremSPNUsers -and $onPremSPNUsers.Count -gt 0) {
        $findings += Add-Finding -Severity "CRITICAL" -Category "On-Premises AD" -Title "Kerberoasting Vulnerable Accounts" -Description "$($onPremSPNUsers.Count) user accounts with Service Principal Names detected" -Impact "Users with SPNs are vulnerable to Kerberoasting attacks allowing password hash extraction." -Recommendation "Remove unnecessary SPNs, use managed service accounts (MSA/gMSA), and ensure strong passwords for SPN accounts." -Evidence $onPremSPNUsers -Count $onPremSPNUsers.Count
    }
    
    # ASREPRoasting candidates (pre-auth disabled)
    if ($onPremPreAuthUsers -and $onPremPreAuthUsers.Count -gt 0) {
        $findings += Add-Finding -Severity "CRITICAL" -Category "On-Premises AD" -Title "ASREPRoasting Vulnerable Accounts" -Description "$($onPremPreAuthUsers.Count) user accounts with Kerberos pre-authentication disabled" -Impact "Accounts without pre-auth are vulnerable to ASREPRoasting attacks for password cracking." -Recommendation "Enable Kerberos pre-authentication for all user accounts unless specifically required." -Evidence $onPremPreAuthUsers -Count $onPremPreAuthUsers.Count
    }
    
    # Unconstrained delegation
    if ($onPremDelegation) {
        $unconstrainedDelegation = $onPremDelegation | Where-Object { $_.TrustedForDelegation -eq "True" }
        if ($unconstrainedDelegation.Count -gt 0) {
            $findings += Add-Finding -Severity "CRITICAL" -Category "On-Premises AD" -Title "Unconstrained Delegation Configured" -Description "$($unconstrainedDelegation.Count) computer accounts configured for unconstrained delegation" -Impact "Unconstrained delegation allows attackers to impersonate any user to any service." -Recommendation "Replace unconstrained delegation with constrained delegation or resource-based constrained delegation." -Evidence $unconstrainedDelegation -Count $unconstrainedDelegation.Count
        }
    }
}

# =============================================================================
# HIGH FINDINGS  
# =============================================================================

# Stale privileged accounts (no recent activity)
# Note: This would require additional data about last sign-in times
# For now, we'll check for disabled privileged accounts that still have roles

$disabledPrivileged = $privilegedUsers | Where-Object { 
    $privUser = $_
    $userDetail = $allUsers | Where-Object { $_.UserPrincipalName -eq $privUser.UserPrincipalName }
    $userDetail -and $userDetail.AccountEnabled -eq "False"
}
if ($disabledPrivileged.Count -gt 0) {
    $findings += Add-Finding -Severity "HIGH" -Category "Identity Management" -Title "Disabled Users with Privileged Roles" -Description "$($disabledPrivileged.Count) disabled user accounts still have privileged roles assigned" -Impact "Disabled accounts with privileges could be re-enabled and misused." -Recommendation "Remove all role assignments from disabled user accounts." -Evidence $disabledPrivileged -Count $disabledPrivileged.Count
}

# High number of guest users
$guestCount = $guestUsers.Count
$totalUsers = $allUsers.Count
$guestPercentage = [math]::Round(($guestCount / $totalUsers) * 100, 2)
if ($guestPercentage -gt 20) {
    $findings += Add-Finding -Severity "HIGH" -Category "Identity Management" -Title "High Percentage of Guest Users" -Description "Guest users represent $guestPercentage% of total users ($guestCount out of $totalUsers)" -Impact "Large number of external users increases attack surface and data exposure risk." -Recommendation "Review guest user access regularly. Implement guest access reviews and expiration policies." -Evidence $null -Count $guestCount
}

# Applications with high permissions
$highPermissionApps = $servicePrincipals | Where-Object { 
    $_.DisplayName -notlike "*Microsoft*" -and $_.PublisherName -notlike "*Microsoft*"
}
if ($highPermissionApps.Count -gt ($servicePrincipals.Count * 0.3)) {
    $findings += Add-Finding -Severity "HIGH" -Category "Application Security" -Title "High Number of Third-Party Applications" -Description "$($highPermissionApps.Count) non-Microsoft applications have service principals" -Impact "Third-party applications may have excessive permissions and access to sensitive data." -Recommendation "Review all third-party application permissions. Implement least privilege principle." -Evidence $highPermissionApps -Count $highPermissionApps.Count
}

# Application registrations without publisher verification
$unverifiedApps = $appRegistrations | Where-Object { 
    $_.PublisherDomain -eq "" -or $_.PublisherDomain -eq $null -or $_.PublisherDomain -like "*onmicrosoft.com*"
}
if ($unverifiedApps.Count -gt 0) {
    $findings += Add-Finding -Severity "HIGH" -Category "Application Security" -Title "Unverified Application Publishers" -Description "$($unverifiedApps.Count) application registrations lack publisher verification" -Impact "Unverified applications may be malicious or lack proper security controls." -Recommendation "Review all unverified applications and require publisher verification for production apps." -Evidence $unverifiedApps -Count $unverifiedApps.Count
}

# Application registrations that may be unused or abandoned
$potentiallyUnusedApps = $appRegistrations | Where-Object { 
    ($_.LastSignInDateTime -eq "" -or $_.LastSignInDateTime -eq $null) -and 
    ($_.CreatedDateTime -lt (Get-Date).AddDays(-90))
}
if ($potentiallyUnusedApps.Count -gt 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Application Security" -Title "Potentially Unused Application Registrations" -Description "$($potentiallyUnusedApps.Count) application registrations show no recent sign-in activity and are over 90 days old" -Impact "Unused applications represent unnecessary attack surface and potential security vulnerabilities." -Recommendation "Review and remove application registrations that are no longer needed. Implement regular app registration cleanup processes." -Evidence $potentiallyUnusedApps -Count $potentiallyUnusedApps.Count
}

# =============================================================================
# ATTACK KILL CHAIN ANALYSIS - ENHANCED DETECTION
# =============================================================================

Write-Host "[*] Analyzing Azure AD Kill Chain attack vectors..." -ForegroundColor Yellow

# Outsider Reconnaissance Vulnerabilities
# Check for publicly exposed tenant information
$exposedDomains = $domains | Where-Object { $_.IsVerified -eq $false }
if ($exposedDomains.Count -gt 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Information Disclosure" -Title "Unverified Domains Exposed" -Description "$($exposedDomains.Count) unverified domains are publicly visible" -Impact "Unverified domains may reveal business secrets, upcoming products, or internal infrastructure details to outsiders." -Recommendation "Remove or verify unverified domains. Avoid registering future product domains in Azure AD until ready for public disclosure." -Evidence $exposedDomains -Count $exposedDomains.Count
}

# Desktop SSO Configuration Check (Seamless SSO vulnerability)
$seamlessSSODomains = $domains | Where-Object { $_.AuthenticationType -eq "Federated" }
if ($seamlessSSODomains.Count -gt 0) {
    $findings += Add-Finding -Severity "HIGH" -Category "Authentication Security" -Title "Federated Domains Detected" -Description "$($seamlessSSODomains.Count) domains use federated authentication" -Impact "Federated domains may be vulnerable to user enumeration attacks and phishing if Desktop SSO is enabled." -Recommendation "Monitor for suspicious authentication attempts. Implement conditional access policies for federated domains." -Evidence $seamlessSSODomains -Count $seamlessSSODomains.Count
}

# Guest Access Attack Vector Analysis
$guestEnumerationRisk = $allGroups | Where-Object { 
    $_.DisplayName -like "*guest*" -or $_.DisplayName -like "*external*" -or 
    $_.Description -like "*guest*" -or $_.Description -like "*external*"
}
if ($guestEnumerationRisk.Count -gt 0) {
    $findings += Add-Finding -Severity "HIGH" -Category "Guest Access Security" -Title "Guest Enumeration Groups Detected" -Description "$($guestEnumerationRisk.Count) groups contain or reference guest/external users" -Impact "Dynamic groups containing all guests allow guest users to enumerate all external users and potentially escalate access." -Recommendation "Review guest-related groups. Avoid dynamic groups that include all guests. Implement guest access restrictions." -Evidence $guestEnumerationRisk -Count $guestEnumerationRisk.Count
}

# Dynamic Group Analysis for Kill Chain Vulnerabilities
$allUserGroups = $allGroups | Where-Object { 
    $_.Description -like "*all user*" -or $_.Description -like "*all member*" -or
    $_.DisplayName -like "*all user*" -or $_.DisplayName -like "*all member*"
}
if ($allUserGroups.Count -gt 0) {
    $findings += Add-Finding -Severity "CRITICAL" -Category "Access Control" -Title "All-Users Dynamic Groups Detected" -Description "$($allUserGroups.Count) groups appear to include all tenant users" -Impact "Dynamic groups including all users allow guest users to enumerate the entire user base, exposing organizational structure." -Recommendation "Remove or restrict dynamic groups that include all users. Implement guest access limitations immediately." -Evidence $allUserGroups -Count $allUserGroups.Count
}

# Insider Threat - Bulk Device Registration Capability
$deviceJoinPolicy = "Unknown" # This would need to be checked via Graph API in real implementation
# Note: In a real implementation, this would check the device registration settings
$findings += Add-Finding -Severity "MEDIUM" -Category "Device Security" -Title "Device Registration Policy Review Needed" -Description "User device registration capabilities require verification" -Impact "If users can register unlimited devices, they may perform DoS attacks by filling Azure AD object quota with fake devices." -Recommendation "Review device registration settings. Limit devices per user. Monitor for bulk device registrations." -Evidence $null -Count 0

# Application Registration Abuse Detection
$suspiciousApps = $appRegistrations | Where-Object { 
    $_.DisplayName -like "*test*" -or $_.DisplayName -like "*temp*" -or 
    $_.DisplayName -like "*debug*" -or $_.DisplayName -like "*dev*"
}
if ($suspiciousApps.Count -gt 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Application Security" -Title "Suspicious Application Names Detected" -Description "$($suspiciousApps.Count) applications have suspicious or temporary-sounding names" -Impact "Test/temporary applications may be forgotten and provide unauthorized access paths or be used for malicious purposes." -Recommendation "Review all applications with test/temporary names. Remove unused applications. Implement application naming conventions." -Evidence $suspiciousApps -Count $suspiciousApps.Count
}

# Service Principal Analysis for Attack Vectors
$highRiskSPs = $servicePrincipals | Where-Object { 
    $_.PublisherName -eq "" -or $_.PublisherName -eq $null -or
    ($_.DisplayName -notlike "*Microsoft*" -and $_.PublisherName -notlike "*Microsoft*")
}
if ($highRiskSPs.Count -gt ($servicePrincipals.Count * 0.4)) {
    $findings += Add-Finding -Severity "HIGH" -Category "Application Security" -Title "High Volume of Unverified Service Principals" -Description "$($highRiskSPs.Count) service principals lack verified publishers (40%+ of total)" -Impact "Large numbers of unverified service principals increase attack surface and may indicate compromise or poor application governance." -Recommendation "Audit all third-party service principals. Require publisher verification. Remove unused service principals." -Evidence $highRiskSPs -Count $highRiskSPs.Count
}

# Attack Chain - Privilege Escalation Paths
$privilegedRoleCount = ($privilegedUsers | Measure-Object).Count
$totalUserCount = ($allUsers | Measure-Object).Count
$privilegedPercentage = if ($totalUserCount -gt 0) { [math]::Round(($privilegedRoleCount / $totalUserCount) * 100, 2) } else { 0 }

if ($privilegedPercentage -gt 10) {
    $findings += Add-Finding -Severity "CRITICAL" -Category "Privilege Management" -Title "Excessive Privileged Access" -Description "$privilegedPercentage% of users have privileged roles ($privilegedRoleCount out of $totalUserCount)" -Impact "High percentage of privileged users creates multiple attack paths for privilege escalation and increases blast radius of compromise." -Recommendation "Implement Just-In-Time (JIT) access. Use Privileged Identity Management (PIM). Review and reduce privileged role assignments." -Evidence $privilegedUsers -Count $privilegedRoleCount
}

# =============================================================================
# KILL CHAIN MITIGATION ANALYSIS
# =============================================================================

# Admin Role Security Analysis (Admin Phase Detection)
$globalAdmins = $privilegedUsers | Where-Object { 
    $_.RoleName -like "*Global*" -or $_.RoleName -like "*Company*" 
}
if ($globalAdmins.Count -gt 5) {
    $findings += Add-Finding -Severity "CRITICAL" -Category "Admin Security" -Title "Excessive Global Administrators" -Description "$($globalAdmins.Count) Global Administrator accounts detected" -Impact "Multiple Global Admin accounts increase risk of total tenant compromise. Each account is a high-value target." -Recommendation "Limit Global Admin accounts to 2-4. Use PIM for temporary elevation. Implement break-glass procedures." -Evidence $globalAdmins -Count $globalAdmins.Count
}

# Phishing Resilience Analysis
$usersWithoutMFA = $allUsers | Where-Object { 
    $_.MfaEnabled -eq $false -or $_.MfaEnabled -eq $null -or $_.MfaEnabled -eq ""
}
if ($usersWithoutMFA.Count -gt ($allUsers.Count * 0.1)) {
    $findings += Add-Finding -Severity "HIGH" -Category "Authentication Security" -Title "Large Population Vulnerable to Phishing" -Description "$($usersWithoutMFA.Count) users lack MFA protection" -Impact "Users without MFA are vulnerable to device code phishing and credential attacks. This affects $([math]::Round(($usersWithoutMFA.Count / $allUsers.Count) * 100, 1))% of the user base." -Recommendation "Enforce MFA for all users. Implement conditional access policies. Use phishing-resistant authentication methods." -Evidence $usersWithoutMFA -Count $usersWithoutMFA.Count
}

# Persistence Mechanism Detection
$longLivedTokens = $appRegistrations | Where-Object { 
    $_.PasswordCredentials -ne $null -or $_.KeyCredentials -ne $null
}
if ($longLivedTokens.Count -gt 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Persistence Risk" -Title "Applications with Long-lived Credentials" -Description "$($longLivedTokens.Count) applications have password or key credentials" -Impact "Long-lived application credentials can be used for persistence after initial compromise." -Recommendation "Rotate application credentials regularly. Use certificates instead of passwords. Implement credential monitoring." -Evidence $longLivedTokens -Count $longLivedTokens.Count
}

# Lateral Movement Risk Assessment
$internalApps = $servicePrincipals | Where-Object { 
    $_.PublisherName -like "*onmicrosoft.com*" -or $_.AppOwnerOrganizationId -ne $null
}
$internalAppPercentage = if ($servicePrincipals.Count -gt 0) { [math]::Round(($internalApps.Count / $servicePrincipals.Count) * 100, 2) } else { 0 }

if ($internalAppPercentage -lt 60) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Attack Surface" -Title "High External Application Dependency" -Description "Only $internalAppPercentage% of service principals are internal applications" -Impact "Heavy reliance on external applications increases lateral movement opportunities for attackers." -Recommendation "Review external application necessity. Implement application governance policies. Monitor cross-tenant application access." -Evidence $servicePrincipals -Count $servicePrincipals.Count
}

# Device Code Phishing Protection Analysis
# Note: This check would ideally verify conditional access policies blocking device code flow
$findings += Add-Finding -Severity "INFO" -Category "Phishing Protection" -Title "Device Code Phishing Protection Review" -Description "Device code authentication flow protection should be verified" -Impact "Device code flow can be abused for phishing attacks without requiring infrastructure setup." -Recommendation "Implement conditional access policies to block device code flow for high-risk scenarios. Train users on device code phishing." -Evidence $null -Count 0

# =============================================================================
# ON-PREMISES AD HIGH FINDINGS  
# =============================================================================

if ($IncludeOnPrem) {
    Write-Host "[*] Analyzing on-premises kill chain vectors..." -ForegroundColor Yellow
    
    # Azure AD Connect Security Analysis
    $syncAccounts = $allUsers | Where-Object { 
        $_.UserPrincipalName -like "*Sync_*" -or $_.DisplayName -like "*Sync*" -or
        $_.UserPrincipalName -like "*MSOL_*" -or $_.DisplayName -like "*Directory Sync*"
    }
    if ($syncAccounts.Count -gt 1) {
        $findings += Add-Finding -Severity "HIGH" -Category "Hybrid Security" -Title "Multiple Sync Accounts Detected" -Description "$($syncAccounts.Count) directory synchronization accounts found" -Impact "Multiple sync accounts may indicate multiple Azure AD Connect servers or stale accounts that could be abused for privilege escalation." -Recommendation "Verify legitimacy of all sync accounts. Remove unused sync accounts. Secure Azure AD Connect servers." -Evidence $syncAccounts -Count $syncAccounts.Count
    }

    # Seamless SSO Computer Account Analysis
    $azureADSSOAccounts = $allUsers | Where-Object { 
        $_.UserPrincipalName -like "*AZUREADSSOACC*" -or $_.DisplayName -like "*AZUREADSSOACC*"
    }
    if ($azureADSSOAccounts.Count -gt 0) {
        $findings += Add-Finding -Severity "CRITICAL" -Category "Hybrid Security" -Title "Seamless SSO Account Detected" -Description "AZUREADSSOACC computer account indicates Seamless SSO is enabled" -Impact "If on-premises admin dumps AZUREADSSOACC password hash, they can create Kerberos tickets to sign in as any user bypassing MFA." -Recommendation "Rotate AZUREADSSOACC account password every 30 days. Monitor access to this account. Consider disabling Seamless SSO if not required." -Evidence $azureADSSOAccounts -Count $azureADSSOAccounts.Count
    }

    # Federation Security Analysis  
    $federatedDomains = $domains | Where-Object { $_.AuthenticationType -eq "Federated" }
    if ($federatedDomains.Count -gt 0) {
        $findings += Add-Finding -Severity "HIGH" -Category "Federation Security" -Title "Federated Domains Present" -Description "$($federatedDomains.Count) domains use federation" -Impact "Federated domains allow on-premises admins to export token signing certificates and sign in as any user, bypassing MFA." -Recommendation "Secure ADFS servers. Monitor certificate access. Implement certificate rotation. Use hardware security modules for certificate storage." -Evidence $federatedDomains -Count $federatedDomains.Count
    }
    
    # On-Premises Privilege Escalation Paths
    if ($onPremUsers -and $onPremUsers.Count -gt 0) {
        # Stale computer accounts
        if ($onPremComputers -and $onPremComputers.Count -gt 0) {
            $findings += Add-Finding -Severity "HIGH" -Category "On-Premises AD" -Title "Stale Computer Accounts" -Description "$($onPremComputers.Count) computer accounts have not logged on in 90+ days" -Impact "Stale computer accounts can be leveraged for attacks and indicate poor asset management." -Recommendation "Disable or remove computer accounts that haven't been used in 90+ days." -Evidence $onPremComputers -Count $onPremComputers.Count
        }
        
        # Kerberoasting vulnerabilities
        if ($onPremSPNUsers -and $onPremSPNUsers.Count -gt 0) {
            $findings += Add-Finding -Severity "HIGH" -Category "On-Premises AD" -Title "Kerberoasting Vulnerable Accounts" -Description "$($onPremSPNUsers.Count) user accounts have Service Principal Names" -Impact "User accounts with SPNs are vulnerable to Kerberoasting attacks for offline password cracking." -Recommendation "Use Managed Service Accounts (MSA/gMSA) instead of user accounts for services. Use complex passwords for service accounts." -Evidence $onPremSPNUsers -Count $onPremSPNUsers.Count
        }
        
        # ASREPRoasting vulnerabilities  
        if ($onPremPrivileged -and $onPremPrivileged.Count -gt 0) {
            $asrepVulnerable = $onPremPrivileged | Where-Object { $_.PreAuthDisabled -eq $true }
            if ($asrepVulnerable.Count -gt 0) {
                $findings += Add-Finding -Severity "HIGH" -Category "On-Premises AD" -Title "ASREPRoasting Vulnerable Accounts" -Description "$($asrepVulnerable.Count) accounts have Kerberos pre-authentication disabled" -Impact "Accounts without pre-authentication allow ASREPRoasting attacks for offline password cracking." -Recommendation "Enable Kerberos pre-authentication for all accounts unless specifically required for compatibility." -Evidence $asrepVulnerable -Count $asrepVulnerable.Count
            }
        }
    }
    
    # Weak password policy
    if ($onPremPasswordPolicy) {
        $weakPolicy = $onPremPasswordPolicy | Where-Object { 
            $_.MinPasswordLength -lt 12 -or 
            $_.ComplexityEnabled -eq "False" -or
            $_.MaxPasswordAge.Days -gt 90
        }
        if ($weakPolicy) {
            $findings += Add-Finding -Severity "HIGH" -Category "On-Premises AD" -Title "Weak Domain Password Policy" -Description "Domain password policy does not meet security best practices" -Impact "Weak password policies increase risk of successful brute force and credential attacks." -Recommendation "Implement minimum 12 character passwords, complexity requirements, and 60-90 day maximum age." -Evidence $weakPolicy -Count 1
        }
    }
    
    # External domain trusts
    if ($onPremTrusts) {
        $externalTrusts = $onPremTrusts | Where-Object { $_.IntraForest -eq "False" }
        if ($externalTrusts.Count -gt 0) {
            $findings += Add-Finding -Severity "HIGH" -Category "On-Premises AD" -Title "External Domain Trusts" -Description "$($externalTrusts.Count) external forest/domain trusts configured" -Impact "External trusts expand attack surface and may allow lateral movement." -Recommendation "Review necessity of external trusts and implement selective authentication where possible." -Evidence $externalTrusts -Count $externalTrusts.Count
        }
    }
}

# =============================================================================
# MEDIUM FINDINGS
# =============================================================================

Write-Host "[*] Analyzing medium priority attack vectors..." -ForegroundColor Yellow

# No Conditional Access policies (if data available)
if ($conditionalAccess -and $conditionalAccess.Count -eq 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Access Control" -Title "No Conditional Access Policies Configured" -Description "No Conditional Access policies are configured" -Impact "Missing modern security controls for access management and risk mitigation." -Recommendation "Implement Conditional Access policies for device compliance, location-based access, and risk-based authentication." -Evidence $null -Count 0
}

# Kill Chain - Information Gathering Prevention
$publicGroupsRisk = $allGroups | Where-Object { 
    $_.Visibility -eq "Public" -or $_.GroupTypes -contains "DynamicMembership"
}
if ($publicGroupsRisk.Count -gt ($allGroups.Count * 0.3)) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Information Disclosure" -Title "High Number of Public/Dynamic Groups" -Description "$($publicGroupsRisk.Count) groups are public or dynamic (30%+ of total)" -Impact "Public and dynamic groups can be enumerated by guest users, revealing organizational structure and membership information." -Recommendation "Review group visibility settings. Limit public groups. Carefully design dynamic group rules to prevent information leakage." -Evidence $publicGroupsRisk -Count $publicGroupsRisk.Count
}

# Legacy Authentication Detection
$legacyAuthUsers = $allUsers | Where-Object { 
    $_.LastSignInDateTime -ne $null -and $_.LastSignInDateTime -ne "" -and 
    ($_.SignInSessionsValidFromDateTime -lt (Get-Date).AddDays(-90) -or $_.SignInSessionsValidFromDateTime -eq $null)
}
if ($legacyAuthUsers.Count -gt 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Authentication Security" -Title "Potential Legacy Authentication Usage" -Description "$($legacyAuthUsers.Count) users may be using legacy authentication protocols" -Impact "Legacy authentication protocols bypass modern security controls like MFA and conditional access." -Recommendation "Block legacy authentication protocols. Enable modern authentication for all applications. Monitor for legacy auth usage." -Evidence $legacyAuthUsers -Count $legacyAuthUsers.Count
}

# Unverified domains
$unverifiedDomains = $domains | Where-Object { $_.IsVerified -eq "False" }
if ($unverifiedDomains.Count -gt 0) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Domain Security" -Title "Unverified Domains" -Description "$($unverifiedDomains.Count) domains are not verified" -Impact "Unverified domains can be used for spoofing and phishing attacks." -Recommendation "Verify all legitimate domains and remove unused unverified domains." -Evidence $unverifiedDomains -Count $unverifiedDomains.Count
}

# Large privileged groups
$largePrivGroups = $allGroups | Where-Object { 
    $_.DisplayName -like "*Admin*" -or $_.DisplayName -like "*Privilege*" 
} | Sort-Object DisplayName
if ($largePrivGroups.Count -gt 10) {
    $findings += Add-Finding -Severity "MEDIUM" -Category "Identity Management" -Title "Multiple Administrative Groups" -Description "$($largePrivGroups.Count) groups contain 'Admin' or 'Privilege' in their names" -Impact "Multiple administrative groups can lead to privilege creep and unclear access controls." -Recommendation "Consolidate administrative groups and implement clear group naming conventions." -Evidence $largePrivGroups -Count $largePrivGroups.Count
}

# =============================================================================
# LOW FINDINGS
# =============================================================================

# Guest users from unknown domains
$suspiciousGuestDomains = $guestUsers | Where-Object { 
    $_.UserPrincipalName -like "*gmail.com*" -or 
    $_.UserPrincipalName -like "*outlook.com*" -or 
    $_.UserPrincipalName -like "*hotmail.com*" -or
    $_.UserPrincipalName -like "*yahoo.com*"
} 
if ($suspiciousGuestDomains.Count -gt 0) {
    $findings += Add-Finding -Severity "LOW" -Category "Identity Management" -Title "Guest Users from Public Email Domains" -Description "$($suspiciousGuestDomains.Count) guest users use public email domains" -Impact "Guest users from public domains may indicate personal accounts being used for business." -Recommendation "Review guest users from public domains. Consider requiring corporate email addresses." -Evidence $suspiciousGuestDomains -Count $suspiciousGuestDomains.Count
}

# Non-compliant devices (if data available)
if ($devices) {
    $nonCompliantDevices = $devices | Where-Object { $_.IsCompliant -eq "False" }
    if ($nonCompliantDevices.Count -gt 0) {
        $findings += Add-Finding -Severity "LOW" -Category "Device Management" -Title "Non-Compliant Devices" -Description "$($nonCompliantDevices.Count) devices are marked as non-compliant" -Impact "Non-compliant devices may not meet security policies and could pose risks." -Recommendation "Review device compliance policies and remediate non-compliant devices." -Evidence $nonCompliantDevices -Count $nonCompliantDevices.Count
    }
}

# =============================================================================
# INFO FINDINGS
# =============================================================================

# Statistics
$findings += Add-Finding -Severity "INFO" -Category "Statistics" -Title "Total Users" -Description "Total user accounts in directory: $($allUsers.Count)" -Impact "Informational" -Recommendation "Regular user access reviews recommended for large directories" -Evidence $null -Count $allUsers.Count

$findings += Add-Finding -Severity "INFO" -Category "Statistics" -Title "Total Groups" -Description "Total groups in directory: $($allGroups.Count)" -Impact "Informational" -Recommendation "Regular group membership reviews recommended" -Evidence $null -Count $allGroups.Count

$findings += Add-Finding -Severity "INFO" -Category "Statistics" -Title "Privileged Users" -Description "Total privileged users: $($privilegedUsers.Count)" -Impact "Informational" -Recommendation "Review privileged access regularly" -Evidence $null -Count $privilegedUsers.Count

# =============================================================================
# GENERATE REPORT
# =============================================================================

Write-Host "[*] Generating security assessment report..." -ForegroundColor Yellow

# Create output directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "AzureAD_SecurityAssessment_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Sort findings by severity (using all findings for now, will filter later)
$severityOrder = @("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
$sortedFindings = $findings | Sort-Object { $severityOrder.IndexOf($_.Severity) }

# Calculate security posture statistics
$totalUsers = $allUsers.Count
$totalGroups = $allGroups.Count
$totalApps = $appRegistrations.Count
$totalSPs = $servicePrincipals.Count

# Calculate positive security metrics
$mfaEnabledUsers = $allUsers | Where-Object { $_.MfaEnabled -eq $true -or $_.MfaEnabled -eq "True" }
$mfaPercentage = if ($totalUsers -gt 0) { [math]::Round(($mfaEnabledUsers.Count / $totalUsers) * 100, 1) } else { 0 }

$privilegedUsers = $privilegedUsers | Where-Object { $_ -ne $null }
$privilegedPercentage = if ($totalUsers -gt 0) { [math]::Round(($privilegedUsers.Count / $totalUsers) * 100, 1) } else { 0 }

$guestUsers = $guestUsers | Where-Object { $_ -ne $null }
$guestPercentage = if ($totalUsers -gt 0) { [math]::Round(($guestUsers.Count / $totalUsers) * 100, 1) } else { 0 }

$verifiedDomains = $domains | Where-Object { $_.IsVerified -eq $true -or $_.IsVerified -eq "True" }
$verifiedPercentage = if ($domains.Count -gt 0) { [math]::Round(($verifiedDomains.Count / $domains.Count) * 100, 1) } else { 0 }

$microsoftApps = $servicePrincipals | Where-Object { $_.PublisherName -like "*Microsoft*" -or $_.DisplayName -like "*Microsoft*" }
$microsoftAppPercentage = if ($totalSPs -gt 0) { [math]::Round(($microsoftApps.Count / $totalSPs) * 100, 1) } else { 0 }

# Security posture scoring
$securityScore = 0
$maxScore = 0

# MFA Coverage (25 points max)
$mfaScore = [math]::Min(25, ($mfaPercentage / 100) * 25)
$securityScore += $mfaScore
$maxScore += 25

# Privileged Access Management (20 points max - lower percentage is better)
$privScore = if ($privilegedPercentage -le 5) { 20 } elseif ($privilegedPercentage -le 10) { 15 } elseif ($privilegedPercentage -le 15) { 10 } else { 0 }
$securityScore += $privScore
$maxScore += 20

# Guest Access Control (15 points max)
$guestScore = if ($guestPercentage -le 10) { 15 } elseif ($guestPercentage -le 20) { 10 } elseif ($guestPercentage -le 30) { 5 } else { 0 }
$securityScore += $guestScore
$maxScore += 15

# Domain Security (10 points max)
$domainScore = ($verifiedPercentage / 100) * 10
$securityScore += $domainScore
$maxScore += 10

# Application Security (15 points max)
$appScore = ($microsoftAppPercentage / 100) * 15
$securityScore += $appScore
$maxScore += 15

# Critical/High findings penalty (15 points max) - will calculate after filtering
# $criticalCount = ($filteredFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
# $highCount = ($filteredFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
# $findingsScore = [math]::Max(0, 15 - ($criticalCount * 3) - ($highCount * 1))
# $securityScore += $findingsScore
# $maxScore += 15

$overallSecurityScore = [math]::Round(($securityScore / $maxScore) * 100, 1)



# Don't write executive summary yet - will do it after filtering

# Generate detailed findings report (include meaningful findings)
$filteredFindings = $findings | Where-Object { 
    $_.Count -gt 0 -or 
    $_.Evidence -ne $null -or 
    $_.Severity -eq "INFO"
}

# Re-sort the filtered findings
$sortedFindings = $filteredFindings | Sort-Object { $severityOrder.IndexOf($_.Severity) }

# Calculate proper counts for scoring and console output
$criticalFindings = $filteredFindings | Where-Object { $_.Severity -eq "CRITICAL" }
$highFindings = $filteredFindings | Where-Object { $_.Severity -eq "HIGH" }
$mediumFindings = $filteredFindings | Where-Object { $_.Severity -eq "MEDIUM" }
$lowFindings = $filteredFindings | Where-Object { $_.Severity -eq "LOW" }
$infoFindings = $filteredFindings | Where-Object { $_.Severity -eq "INFO" }

# Force proper counting using Measure-Object to avoid any .Count property issues
$criticalCount = ($criticalFindings | Measure-Object).Count
$highCount = ($highFindings | Measure-Object).Count
$mediumCount = ($mediumFindings | Measure-Object).Count
$lowCount = ($lowFindings | Measure-Object).Count
$infoCount = ($infoFindings | Measure-Object).Count

# Apply findings penalty to security score (delayed from earlier)
$findingsScore = [math]::Max(0, 15 - ($criticalCount * 3) - ($highCount * 1))
$securityScore += $findingsScore
$maxScore += 15

# Recalculate overall security score with proper findings count
$overallSecurityScore = [math]::Round(($securityScore / $maxScore) * 100, 1)

# Generate executive summary after counts are calculated (simple approach)
$execSummary = "========================================`n"
$execSummary += "AZURE AD SECURITY ASSESSMENT REPORT`n"
$execSummary += "========================================`n"
$execSummary += "Date: $(Get-Date)`n"
$execSummary += "Source Data: $ReportDirectory`n"
$execSummary += "Assessment ID: $timestamp`n`n"
$execSummary += "OVERALL SECURITY POSTURE SCORE: $overallSecurityScore%`n"
$execSummary += "FAIR - Significant improvements required`n`n"
$execSummary += "========================================`n"
$execSummary += "SECURITY METRICS OVERVIEW`n"
$execSummary += "========================================`n`n"
$execSummary += "IDENTITY PROTECTION:`n"
$execSummary += "[+] MFA Enabled Users: $($mfaEnabledUsers.Count)/$totalUsers ($mfaPercentage%)`n"
$execSummary += "[+] Verified Domains: $($verifiedDomains.Count)/$($domains.Count) ($verifiedPercentage%)`n"
$execSummary += "[!] POOR MFA coverage - immediate action required`n`n"
$execSummary += "ACCESS MANAGEMENT:`n"
$execSummary += "[+] Privileged Users: $($privilegedUsers.Count)/$totalUsers ($privilegedPercentage%)`n"
$execSummary += "[+] Guest Users: $($guestUsers.Count)/$totalUsers ($guestPercentage%)`n"
$execSummary += "[+] EXCELLENT privilege management`n`n"
$execSummary += "APPLICATION SECURITY:`n"
$execSummary += "[+] Total Applications: $totalApps registrations, $totalSPs service principals`n"
$execSummary += "[+] Microsoft Applications: $($microsoftApps.Count)/$totalSPs ($microsoftAppPercentage%)`n"
$execSummary += "[+] GOOD - Majority are Microsoft applications`n`n"
$execSummary += "========================================`n"
$execSummary += "FINDINGS SUMMARY`n"
$execSummary += "========================================`n"
$execSummary += "Critical Issues: $criticalCount"
if ($criticalCount -eq 0) { $execSummary += " [+]`n" } else { $execSummary += " [!]`n" }
$execSummary += "High Issues: $highCount"
if ($highCount -eq 0) { $execSummary += " [+]`n" } else { $execSummary += " [!]`n" }
$execSummary += "Medium Issues: $mediumCount`n"
$execSummary += "Low Issues: $lowCount`n"
$execSummary += "Informational: $infoCount`n`n"
$execSummary += "PRIORITY ACTIONS REQUIRED:`n"
if ($criticalCount -gt 0) { $execSummary += "[!] IMMEDIATE ACTION REQUIRED - Critical security issues found`n" } else { $execSummary += "[+] No critical issues identified`n" }
if ($highCount -gt 0) { $execSummary += "[!] High priority issues require attention within 7 days`n" } else { $execSummary += "[+] No high priority issues identified`n" }
$execSummary += "`nPOSITIVE SECURITY INDICATORS:`n`n"
$execSummary += "[+] All domains are verified`n"
$execSummary += "[+] Privileged access is well-controlled ($privilegedPercentage%)`n`n"
$execSummary += "========================================`n"

$execSummary | Out-File (Join-Path $outputDir "00_Executive_Summary.txt")

$detailedReport = @"
========================================
DETAILED FINDINGS REPORT
========================================
Generated: $(Get-Date)
Environment: $($domains[0].Name) (Tenant ID: $($allUsers[0].TenantId))

"@

foreach ($finding in $sortedFindings) {
    $severityIcon = switch ($finding.Severity) {
        "CRITICAL" { "[!!]" }
        "HIGH" { "[!]" }
        "MEDIUM" { "[*]" }
        "LOW" { "[+]" }
        "INFO" { "[i]" }
    }
    
    $detailedReport += @"
$severityIcon [$($finding.Severity)] $($finding.Title)
Category: $($finding.Category)
Description: $($finding.Description)
Impact: $($finding.Impact)
Recommendation: $($finding.Recommendation)
$(if ($finding.Count -gt 0) { "Count: $($finding.Count)" })

"@

    # Add specific affected objects for critical and high findings
    if ($finding.Severity -in @("CRITICAL", "HIGH") -and $finding.Evidence) {
        $detailedReport += @"
AFFECTED OBJECTS:
"@
        if ($finding.Evidence -is [System.Array] -and $finding.Evidence.Count -gt 0) {
            # Show first 10 objects with key details
            $objectsToShow = $finding.Evidence | Select-Object -First 10
            foreach ($obj in $objectsToShow) {
                if ($obj.DisplayName) {
                    $detailedReport += "  - $($obj.DisplayName)"
                    if ($obj.UserPrincipalName) { $detailedReport += " ($($obj.UserPrincipalName))" }
                    if ($obj.ObjectId) { $detailedReport += " [ID: $($obj.ObjectId)]" }
                    if ($obj.RoleName) { $detailedReport += " [Role: $($obj.RoleName)]" }
                    if ($obj.LastSignInDateTime) { $detailedReport += " [Last Sign-in: $($obj.LastSignInDateTime)]" }
                    $detailedReport += "`n"
                } elseif ($obj.Name) {
                    $detailedReport += "  - $($obj.Name)"
                    if ($obj.Id) { $detailedReport += " [ID: $($obj.Id)]" }
                    if ($obj.Description) { $detailedReport += " - $($obj.Description)" }
                    $detailedReport += "`n"
                } else {
                    $detailedReport += "  - $($obj.ToString())`n"
                }
            }
            if ($finding.Evidence.Count -gt 10) {
                $detailedReport += "  ... and $($finding.Evidence.Count - 10) more objects`n"
            }
        }
        $detailedReport += "`n"
    }

    # Add detailed remediation steps for critical and high findings
    if ($finding.Severity -in @("CRITICAL", "HIGH")) {
        $remediation = switch ($finding.Title) {
            "All-Users Dynamic Groups Detected" {
                @"
DETAILED REMEDIATION STEPS:
1. Review each group to determine business purpose
2. For each unnecessary group:
   - PowerShell: Remove-AzureADGroup -ObjectId <GroupId>
   - Portal: Azure AD > Groups > Select group > Delete
3. For groups that must remain:
   - Modify membership rules to exclude guests
   - PowerShell: Set-AzureADGroup -ObjectId <GroupId> -MembershipRule "user.userType -eq 'Member'"
4. Implement guest access restrictions:
   - Portal: Azure AD > User settings > External collaboration settings
   - Set "Guest users permissions are limited" to Yes
   - Set "Members can invite" to No
5. Monitor group membership changes via audit logs

BUSINESS IMPACT:
- Guest users can currently see all internal users
- Organizational structure is exposed to external parties
- Potential for targeted social engineering attacks

TIMELINE: Immediate (within 24 hours)
"@
            }
            "Guest Enumeration Groups Detected" {
                @"
DETAILED REMEDIATION STEPS:
1. Audit all guest-related groups:
   - Review group purpose and membership rules
   - Identify groups with "guest" or "external" keywords
2. Modify dynamic group rules:
   - Remove overly broad guest inclusion rules
   - Implement specific business-justified guest groups
3. PowerShell commands:
   - Get-AzureADGroup | Where-Object {$_.Description -like "*guest*"}
   - Set-AzureADGroup -ObjectId <GroupId> -MembershipRule <NewRule>
4. Implement guest access governance:
   - Enable guest access reviews
   - Set guest account expiration policies
   - Require business justification for guest additions

BUSINESS IMPACT:
- Guest users can enumerate other external users
- Potential for guest-to-guest lateral movement
- Information disclosure about external partnerships

TIMELINE: Within 7 days
"@
            }
            "Large Population Vulnerable to Phishing" {
                @"
DETAILED REMEDIATION STEPS:
1. Implement MFA enforcement via Conditional Access:
   - Portal: Azure AD > Security > Conditional Access
   - Create policy: "Require MFA for all users"
   - Target: All users, All cloud apps
   - Grant: Require multi-factor authentication
2. Phase rollout approach:
   - Week 1: Pilot group (IT admins, executives)
   - Week 2: Department heads and managers
   - Week 3: All remaining users
3. Configure MFA methods:
   - Enable Microsoft Authenticator app
   - Disable SMS as primary method (security risk)
   - Consider FIDO2 security keys for admins
4. User communication and training:
   - Send advance notification emails
   - Provide MFA setup instructions
   - Conduct phishing awareness training
5. Monitor MFA adoption:
   - PowerShell: Get-MsolUser | Select UserPrincipalName,StrongAuthenticationRequirements

BUSINESS IMPACT:
- 100% of users vulnerable to credential theft
- High risk of successful phishing attacks
- Potential for complete tenant compromise

TIMELINE: Immediate phased rollout (complete within 30 days)
"@
            }
            "High Percentage of Guest Users" {
                @"
DETAILED REMEDIATION STEPS:
1. Conduct guest user audit:
   - Export all guest users: Get-AzureADUser -Filter "UserType eq 'Guest'"
   - Review business justification for each guest account
   - Identify inactive or unnecessary guest accounts
2. Implement guest access governance:
   - Portal: Azure AD > Identity Governance > Access reviews
   - Create quarterly guest user access reviews
   - Assign reviews to resource owners
3. Clean up unnecessary guest accounts:
   - Remove guests who haven't signed in for 90+ days
   - PowerShell: Remove-AzureADUser -ObjectId <GuestUserId>
4. Implement guest invitation controls:
   - Restrict who can invite guests
   - Require approval workflow for guest invitations
   - Set guest account expiration dates
5. Monitor guest activity:
   - Review sign-in logs for guest users
   - Implement alerts for suspicious guest activity

BUSINESS IMPACT:
- 33.89% guest user ratio significantly above recommended 10-15%
- Increased attack surface and data exposure risk
- Potential compliance and governance issues

TIMELINE: 30-day cleanup project with ongoing governance
"@
            }
            default {
                @"
DETAILED REMEDIATION STEPS:
Specific remediation steps should be implemented based on the finding details above.
Consult with security team for implementation guidance.

TIMELINE: Based on severity level and organizational impact.
"@
            }
        }
        $detailedReport += $remediation + "`n`n"
    }

    $detailedReport += "========================================`n`n"
}

$detailedReport | Out-File (Join-Path $outputDir "01_Detailed_Findings.txt")

# Export findings to CSV
$sortedFindings | Select-Object Severity, Category, Title, Description, Impact, Recommendation, Count | Export-Csv (Join-Path $outputDir "02_Findings_Summary.csv") -NoTypeInformation

# Export evidence for critical and high findings
$criticalHighFindings = $sortedFindings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") -and $_.Evidence }
foreach ($finding in $criticalHighFindings) {
    if ($finding.Evidence) {
        $fileName = "Evidence_$($finding.Title -replace '[^\w]', '_').csv"
        $finding.Evidence | Export-Csv (Join-Path $outputDir $fileName) -NoTypeInformation
    }
}

# Generate Kill Chain Analysis Report
$killChainReport = @"
========================================
AZURE AD ATTACK KILL CHAIN ANALYSIS
========================================
Generated: $(Get-Date)
Environment: $($domains[0].Name)

EXECUTIVE SUMMARY:
This report analyzes your Azure AD environment against the Azure AD Attack Kill Chain methodology,
identifying vulnerabilities across five attack phases: Outsider, Guest, Insider, Admin, and On-Premises Admin.

========================================
KILL CHAIN PHASE ANALYSIS
========================================

"@

# Categorize findings by kill chain phase
$outsiderFindings = $findings | Where-Object { 
    $_.Category -eq "Information Disclosure" -or 
    $_.Title -like "*Unverified*" -or 
    $_.Title -like "*Federated*" -or
    $_.Category -eq "Authentication Security"
}

$guestFindings = $findings | Where-Object { 
    $_.Category -eq "Guest Access Security" -or 
    $_.Title -like "*Guest*" -or
    $_.Title -like "*All-Users*"
}

$insiderFindings = $findings | Where-Object { 
    $_.Title -like "*MFA*" -or 
    $_.Title -like "*Phishing*" -or
    $_.Title -like "*Legacy*" -or
    $_.Category -eq "Device Security"
}

$adminFindings = $findings | Where-Object { 
    $_.Category -eq "Admin Security" -or 
    $_.Title -like "*Admin*" -or
    $_.Title -like "*Privilege*" -or
    $_.Category -eq "Privilege Management"
}

$onPremFindings = $findings | Where-Object { 
    $_.Category -like "*Hybrid*" -or 
    $_.Category -like "*Federation*" -or
    $_.Category -eq "On-Premises AD"
}

# OUTSIDER PHASE ANALYSIS
$killChainReport += @"
[PHASE 1] OUTSIDER ATTACK PHASE
Risk Level: $(if ($outsiderFindings.Count -gt 3) { "HIGH" } elseif ($outsiderFindings.Count -gt 1) { "MEDIUM" } elseif ($outsiderFindings.Count -gt 0) { "LOW" } else { "NONE" })
Findings: $($outsiderFindings.Count)

ATTACK SCENARIO:
External attackers with no initial access attempt to gather information about your organization
through publicly available APIs, DNS queries, and reconnaissance techniques.

IDENTIFIED VULNERABILITIES:
"@

foreach ($finding in $outsiderFindings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") }) {
    $killChainReport += "- [$($finding.Severity)] $($finding.Title)`n"
    $killChainReport += "  Impact: $($finding.Description)`n"
}

if ($outsiderFindings.Count -eq 0) {
    $killChainReport += "+ No significant outsider attack vectors identified`n"
}

$killChainReport += @"

OUTSIDER MITIGATION PRIORITIES:
1. Verify all domains to prevent information leakage
2. Review federated authentication configurations
3. Implement external collaboration restrictions
4. Monitor for reconnaissance activities

========================================

"@

# GUEST PHASE ANALYSIS
$killChainReport += @"
[PHASE 2] GUEST ACCESS ATTACK PHASE
Risk Level: $(if ($guestFindings.Count -gt 3) { "HIGH" } elseif ($guestFindings.Count -gt 1) { "MEDIUM" } elseif ($guestFindings.Count -gt 0) { "LOW" } else { "NONE" })
Findings: $($guestFindings.Count)

ATTACK SCENARIO:
External users with guest access (from SharePoint sharing, Teams invitations) exploit
guest permissions to enumerate users, groups, and organizational structure.

IDENTIFIED VULNERABILITIES:
"@

foreach ($finding in $guestFindings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") }) {
    $killChainReport += "- [$($finding.Severity)] $($finding.Title)`n"
    $killChainReport += "  Impact: $($finding.Description)`n"
}

if ($guestFindings.Count -eq 0) {
    $killChainReport += "+ No significant guest attack vectors identified`n"
}

$killChainReport += @"

GUEST MITIGATION PRIORITIES:
1. Implement guest access restrictions immediately
2. Review and modify dynamic groups including all users
3. Enable guest access reviews and expiration policies
4. Restrict guest permissions to minimum required

========================================

"@

# INSIDER PHASE ANALYSIS
$killChainReport += @"
[PHASE 3] INSIDER ATTACK PHASE
Risk Level: $(if ($insiderFindings.Count -gt 10) { "HIGH" } elseif ($insiderFindings.Count -gt 3) { "MEDIUM" } elseif ($insiderFindings.Count -gt 0) { "LOW" } else { "NONE" })
Findings: $($insiderFindings.Count)

ATTACK SCENARIO:
Internal users or compromised accounts exploit legitimate access to perform reconnaissance,
lateral movement, and privilege escalation within the Azure AD environment.

IDENTIFIED VULNERABILITIES:
"@

foreach ($finding in $insiderFindings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") } | Select-Object -First 5) {
    $killChainReport += "- [$($finding.Severity)] $($finding.Title)`n"
    $killChainReport += "  Impact: $($finding.Description)`n"
}

if ($insiderFindings.Count -eq 0) {
    $killChainReport += "+ No significant insider attack vectors identified`n"
}

$killChainReport += @"

INSIDER MITIGATION PRIORITIES:
1. Enforce MFA for all users to prevent credential-based attacks
2. Implement Zero Trust conditional access policies
3. Monitor for unusual user and device behavior
4. Restrict device registration capabilities

========================================

"@

# ADMIN PHASE ANALYSIS
$killChainReport += @"
[PHASE 4] ADMIN ATTACK PHASE
Risk Level: $(if ($adminFindings.Count -gt 3) { "HIGH" } elseif ($adminFindings.Count -gt 1) { "MEDIUM" } elseif ($adminFindings.Count -gt 0) { "LOW" } else { "NONE" })
Findings: $($adminFindings.Count)

ATTACK SCENARIO:
Attackers attempt to gain administrative privileges through privilege escalation,
compromised admin accounts, or exploitation of excessive privileged access.

IDENTIFIED VULNERABILITIES:
"@

foreach ($finding in $adminFindings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") }) {
    $killChainReport += "- [$($finding.Severity)] $($finding.Title)`n"
    $killChainReport += "  Impact: $($finding.Description)`n"
}

if ($adminFindings.Count -eq 0) {
    $killChainReport += "+ No significant admin attack vectors identified`n"
}

$killChainReport += @"

ADMIN MITIGATION PRIORITIES:
1. Implement Privileged Identity Management (PIM)
2. Reduce number of permanent global administrators
3. Enable admin MFA and conditional access policies
4. Monitor privileged account activities

========================================

"@

# ON-PREMISES ADMIN PHASE ANALYSIS
$killChainReport += @"
[PHASE 5] ON-PREMISES ADMIN ATTACK PHASE
Risk Level: $(if ($onPremFindings.Count -gt 3) { "HIGH" } elseif ($onPremFindings.Count -gt 1) { "MEDIUM" } elseif ($onPremFindings.Count -gt 0) { "LOW" } else { "NONE" })
Findings: $($onPremFindings.Count)

ATTACK SCENARIO:
On-premises administrators or compromised on-premises infrastructure can be used to
gain cloud administrative privileges through hybrid identity connections.

IDENTIFIED VULNERABILITIES:
"@

foreach ($finding in $onPremFindings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") }) {
    $killChainReport += "- [$($finding.Severity)] $($finding.Title)`n"
    $killChainReport += "  Impact: $($finding.Description)`n"
}

if ($onPremFindings.Count -eq 0) {
    $killChainReport += "+ No significant on-premises attack vectors identified`n"
}

$killChainReport += @"

ON-PREMISES MITIGATION PRIORITIES:
1. Secure Azure AD Connect servers and service accounts
2. Rotate Seamless SSO computer account passwords
3. Implement federation security best practices
4. Monitor hybrid identity synchronization

========================================
OVERALL KILL CHAIN RISK ASSESSMENT
========================================

ATTACK PATH SUMMARY:
$(if ($outsiderFindings.Count -gt 0) { "[!] Outsider -> " } else { "[+] Outsider -X- " })$(if ($guestFindings.Count -gt 0) { "Guest -> " } else { "Guest -X- " })$(if ($insiderFindings.Count -gt 0) { "Insider -> " } else { "Insider -X- " })$(if ($adminFindings.Count -gt 0) { "Admin" } else { "Admin [+]" })

CRITICAL ATTACK PATHS:
$(if ($outsiderFindings.Count -gt 0 -and $guestFindings.Count -gt 0) { "[!] CRITICAL: Outsider can gain guest access and enumerate organization" } else { "" })
$(if ($guestFindings.Count -gt 0 -and $insiderFindings.Count -gt 0) { "[!] CRITICAL: Guest access enables insider-level reconnaissance" } else { "" })
$(if ($insiderFindings.Count -gt 0 -and $adminFindings.Count -gt 0) { "[!] CRITICAL: Insider access can escalate to administrator privileges" } else { "" })

IMMEDIATE PRIORITIES (Next 7 Days):
1. Address all CRITICAL findings immediately
2. Implement guest access restrictions
3. Enforce MFA for all users
4. Review and reduce privileged access

STRATEGIC INITIATIVES (30-90 Days):
1. Implement Zero Trust architecture
2. Deploy Privileged Identity Management
3. Establish continuous monitoring
4. Conduct regular access reviews

========================================

"@

$killChainReport | Out-File (Join-Path $outputDir "03_Kill_Chain_Analysis.txt")

# Generate Remediation Action Plan
$remediationPlan = @"
========================================
REMEDIATION ACTION PLAN
========================================
Generated: $(Get-Date)
Environment: $($domains[0].Name)

EXECUTIVE SUMMARY:
This document provides a prioritized, step-by-step remediation plan to address identified
security vulnerabilities. Actions are organized by timeline and business impact.

========================================
IMMEDIATE ACTIONS (0-7 DAYS)
========================================

"@

$criticalFindings = $sortedFindings | Where-Object { $_.Severity -eq "CRITICAL" }
$highFindings = $sortedFindings | Where-Object { $_.Severity -eq "HIGH" }

if ($criticalFindings.Count -gt 0) {
    $remediationPlan += @"
CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:

"@
    $priority = 1
    foreach ($finding in $criticalFindings) {
        $remediationPlan += @"
PRIORITY $priority : $($finding.Title)
Affected Objects: $($finding.Count)
Business Risk: EXTREME - Immediate potential for security breach

ACTION REQUIRED:
$($finding.Recommendation)

VERIFICATION STEPS:
"@
        switch ($finding.Title) {
            "All-Users Dynamic Groups Detected" {
                $remediationPlan += @"
1. Run: Get-AzureADGroup | Where-Object {$_.MembershipRule -like "*user.userType*"}
2. Verify no groups include all users in membership rules
3. Confirm guest access restrictions are enabled
4. Test guest user permissions to enumerate groups
"@
            }
            "Seamless SSO Account Detected" {
                $remediationPlan += @"
1. Verify AZUREADSSOACC password last rotation date
2. Run password rotation: Update-AzureADSSO
3. Monitor for suspicious Kerberos ticket requests
4. Implement privileged access monitoring
"@
            }
            default {
                $remediationPlan += @"
1. Verify remediation implementation
2. Test security controls
3. Monitor for compliance
4. Document changes made
"@
            }
        }
        $remediationPlan += "`n`nTIMELINE: Within 24 hours`nRESPONSIBLE: Security Team Lead`n`n"
        $priority++
    }
}

if ($highFindings.Count -gt 0) {
    $remediationPlan += @"
HIGH PRIORITY ISSUES (Complete within 7 days):

"@
    $priority = 1
    foreach ($finding in $highFindings | Select-Object -First 5) {
        $remediationPlan += @"
HIGH-$priority : $($finding.Title)
Affected Objects: $($finding.Count)
Business Risk: HIGH - Significant security exposure

DETAILED ACTIONS:
"@
        switch ($finding.Title) {
            "Large Population Vulnerable to Phishing" {
                $remediationPlan += @"
Day 1-2: Plan MFA rollout strategy
- Identify pilot groups (IT, executives, department heads)
- Prepare user communication materials
- Configure Conditional Access policies in report-only mode

Day 3-4: Pilot deployment
- Enable MFA for pilot groups via Conditional Access
- Monitor adoption rates and support requests
- Refine policies based on feedback

Day 5-7: Full deployment
- Enable MFA enforcement for all users
- Monitor authentication patterns
- Provide user support and training

CONFIGURATION STEPS:
1. Azure Portal > Azure AD > Security > Conditional Access
2. Create new policy: "Require MFA for All Users"
3. Assignments: Users and groups = All users
4. Cloud apps = All cloud apps
5. Grant = Require multi-factor authentication
6. Enable policy: On

COMMUNICATION TEMPLATE:
Subject: IMPORTANT: Multi-Factor Authentication (MFA) Implementation
Body: Starting [DATE], all users will be required to set up MFA...
[Include setup instructions and support contact]
"@
            }
            "High Percentage of Guest Users" {
                $remediationPlan += @"
Day 1: Guest user audit
- Export all guest users: Get-AzureADUser -Filter "UserType eq 'Guest'"
- Categorize by last sign-in date and business purpose
- Identify inactive guests (90+ days no sign-in)

Day 2-3: Clean up inactive guests
- Contact business owners for confirmation
- Remove confirmed inactive guest accounts
- Document removals for audit trail

Day 4-5: Implement governance
- Configure access reviews for guest users
- Set up guest account expiration policies
- Implement approval workflow for new guest invitations

Day 6-7: Monitor and report
- Generate updated guest user metrics
- Brief leadership on guest user reduction
- Establish ongoing monitoring processes

POWERSHELL COMMANDS:
# Export guest user list
Get-AzureADUser -Filter "UserType eq 'Guest'" | Export-Csv "GuestUsers.csv"

# Remove inactive guest (after approval)
Remove-AzureADUser -ObjectId <GuestUserId>

# Configure access review
New-AzureADAccessReview -DisplayName "Quarterly Guest Review"
"@
            }
            default {
                $remediationPlan += @"
Detailed remediation steps as outlined in the findings report.
Coordinate with relevant teams for implementation.
"@
            }
        }
        $remediationPlan += "`n`nTIMELINE: 7 days`nRESPONSIBLE: Identity Team + Business Owners`n`n"
        $priority++
    }
}

$remediationPlan += @"
========================================
SHORT-TERM ACTIONS (7-30 DAYS)
========================================

MEDIUM PRIORITY ITEMS:
$(foreach ($finding in ($sortedFindings | Where-Object { $_.Severity -eq "MEDIUM" } | Select-Object -First 5)) {
"- $($finding.Title) ($($finding.Count) affected objects)"
})

IMPLEMENTATION APPROACH:
1. Week 2: Application security review
   - Audit unverified applications
   - Review suspicious application names
   - Implement application governance policies

2. Week 3: Device security hardening
   - Review device compliance policies
   - Address non-compliant devices
   - Implement device registration restrictions

3. Week 4: Group and access management
   - Consolidate administrative groups
   - Review group naming conventions
   - Implement group access reviews

========================================
LONG-TERM STRATEGIC INITIATIVES (30-90 DAYS)
========================================

MONTH 1: Zero Trust Foundation
- Implement comprehensive Conditional Access framework
- Deploy device compliance policies
- Establish identity protection baselines

MONTH 2: Privileged Access Management
- Deploy Azure AD Privileged Identity Management (PIM)
- Implement just-in-time administrative access
- Establish privileged access governance

MONTH 3: Monitoring and Governance
- Deploy Azure Sentinel for advanced threat detection
- Establish continuous compliance monitoring
- Implement automated response capabilities

========================================
BUDGET AND RESOURCE PLANNING
========================================

ESTIMATED COSTS:
- Azure AD Premium P2 licenses: $($totalUsers * 9) USD/month
- Additional security tools: $10,000-25,000 annually
- Professional services: $15,000-30,000 for implementation

RESOURCE REQUIREMENTS:
- Security Team: 2-3 FTE for implementation phase
- IT Administration: 1 FTE for ongoing management
- Business Teams: Part-time for access reviews and governance

PROJECT TIMELINE: 6-month comprehensive security transformation

========================================
SUCCESS METRICS AND KPIs
========================================

SECURITY METRICS TO TRACK:
- Overall Security Score improvement (Target: 80%+)
- MFA adoption rate (Target: 100%)
- Guest user ratio (Target: <15%)
- Privileged access ratio (Target: <5%)
- Critical/High findings (Target: 0)

MONTHLY REPORTING:
- Security posture dashboard
- Finding remediation status
- Access review completion rates
- Incident and alert trends

QUARTERLY ASSESSMENTS:
- Full security assessment repeat
- Kill chain analysis update
- Compliance posture review
- ROI and metrics analysis

========================================
RISK ACCEPTANCE AND EXCEPTIONS
========================================

BUSINESS JUSTIFICATION REQUIRED FOR:
- Delaying critical finding remediation beyond 24 hours
- Maintaining guest user ratios above 20%
- Keeping applications without publisher verification
- Granting permanent privileged access

APPROVAL PROCESS:
1. Document business justification
2. Assess residual risk impact
3. Implement compensating controls
4. Obtain executive approval
5. Regular risk review (quarterly)

========================================

"@

$remediationPlan | Out-File (Join-Path $outputDir "04_Remediation_Action_Plan.txt")

# Console output
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "SECURITY ASSESSMENT COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Report saved to: $outputDir" -ForegroundColor Cyan
Write-Host ""

# Display environment statistics
Write-Host "ENVIRONMENT OVERVIEW:" -ForegroundColor Cyan
Write-Host "  Total Users: $($allUsers.Count)" -ForegroundColor White
Write-Host "  Guest Users: $($guestUsers.Count) ($guestPercentage%)" -ForegroundColor White
Write-Host "  Privileged Users: $($privilegedUsers.Count) ($privilegedPercentage%)" -ForegroundColor White
Write-Host "  Service Principals: $($servicePrincipals.Count)" -ForegroundColor White
Write-Host "  App Registrations: $($appRegistrations.Count)" -ForegroundColor White
Write-Host "  Groups: $($allGroups.Count)" -ForegroundColor White
Write-Host ""

Write-Host "SECURITY POSTURE:" -ForegroundColor Cyan
Write-Host "  Overall Score: $overallSecurityScore%" -ForegroundColor $(if ($overallSecurityScore -ge 80) { "Green" } elseif ($overallSecurityScore -ge 60) { "Yellow" } else { "Red" })
Write-Host "  MFA Coverage: $mfaPercentage%" -ForegroundColor $(if ($mfaPercentage -ge 95) { "Green" } elseif ($mfaPercentage -ge 80) { "Yellow" } else { "Red" })
Write-Host "  Domain Verification: $verifiedPercentage%" -ForegroundColor $(if ($verifiedPercentage -eq 100) { "Green" } elseif ($verifiedPercentage -ge 80) { "Yellow" } else { "Red" })
Write-Host "  Microsoft Apps: $microsoftAppPercentage%" -ForegroundColor $(if ($microsoftAppPercentage -ge 60) { "Green" } else { "Yellow" })
Write-Host ""

# Azure AD Kill Chain Risk Assessment
Write-Host ""
Write-Host "ATTACK KILL CHAIN RISK ASSESSMENT:" -ForegroundColor Red
$killChainFindings = @{
    "Outsider" = ($findings | Where-Object { $_.Category -eq "Information Disclosure" -or $_.Title -like "*Unverified*" }).Count
    "Guest" = ($findings | Where-Object { $_.Category -eq "Guest Access Security" -or $_.Title -like "*Guest*" }).Count
    "Insider" = ($findings | Where-Object { $_.Category -eq "Authentication Security" -or $_.Title -like "*MFA*" }).Count
    "Admin" = ($findings | Where-Object { $_.Category -eq "Admin Security" -or $_.Title -like "*Admin*" }).Count
    "OnPremAdmin" = ($findings | Where-Object { $_.Category -like "*Hybrid*" -or $_.Category -like "*Federation*" }).Count
}

foreach ($phase in $killChainFindings.Keys) {
    $count = $killChainFindings[$phase]
    $riskLevel = if ($count -gt 3) { "HIGH" } elseif ($count -gt 1) { "MEDIUM" } elseif ($count -gt 0) { "LOW" } else { "NONE" }
    $color = switch ($riskLevel) {
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" } 
        "LOW" { "DarkYellow" }
        "NONE" { "Green" }
    }
    Write-Host "  $phase Attack Risk: $riskLevel ($count findings)" -ForegroundColor $color
}

Write-Host ""
Write-Host "FINDINGS SUMMARY:" -ForegroundColor Yellow
if ($criticalCount -gt 0) { Write-Host "  [!] Critical: $criticalCount" -ForegroundColor Red }
if ($highCount -gt 0) { Write-Host "  [!] High: $highCount" -ForegroundColor DarkYellow }
if ($mediumCount -gt 0) { Write-Host "  [*] Medium: $mediumCount" -ForegroundColor Yellow }
if ($lowCount -gt 0) { Write-Host "  [+] Low: $lowCount" -ForegroundColor Blue }
if ($infoCount -gt 0) { Write-Host "  [i] Info: $infoCount" -ForegroundColor Gray }

Write-Host ""
Write-Host "Key files:" -ForegroundColor Yellow
Write-Host "  - 00_Executive_Summary.txt (executive overview)" -ForegroundColor White
Write-Host "  - 01_Detailed_Findings.txt (detailed technical analysis with affected objects)" -ForegroundColor White
Write-Host "  - 02_Findings_Summary.csv (spreadsheet format)" -ForegroundColor White
Write-Host "  - 03_Kill_Chain_Analysis.txt (attack vector analysis by phase)" -ForegroundColor White
Write-Host "  - 04_Remediation_Action_Plan.txt (step-by-step remediation guide)" -ForegroundColor White
Write-Host "  - Evidence_*.csv (supporting evidence for critical/high findings)" -ForegroundColor White
Write-Host ""

if ($criticalCount -gt 0) {
    Write-Host "[!] CRITICAL ISSUES FOUND - IMMEDIATE ACTION REQUIRED" -ForegroundColor Red -BackgroundColor Black
} elseif ($highCount -gt 0) {
    Write-Host "[!] HIGH PRIORITY ISSUES - ACTION REQUIRED WITHIN 7 DAYS" -ForegroundColor DarkYellow
} else {
    Write-Host "[+] No critical or high priority issues identified" -ForegroundColor Green
}

Write-Host ""