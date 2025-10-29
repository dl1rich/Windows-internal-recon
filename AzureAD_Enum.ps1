# Azure AD Enumeration Report Generator
# Creates timestamped reports with all enumeration data

# Create output directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "AzureAD_Report_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "[*] Starting Azure AD enumeration..." -ForegroundColor Cyan
Write-Host "[*] Output directory: $outputDir" -ForegroundColor Cyan
Write-Host ""

# Connect to Azure AD
Write-Host "[*] Connecting to Azure AD..." -ForegroundColor Yellow
Write-Host "    (Use your credentials in the popup - supports MFA)" -ForegroundColor Yellow
try {
    Connect-AzureAD -ErrorAction Stop
    Write-Host "[+] Connected to Azure AD" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to connect to Azure AD: $_" -ForegroundColor Red
    exit
}

# Connect to MSOnline
Write-Host "[*] Connecting to MSOnline..." -ForegroundColor Yellow
Write-Host "    (Use your credentials in the popup - supports MFA)" -ForegroundColor Yellow
try {
    Connect-MsolService -ErrorAction Stop
    Write-Host "[+] Connected to MSOnline" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to connect to MSOnline (some features may not work): $_" -ForegroundColor Yellow
}

Write-Host ""

# Get current user info
$currentUser = (Get-AzureADCurrentSessionInfo).Account.Id
Write-Host "[+] Connected as: $currentUser" -ForegroundColor Green
Write-Host ""

# Main report file
$mainReport = Join-Path $outputDir "00_Executive_Summary.txt"

# Start main report
@"
========================================
AZURE AD PENETRATION TEST REPORT
========================================
Date: $(Get-Date)
Tested By: $currentUser
Target Tenant: $(try{(Get-AzureADTenantDetail).DisplayName}catch{"Unknown"})
========================================

"@ | Out-File $mainReport

# Function to log and save
function Save-Report {
    param(
        [string]$Title,
        [string]$FileName,
        [scriptblock]$Command
    )
    
    Write-Host "[*] Collecting: $Title" -ForegroundColor Yellow
    
    try {
        $data = & $Command
        $filePath = Join-Path $outputDir $FileName
        
        # Save as CSV if possible
        if ($data -and $data.Count -gt 0) {
            $data | Export-Csv -Path "$filePath.csv" -NoTypeInformation -ErrorAction SilentlyContinue
            $data | Format-Table -AutoSize | Out-File -FilePath "$filePath.txt" -Width 300
            
            # Add summary to main report
            "$Title - Count: $($data.Count)" | Out-File $mainReport -Append
            
            Write-Host "    [✓] Saved: $($data.Count) items" -ForegroundColor Green
        } else {
            "No data found for $Title" | Out-File "$filePath.txt"
            Write-Host "    [!] No data found" -ForegroundColor Yellow
        }
    } catch {
        "Error collecting $Title : $_" | Out-File "$filePath.txt"
        Write-Host "    [-] Error: $_" -ForegroundColor Red
    }
}

# 1. Current session info
Save-Report -Title "Current Session Info" -FileName "01_Session_Info" -Command {
    Get-AzureADCurrentSessionInfo
}

# 2. Tenant details
Save-Report -Title "Tenant Details" -FileName "02_Tenant_Details" -Command {
    Get-AzureADTenantDetail
}

Save-Report -Title "Company Information" -FileName "03_Company_Info" -Command {
    Get-MsolCompanyInformation
}

# 3. All users
Save-Report -Title "All Users" -FileName "04_All_Users" -Command {
    Get-AzureADUser -All $true | Select-Object UserPrincipalName, DisplayName, ObjectId, AccountEnabled, UserType, Mail, JobTitle, Department, MobilePhone
}

# 4. All groups
Save-Report -Title "All Groups" -FileName "05_All_Groups" -Command {
    Get-AzureADGroup -All $true | Select-Object DisplayName, Description, ObjectId, SecurityEnabled, MailEnabled, GroupTypes
}

# 5. Privileged users (Directory Roles)
Save-Report -Title "Privileged Users" -FileName "06_Privileged_Users" -Command {
    $privilegedUsers = @()
    Get-AzureADDirectoryRole | ForEach-Object {
        $role = $_
        Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | ForEach-Object {
            $privilegedUsers += [PSCustomObject]@{
                Role = $role.DisplayName
                DisplayName = $_.DisplayName
                UserPrincipalName = $_.UserPrincipalName
                ObjectId = $_.ObjectId
                ObjectType = $_.ObjectType
            }
        }
    }
    $privilegedUsers
}

# 6. All devices
Save-Report -Title "All Devices" -FileName "07_All_Devices" -Command {
    Get-AzureADDevice -All $true | Select-Object DisplayName, DeviceId, DeviceOSType, DeviceOSVersion, IsCompliant, IsManaged, ApproximateLastLogonTimeStamp
}

# 7. MFA Status
Save-Report -Title "MFA Status" -FileName "08_MFA_Status" -Command {
    Get-MsolUser -All | Select-Object DisplayName, UserPrincipalName, @{N="MFA Status"; E={if($_.StrongAuthenticationRequirements.State){$_.StrongAuthenticationRequirements.State}else{"Disabled"}}}, BlockCredential, IsLicensed, LastPasswordChangeTimestamp
}

# 8. Conditional Access Policies
Save-Report -Title "Conditional Access Policies" -FileName "09_Conditional_Access" -Command {
    Get-AzureADMSConditionalAccessPolicy | Select-Object DisplayName, State, Id, CreatedDateTime, ModifiedDateTime
}

# 9. Service Principals
Save-Report -Title "Service Principals" -FileName "10_Service_Principals" -Command {
    Get-AzureADServicePrincipal -All $true | Select-Object DisplayName, AppId, ObjectId, ServicePrincipalType, AccountEnabled, PublisherName
}

# 10. App Registrations
Save-Report -Title "App Registrations" -FileName "11_App_Registrations" -Command {
    Get-AzureADApplication -All $true | Select-Object DisplayName, AppId, ObjectId, PublisherDomain, SignInAudience
}

# 11. Service Principal Permissions
Save-Report -Title "Service Principal Permissions" -FileName "12_SP_Permissions" -Command {
    $spPermissions = @()
    Get-AzureADServicePrincipal -All $true | ForEach-Object {
        $sp = $_
        Get-AzureADServiceAppRoleAssignment -ObjectId $_.ObjectId -ErrorAction SilentlyContinue | ForEach-Object {
            $spPermissions += [PSCustomObject]@{
                ServicePrincipal = $sp.DisplayName
                PrincipalDisplayName = $_.PrincipalDisplayName
                ResourceDisplayName = $_.ResourceDisplayName
                Id = $_.Id
            }
        }
    }
    $spPermissions
}

# 12. Guest Users
Save-Report -Title "Guest Users" -FileName "13_Guest_Users" -Command {
    Get-AzureADUser -All $true -Filter "UserType eq 'Guest'" | Select-Object UserPrincipalName, DisplayName, Mail, CreationType, AccountEnabled
}

# 13. Dynamic Groups
Save-Report -Title "Dynamic Groups" -FileName "14_Dynamic_Groups" -Command {
    Get-AzureADMSGroup -All $true | Where-Object {$_.GroupTypes -contains "DynamicMembership"} | Select-Object DisplayName, Id, MembershipRule, MembershipRuleProcessingState
}

# 14. Domains
Save-Report -Title "Verified Domains" -FileName "15_Domains" -Command {
    Get-AzureADDomain | Select-Object Name, IsVerified, IsDefault, AuthenticationType
}

# 15. OAuth Permissions (Delegated Permissions)
Save-Report -Title "OAuth2 Permission Grants" -FileName "16_OAuth_Permissions" -Command {
    Get-AzureADOAuth2PermissionGrant -All $true | Select-Object ClientId, ConsentType, PrincipalId, ResourceId, Scope
}

# 16. Group Memberships for Current User
Save-Report -Title "Your Group Memberships" -FileName "17_Your_Groups" -Command {
    $me = Get-AzureADUser -ObjectId $currentUser
    Get-AzureADUserMembership -ObjectId $me.ObjectId | Select-Object DisplayName, Description, ObjectId, SecurityEnabled
}

# 17. Your Directory Roles
Save-Report -Title "Your Directory Roles" -FileName "18_Your_Roles" -Command {
    $yourRoles = @()
    Get-AzureADDirectoryRole | ForEach-Object {
        $role = $_
        $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
        if ($members.UserPrincipalName -contains $currentUser) {
            $yourRoles += [PSCustomObject]@{
                RoleName = $role.DisplayName
                RoleDescription = $role.Description
                ObjectId = $role.ObjectId
            }
        }
    }
    $yourRoles
}

# Generate summary statistics
Write-Host ""
Write-Host "[*] Generating summary..." -ForegroundColor Cyan

$summaryStats = @"

========================================
SUMMARY STATISTICS
========================================

"@

try { $summaryStats += "Total Users: $((Get-AzureADUser -All $true).Count)`n" } catch {}
try { $summaryStats += "Total Groups: $((Get-AzureADGroup -All $true).Count)`n" } catch {}
try { $summaryStats += "Total Devices: $((Get-AzureADDevice -All $true).Count)`n" } catch {}
try { $summaryStats += "Total Service Principals: $((Get-AzureADServicePrincipal -All $true).Count)`n" } catch {}
try { $summaryStats += "Total Applications: $((Get-AzureADApplication -All $true).Count)`n" } catch {}
try { $summaryStats += "Users without MFA: $((Get-MsolUser -All | Where-Object {!$_.StrongAuthenticationRequirements.State}).Count)`n" } catch {}
try { $summaryStats += "Guest Users: $((Get-AzureADUser -All $true -Filter 'UserType eq ''Guest''').Count)`n" } catch {}

$summaryStats | Out-File $mainReport -Append

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "ENUMERATION COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Reports saved to: $outputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Key files:" -ForegroundColor Yellow
Write-Host "  - 00_Executive_Summary.txt (overview)" -ForegroundColor White
Write-Host "  - 04_All_Users.csv (all user accounts)" -ForegroundColor White
Write-Host "  - 06_Privileged_Users.csv (admins and high-privilege accounts)" -ForegroundColor White
Write-Host "  - 08_MFA_Status.csv (users without MFA)" -ForegroundColor White
Write-Host "  - 13_Guest_Users.csv (external users)" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review privileged users in 06_Privileged_Users.csv" -ForegroundColor White
Write-Host "  2. Check for users without MFA in 08_MFA_Status.csv" -ForegroundColor White
Write-Host "  3. Examine guest users in 13_Guest_Users.csv" -ForegroundColor White
Write-Host "  4. Review service principal permissions in 12_SP_Permissions.csv" -ForegroundColor White
Write-Host ""
