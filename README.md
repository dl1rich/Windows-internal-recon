# Azure AD Security Assessment Toolkit

A comprehensive PowerShell toolkit for Azure Active Directory and On-Premises Active Directory security assessment, penetration testing, and compliance auditing.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Scripts Description](#scripts-description)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Output Files](#output-files)
- [Security Scoring](#security-scoring)
- [Attack Kill Chain Analysis](#attack-kill-chain-analysis)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)

## 🎯 Overview

This toolkit provides security professionals with comprehensive tools to assess Azure AD and on-premises Active Directory environments for security vulnerabilities, misconfigurations, and attack vectors. The toolkit is based on real-world attack techniques and follows industry best practices for security assessment.

## ✨ Features

- **Comprehensive Enumeration**: Complete Azure AD tenant reconnaissance
- **Kill Chain Analysis**: Detection based on Azure AD attack kill chain methodology
- **Security Scoring**: Quantitative security posture assessment with percentages
- **Hybrid Environment Support**: Both cloud and on-premises Active Directory analysis
- **Evidence Collection**: Detailed evidence gathering for findings
- **Executive Reporting**: Business-ready reports with actionable recommendations
- **Attack Vector Detection**: Identifies specific attack paths and vulnerabilities
- **Compliance Assessment**: Maps findings to security frameworks

## 📁 Scripts Description

### 1. AzureAD_Enum.ps1
**Primary enumeration script for Azure AD reconnaissance**

- Enumerates users, groups, applications, and service principals
- Collects MFA status, conditional access policies, and device information
- Exports data to CSV files for analysis
- Smart module detection and installation
- Error handling and authentication management

**Key Data Collected:**
- All user accounts with detailed attributes
- Security groups and dynamic groups
- Privileged role assignments
- Application registrations and service principals
- Domain configurations and verification status
- Guest user accounts and permissions
- Device registration and compliance status

### 2. AzureAD_SecurityAnalyzer.ps1
**Advanced security analysis and kill chain detection**

- Analyzes enumerated data for security vulnerabilities
- Implements Azure AD kill chain attack detection
- Generates comprehensive security reports with scoring
- Provides evidence-based findings with remediation guidance
- Supports both standalone and hybrid analysis

**Key Analysis Areas:**
- Multi-factor authentication coverage
- Privileged access management
- Guest user security risks
- Application security vulnerabilities
- Information disclosure risks
- Attack vector identification
- Kill chain phase analysis

### 3. OnPrem_AD_SecurityEnum.ps1
**On-premises Active Directory security enumeration**

- Discovers Kerberoasting and ASREPRoasting vulnerabilities
- Identifies delegation misconfigurations
- Analyzes privileged account security
- Detects stale computer accounts
- Evaluates password policies and domain trusts

**Key Checks:**
- Service Principal Name (SPN) analysis
- Kerberos pre-authentication settings
- Unconstrained delegation detection
- Privileged group membership
- Computer account hygiene
- Domain trust configurations

## 🔧 Prerequisites

### PowerShell Modules Required:
- **AzureAD**: Azure Active Directory PowerShell module
- **MSOnline**: Microsoft Online Services PowerShell module (legacy)
- **ActiveDirectory**: On-premises AD module (for hybrid analysis)

### Permissions Required:

#### Azure AD:
- **Global Reader** (minimum)
- **Security Reader** (recommended)
- **Global Administrator** (for complete analysis)

#### On-Premises AD:
- **Domain Users** (minimum for basic enumeration)
- **Domain Admins** (for comprehensive analysis)
- **Account Operators** (for extended user analysis)

### System Requirements:
- PowerShell 5.1 or higher
- Windows PowerShell or PowerShell Core
- Internet connectivity for Azure AD access
- Network connectivity to domain controllers (for on-premises analysis)

## 🚀 Installation

### 1. Clone or Download Scripts
```powershell
# Download the scripts to your working directory
# Ensure all three main scripts are in the same folder
```

### 2. Install Required Modules
```powershell
# Install Azure AD modules
Install-Module -Name AzureAD -Force -AllowClobber
Install-Module -Name MSOnline -Force -AllowClobber

# Install on-premises AD module (Windows Server/RSAT required)
# On Windows 10/11:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools

# On Windows Server:
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

### 3. Set Execution Policy
```powershell
# Allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📖 Usage

### Quick Start - Azure AD Only Assessment

```powershell
# Step 1: Enumerate Azure AD
.\AzureAD_Enum.ps1

# Step 2: Analyze security posture
.\AzureAD_SecurityAnalyzer.ps1
```

### Comprehensive Hybrid Assessment

```powershell
# Step 1: Enumerate Azure AD
.\AzureAD_Enum.ps1

# Step 2: Enumerate on-premises AD (run from domain-joined machine)
.\OnPrem_AD_SecurityEnum.ps1

# Step 3: Analyze both environments
.\AzureAD_SecurityAnalyzer.ps1 -IncludeOnPrem
```

### Advanced Usage Options

```powershell
# Specify custom report directory
.\AzureAD_SecurityAnalyzer.ps1 -ReportDirectory "C:\CustomPath\Reports"

# Include on-premises analysis
.\AzureAD_SecurityAnalyzer.ps1 -IncludeOnPrem

# Analyze existing enumeration data
.\AzureAD_SecurityAnalyzer.ps1 -ReportDirectory ".\AzureAD_Enum_20241029_143022"
```

## 📊 Output Files

### Generated Reports

| File | Description | Audience |
|------|-------------|----------|
| `00_Executive_Summary.txt` | High-level security posture overview | Executives, Management |
| `01_Detailed_Findings.txt` | Complete technical findings | Security Teams, IT |
| `02_Findings_Summary.csv` | Structured findings data | Analysis, Tracking |
| `03_Evidence_*.csv` | Supporting evidence files | Technical Review |

### Enumeration Data (CSV Files)

| File | Content |
|------|---------|
| `04_All_Users.csv` | Complete user directory |
| `05_All_Groups.csv` | Security and distribution groups |
| `06_Privileged_Users.csv` | Users with administrative roles |
| `07_All_Devices.csv` | Registered and managed devices |
| `08_MFA_Status.csv` | Multi-factor authentication status |
| `09_Conditional_Access.csv` | Conditional access policies |
| `10_Service_Principals.csv` | Application service principals |
| `11_App_Registrations.csv` | Application registrations |
| `12_Directory_Roles.csv` | Directory role assignments |
| `13_Guest_Users.csv` | External user accounts |
| `15_Domains.csv` | Domain verification and configuration |

## 🏆 Security Scoring

The toolkit provides a comprehensive security score (0-100%) based on:

### Scoring Components:
- **MFA Coverage (25 points)**: Percentage of users with MFA enabled
- **Privileged Access Management (20 points)**: Control over administrative privileges
- **Guest Access Control (15 points)**: External user management
- **Domain Security (10 points)**: Domain verification status
- **Application Security (15 points)**: Microsoft vs third-party application ratio
- **Critical/High Findings Penalty (15 points)**: Deductions for security issues

### Score Interpretation:
- **80-100%**: Excellent security posture
- **60-79%**: Good security with room for improvement
- **40-59%**: Fair security requiring significant improvements
- **0-39%**: Poor security requiring immediate action

## ⚔️ Attack Kill Chain Analysis

Based on AADInternals research, the toolkit detects attack vectors across five phases:

### 1. Outsider Phase
- Public information disclosure
- Unverified domain exposure
- User enumeration vulnerabilities

### 2. Guest Access Phase
- Guest privilege escalation paths
- Information gathering through guest accounts
- Dynamic group enumeration risks

### 3. Insider Phase
- Internal reconnaissance capabilities
- Legacy authentication usage
- Bulk object creation potential

### 4. Admin Phase
- Privilege escalation to administrator
- Phishing resilience analysis
- Admin account security

### 5. On-Premises Admin Phase
- Azure AD Connect vulnerabilities
- Seamless SSO exploitation risks
- Federation certificate access

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Authentication Failures
```powershell
# Clear cached credentials
Connect-AzureAD
Connect-MsolService

# Use specific tenant
Connect-AzureAD -TenantId "your-tenant-id"
```

#### Module Import Errors
```powershell
# Force module reload
Remove-Module AzureAD, MSOnline -Force -ErrorAction SilentlyContinue
Import-Module AzureAD, MSOnline -Force
```

#### Permission Errors
- Verify account has required Azure AD roles
- Check on-premises domain permissions
- Ensure user can read Active Directory

#### Script Execution Errors
```powershell
# Check execution policy
Get-ExecutionPolicy

# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Debug Mode
```powershell
# Enable verbose output for troubleshooting
$VerbosePreference = "Continue"
.\AzureAD_SecurityAnalyzer.ps1 -Verbose
```

## 🔒 Security Considerations

### Data Protection
- Enumerated data contains sensitive organizational information
- Store reports securely and limit access
- Consider encryption for data at rest
- Follow data retention policies

### Audit Logging
- Azure AD activities are logged in sign-in logs
- On-premises enumeration may generate security events
- Review logs for legitimate assessment activities

### Permissions
- Use minimum required permissions
- Consider dedicated assessment accounts
- Implement just-in-time access for privileged operations

### Network Security
- Run from trusted, managed devices
- Use secure network connections
- Consider VPN for remote assessments

## 📈 Best Practices

### Assessment Planning
1. **Scope Definition**: Clearly define assessment boundaries
2. **Permission Approval**: Obtain proper authorization
3. **Baseline Creation**: Document current state before changes
4. **Communication**: Inform relevant teams about assessment activities

### Execution
1. **Incremental Approach**: Start with read-only enumeration
2. **Documentation**: Record all activities and findings
3. **Evidence Preservation**: Save all generated reports
4. **Validation**: Verify findings with multiple sources

### Reporting
1. **Executive Summary**: Provide business context and risk ratings
2. **Technical Details**: Include specific remediation steps
3. **Prioritization**: Rank findings by risk and effort
4. **Tracking**: Create remediation tracking mechanisms

## 🔄 Regular Assessment

### Recommended Frequency
- **Monthly**: Basic security posture checks
- **Quarterly**: Comprehensive security assessment
- **Annually**: Full penetration test style assessment
- **Ad-hoc**: After major configuration changes

### Trending Analysis
- Track security score improvements over time
- Monitor finding reduction trends
- Measure remediation effectiveness
- Identify recurring issues

## 📋 Compliance Mapping

The toolkit findings can support various compliance frameworks:

- **NIST Cybersecurity Framework**
- **ISO 27001/27002**
- **CIS Controls**
- **MITRE ATT&CK Framework**
- **Microsoft Security Baselines**

## 🆘 Support and Resources

### Documentation References
- [Azure AD Documentation](https://docs.microsoft.com/en-us/azure/active-directory/)
- [AADInternals Research](https://aadinternals.com/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/security/compass/)

### Community Resources
- Azure AD Security Community
- PowerShell Security Groups
- Information Security Forums

## ⚠️ Disclaimer

This toolkit is intended for authorized security assessments only. Users are responsible for:
- Obtaining proper authorization before use
- Complying with organizational policies
- Following applicable laws and regulations
- Protecting sensitive data discovered during assessments

The authors are not responsible for misuse of these tools or any damages resulting from their use.

## 📝 License

This project is provided as-is for educational and authorized security assessment purposes.

---

**Version**: 2.0  
**Last Updated**: October 2025  
**Compatibility**: PowerShell 5.1+, Azure AD PowerShell v2