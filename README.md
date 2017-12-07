NOTE
----

(December 7, 2017) I'm unable to maintain this module moving forward. I simply don't have access to Azure Pack anymore and therefore I'm unable to test / validate new code / PR(s). I feel uncomfortable pushing out updates for this module while sailing blind.

WapTenantPublicAPI
------------------

A PowerShell module which enables you to deploy VM Roles, Virtual Networks and SQL Databases through the Windows Azure Pack Tenant API and Tenant Public API.

Requirements
------------

Tenant **Public** Api needs to be configured for HybridTenant mode to allow token based authentication besided Cert based authentication (The Tenant API does not have this requirement).
```powershell
Unprotect-MgmtSvcConfiguration -Namespace tenantpublicapi
Set-WebConfigurationProperty -pspath IIS:\Sites\MgmtSvc-TenantPublicAPI  -filter "appSettings/add[@key='TenantServiceMode']" -name "value" -value "HybridTenant"
Protect-MgmtSvcConfiguration -Namespace tenantpublicapi
```

The Tenant Api by default does not have enough permissions in the database to function correctly. 
Permissions involved with executing stored procedures to validate CoAdmin and User Tokens are missing.
Missing permissions can be resolved by running the following TSQL script:
```sql
USE [Microsoft.MgmtSvc.Store]
GO
Grant Execute On Type::.mp.CoAdminTableType To mp_TenantAPI
Grant Execute On Object::mp.GetInvalidatedUserTokens to mp_TenantAPI
```

Get-WAPToken is capable to get the token from both the tenant auth site which comes with and is preconfigured with WAP by default and ADFS.
The function is based on the example WAP functions found in the Admin-API install directory.

Both Tenant and Admin should have the same relying party settings configured.

## Admin API functions
Started with implementation of Admin API functions. These functions are prefixed with the noun WAPAdmin.
- Get-WAPAdminSubscription [-SubscriptionId 'subscriptionid']

Examples
--------
```powershell
#example DBaaS
Get-WAPToken -URL https://sts.bgelens.nl -ADFS -Credential administrator@gelens.int
Connect-WAPAPI -Url https://api.bgelens.nl -Port 443
Get-WAPSubscription -Name Test | Select-WAPSubscription
Get-WAPSQLOffer -Name 'MySQLEditions' | Select-WAPSQLOffer
Test-WAPSQLDatabaseNameAvailable -Name 'MyNewDBName'
New-WAPSQLDatabase -Name 'MyNewDBName' -Credential AdminBen #SQL Auth
New-WAPSQLDatabase -Name 'MyNewDBName' -WindowsAuthentication -WindowsAccount 'Domain\username' #Windows Auth
Get-WAPSQLDatabase -Name 'MyNewDBName'
Get-WAPSQLDatabase -Name 'MyNewDBName' | Reset-WAPSQLDatabaseAdmin #Reset SQL User Password
Get-WAPSQLDatabase -Name 'MyNewDBName' | Resize-WAPSQLDatabase -SizeMB 2048
Get-WAPSQLDatabase -Name 'MyNewDBName' | Remove-WAPSQLDatabase

#exampl websites
Get-WAPToken -URL https://sts.bgelens.nl -ADFS -Credential administrator@gelens.int
Connect-WAPAPI -Url https://api.bgelens.nl -Port 443
Get-WAPSubscription -Name Test | Select-WAPSubscription
Get-WAPWebSpace | Select-WAPWebSpace
Test-WAPWebSiteNameAvailable -Name ben -Verbose
New-WAPWebSite -Name ben -Mode SharedFree -Verbose
Get-WAPWebSite
Get-WAPWebSite -Name ben | Get-WAPWebSitePublishingXML -OutFile C:\Users\gelensb.eu\Desktop\test.xml
Get-WAPWebSite -Name ben | Get-WAPWebSiteConfiguration
Get-WAPWebSite -Name ben | New-WAPWebSiteGitRepository
Get-WAPWebSite -Name ben | Get-WAPWebSiteGitRepository
Get-WAPWebSite -Name ben | Get-WAPWebSitePublishingInfo
Get-WAPWebSite -Name ben | Remove-WAPWebSiteGitRepository
Get-WAPWebSite -Name ben | Restart-WAPWebSite
Get-WAPWebSite -Name ben | Remove-WAPWebSite

#example deployment 1 via Tenant Public API
Get-WAPToken -URL https://sts.bgelens.nl -ADFS -Credential administrator@gelens.int
Connect-WAPAPI -Url https://api.bgelens.nl -Port 443
Get-WAPSubscription -Name Test | Select-WAPSubscription
$GI = Get-WAPGalleryVMRole -Name DSCPullServerClient
$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
$NW = Get-WAPVMNetwork -Name internal
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Medium -VMNetwork $NW
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'
New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -CloudServiceName MyCloudService

#example deployment 2 via Tenant Public API
Get-WAPToken -Credential ben@bgelens.nl -URL https://wapauth.bgelens.nl -Port 443
Connect-WAPAPI -Url https://api.bgelens.nl -Port 443
Get-WAPSubscription -Name Test | Select-WAPSubscription
$GI = Get-WAPGalleryVMRole -Name DSCPullServerClient
$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
$NW = Get-WAPVMNetwork -Name internal
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'
$CS = New-WAPCloudService -Name MyCloudService
$CS | New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps

#example connect with Tenant API (non Public)
Get-WAPToken -URL https://sts.bgelens.nl -ADFS -Credential administrator@gelens.int
Connect-WAPAPI -URL https://wap.gelens.int -Port 30005 -Verbose -IgnoreSSL
Get-WAPSubscription -Name Test | Select-WAPSubscription

#example check and work with cloudservices
Get-WAPCloudService
$CS = New-WAPCloudService -Name test
$CS | Get-WAPCloudService
$CS | New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -Verbose

#remove cloudservice including VM Role
$CS = Get-WAPCloudService -Name Test
$CS | Remove-WAPCloudService

#remove all cloudservices 
Get-WAPCloudService | Remove-WAPCloudService -Force

#remove specified cloudservice
Get-WAPCloudService -Name Test | Remove-WAPCloudService -Force

#get more details about deployed all deployed VM roles
Get-WAPCloudService | Get-WAPVMRole | select *

#get more details about specific deployed VM Role
Get-WAPCloudService -Name test | Get-WAPVMRole | select *

#list VM instances deployed as part of the VM Role
C:\>Get-WAPCloudService -Name DCs | Get-WAPVMRoleVM

#get additional information for VM Role deployed VM instance
Get-WAPCloudService -Name DCs | Get-WAPVMroleVM -VMMEnhanced

#connect to VM Role VM instances over RDP
C:\>Get-WAPCloudService -Name DCs | Get-WAPVMRoleVM | Connect-WAPVMRDP

#connect to specific VM Role VM instance over RDP
C:\>Get-WAPCloudService -Name DCs | Get-WAPVMRoleVM -Name SRV001 | Connect-WAPVMRDP

#Disk Functions
#Get-WAPVMRoleVMDisk
Fetches all Disks currently attached to a WAPVMRoleVM. Returns WAP.DISK objects
#Expand-WAPVMRoleVMDisk
Takes a WAP.DISK Object a size in GB, expands the disk to the requested size.
#Invoke-WAPVMRoleVMDiskExpansion
Takes a WAP.DISK Object a size in GB. This stops the VM, Invokes the epansion command and then restarts the VM.

#Get-WAPVMRoleDisk
Fetches all Disks in the subscription. Returns WAP.DISKIMAGE Objects
#New-WAPVMRoleVMDisk 
Takes a WAP.DISKIMAGE object and a Cloud Service Name, then mounts attaches the Disk to the VM.
```
