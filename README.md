WapTenantPublicAPI
------------------

A PowerShell module which enables you to deploy VM Roles through the Windows Azure Pack Tenant API and Tenant Public API.

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

Examples
--------
```powershell
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
```