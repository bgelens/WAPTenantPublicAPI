Get-WAPToken -URL https://sts.bgelens.nl -ADFS -Credential administrator@gelens.int
Connect-WAPAPI -Url https://api.bgelens.nl -Port 443
Get-WAPSubscription -Name Test | Select-WAPSubscription
$GI = Get-WAPGalleryVMRole -Name DSCPullServerClient #-Version 2.0.0.0
$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
$NW = Get-WAPVMNetwork -Name internal
$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Medium -VMNetwork $NW
$VMProps.VMRoleAdminCredential = 'Administrator:Welkom01'
$VMProps.DSCPullServerClientCredential = 'Domain\Certreq:password'
$VMProps.DSCPullServerClientConfigurationId = '7844f909-1f2e-4770-9c97-7a2e2e5677ae'
New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -CloudServiceName MyCloudService

#example deployment 2
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