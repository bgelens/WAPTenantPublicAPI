function IgnoreSSL {
	$Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
	$Compiler= $Provider.CreateCompiler()
	$Params = New-Object System.CodeDom.Compiler.CompilerParameters
	$Params.GenerateExecutable = $False
	$Params.GenerateInMemory = $True
	$Params.IncludeDebugInformation = $False
	$Params.ReferencedAssemblies.Add('System.DLL') > $null
	$TASource=@'
		namespace Local.ToolkitExtensions.Net.CertificatePolicy
		{
			public class TrustAll : System.Net.ICertificatePolicy
			{
				public TrustAll() {}
				public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
				{
					return true;
				}
			}
		}
'@ 
	$TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
	$TAAssembly=$TAResults.CompiledAssembly
        ## We create an instance of TrustAll and attach it to the ServicePointManager
	$TrustAll = $TAAssembly.CreateInstance('Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll')
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}

function Get-WAPAdfsToken {
    [cmdletbinding(DefaultParameterSetName='Tenant')]
    param (
        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [Parameter(Mandatory)]
        [String] $URL,

        [Int] $Port = 443,

        [Parameter(ParameterSetName='Tenant')]
        [Switch] $Tenant,

        [Parameter(ParameterSetName='Admin')]
        [Switch] $Admin
    )

    if ($PSCmdlet.ParameterSetName -eq 'Tenant') {
        $applyTo = 'http://azureservices/TenantSite'
    }
    else {
        $applyTo = 'http://azureservices/AdminSite'
    }
    #http://virtualstation.azurewebsites.net/?p=4331
    $sendTo = '{0}:{1}/adfs/services/trust/13/usernamemixed' -f $URL,$Port
    $tokenType = 'urn:ietf:params:oauth:token-type:jwt'

    $xml = @"
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                xmlns:a="http://www.w3.org/2005/08/addressing"
                xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <s:Header>
        <a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>
        <a:To s:mustUnderstand="1">$sendTo</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
          <o:UsernameToken u:Id=" uuid-00000000-0000-0000-0000-000000000000-0">
            <o:Username>$($Credential.UserName)</o:Username>
            <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$($Credential.GetNetworkCredential().Password)</o:Password>
          </o:UsernameToken>
        </o:Security>
      </s:Header>
      <s:Body>
        <trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
          <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <a:EndpointReference>
              <a:Address>$applyTo</a:Address>
            </a:EndpointReference>
          </wsp:AppliesTo>
          <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>
          <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
          <trust:TokenType>$tokenType</trust:TokenType>
        </trust:RequestSecurityToken>
      </s:Body>
    </s:Envelope>
"@

    $tokenresponse = [xml] ($xml | Invoke-WebRequest -uri $sendto -Method Post -ContentType 'application/soap+xml' -TimeoutSec 30 -UseBasicParsing)

    $tokenString = $tokenresponse.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.InnerText
    $token = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenString))
    Write-Output -InputObject $token
}

function Get-WAPASPNetToken {
    # PowerShell script to get security token from membership STS
    # Copyright (c) Microsoft Corporation. All rights reserved.
    # Function taken from WAP Examples 'C:\Program Files\Management Service\MgmtSvc-PowerShellAPI\Samples\Authentication\Get-TokenMembership.ps1'
    # Modified by Ben Gelens, Inovativ
    # Adjustments:
    # Changed username password parameters to credential
    # Remove mandatory clientrealm and added default value
    [CmdletBinding()]
    Param(
        #[Parameter(Mandatory=$true)][string]$username,
        #[Parameter(Mandatory=$true)][string]$password,
        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [ValidateSet('http://azureservices/TenantSite','http://azureservices/AdminSite')]
        [string] $clientRealm = 'http://azureservices/TenantSite',

        [switch] $allowSelfSignCertificates,

        [Parameter(Mandatory)]
        [string] $URL,

        [Int] $Port
    )

    if ($Port -eq $null -and $clientRealm -eq 'http://azureservices/TenantSite') {
        $Port = 30071
    }
    if ($Port -eq $null -and $clientRealm -eq 'http://azureservices/AdminSite') {
        $Port = 30072
    }

    try {
        Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    }
    catch {
        throw $_
    }

    try {
        $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ($URL + ":$Port" + '/wstrust/issue/usernamemixed')

        $identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::TransportWithMessageCredential)
        $identityProviderBinding.Security.Message.EstablishSecurityContext = $false
        $identityProviderBinding.Security.Message.ClientCredentialType = 'UserName'
        $identityProviderBinding.Security.Transport.ClientCredentialType = 'None'

        $trustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $identityProviderBinding, $identityProviderEndpoint
        $trustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13

        if ($allowSelfSignCertificates) {
            $certificateAuthentication = New-Object -TypeName System.ServiceModel.Security.X509ServiceCertificateAuthentication
            $certificateAuthentication.CertificateValidationMode = 'None'
            $trustChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = $certificateAuthentication
        }

        $trustChannelFactory.Credentials.SupportInteractive = $false
        $trustChannelFactory.Credentials.UserName.UserName = $Credential.UserName
        $trustChannelFactory.Credentials.UserName.Password = $Credential.GetNetworkCredential().Password

        $channel = $trustChannelFactory.CreateChannel()
        $rst = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityToken -ArgumentList ([System.IdentityModel.Protocols.WSTrust.RequestTypes]::Issue)
        $rst.AppliesTo = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.EndpointReference -ArgumentList $clientRealm
        $rst.TokenType = 'urn:ietf:params:oauth:token-type:jwt'
        $rst.KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer

        $rstr = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse

        $token = $channel.Issue($rst, [ref] $rstr);

        $tokenString = ([System.IdentityModel.Tokens.GenericXmlSecurityToken]$token).TokenXml.InnerText;
        $result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenString));
        return $result
    }
    catch {
        throw $_
    }
}

function Get-WAPSubscription {
    <#
    .SYNOPSIS
    Retrieves Tenant User Subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Tenant User Subscription from Azure Pack TenantPublic or Tenant API

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    Retrieve Tenant User Subscription from Azure Pack
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory)]
        [String] $Token,

        [Parameter(Mandatory)]
        [String] $UserId,

        [Parameter(Mandatory)]
        [String] $PublicTenantAPIUrl,

        [Int] $Port = 30006,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name,

        [Parameter(Mandatory,
                   ParameterSetName='Id')]
        [String] $Id,

        [Parameter(ParameterSetName='List')]
        [Switch] $List,

        [Switch] $IgnoreSSL
    )
    
    try {
        if ($IgnoreSSL) {
            Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
            #Change Certificate Policy to ignore
            $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
            IgnoreSSL
        }
        Write-Verbose 'Constructing Header'
        $Headers = @{
                Authorization = "Bearer $Token"
                'x-ms-principal-id' = $UserId
                Accept = 'application/json'
        }
        $Headers | Out-String | Write-Debug
        
        $URL = '{0}:{1}/subscriptions/' -f $PublicTenantAPIUrl,$Port        
        Write-Verbose "Constructed Subscription URI: $URI"

        $Subscriptions = Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get
        [void] $PSBoundParameters.Remove('Name')
        [void] $PSBoundParameters.Remove('Id')
        [void] $PSBoundParameters.Remove('Verbose')
        [void] $PSBoundParameters.Remove('Debug')
        [void] $PSBoundParameters.Remove('List')
        [void] $PSBoundParameters.Remove('IgnoreSSL')

        foreach ($S in $Subscriptions) {
            if ($PSCmdlet.ParameterSetName -eq 'Name' -and $S.SubscriptionName -ne $Name) {
                continue
            }
            if ($PSCmdlet.ParameterSetName -eq 'Id' -and $S.SubscriptionId -ne $Id) {
                continue
            }
            $PSBoundParameters.GetEnumerator() | %{
                Add-Member -InputObject $S -MemberType NoteProperty -Name $_.Key -Value $_.Value
            }
            $S.Created = [datetime]$S.Created
            Add-Member -InputObject $S -MemberType AliasProperty -Name 'Subscription' -Value SubscriptionId
            $S.PSObject.TypeNames.Insert(0,'WAP.Subscription')
            Write-Output -InputObject $S
        }
    } 
    catch {
        $_
    }
    finally {
        #Change Certificate Policy to the original
        if ($IgnoreSSL) {
            [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
        }
    }
}

function Get-WAPGalleryVMRole {
    <#
    .SYNOPSIS
    Retrieves VM Role Gallery Items asigned to Tenant user Subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves VM Role Gallery Items asigned to Tenant user Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    Retrieve Tenant User Subscription from Azure Pack
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Get-WAPGalleryVMRole
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionID')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Parameter(ParameterSetName='List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/Gallery/GalleryItems/$/MicrosoftCompute.VMRoleGalleryItem?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed Gallery Item URI: $URI"

            $GalleryItems = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            [void] $PSBoundParameters.Remove('Name')
            [void] $PSBoundParameters.Remove('Verbose')
            [void] $PSBoundParameters.Remove('Debug')
            [void] $PSBoundParameters.Remove('List')
            [void] $PSBoundParameters.Remove('IgnoreSSL')

            foreach ($G in $GalleryItems.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $G.Name -ne $Name) {
                    continue
                }
                $PSBoundParameters.GetEnumerator() | %{
                    Add-Member -InputObject $G -MemberType NoteProperty -Name $_.Key -Value $_.Value
                }
                $GIResDEFUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$G.ResourceDefinitionUrl
                Write-Verbose -Message "Acquiring ResDef from URI: $GIResDEFUri"
                $ResDef = Invoke-RestMethod -Uri $GIResDEFUri -Headers $Headers -Method Get

                $GIViewDefUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$G.ViewDefinitionUrl
                Write-Verbose -Message "Acquiring ViewDef from URI: $GIResDEFUri"
                $ViewDef = Invoke-RestMethod -Uri $GIViewDefUri -Headers $Headers -Method Get

                Add-Member -InputObject $G -MemberType NoteProperty -Name ResDef -Value $ResDef
                Add-Member -InputObject $G -MemberType NoteProperty -Name ViewDef -Value $ViewDef

                $G.PublishDate = [datetime]$G.PublishDate
                $G.PSObject.TypeNames.Insert(0,$G.'odata.type')
                Write-Output -InputObject $G 
            }
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }

}

function Get-WAPVMRoleOSDisk {
    <#
    .SYNOPSIS
    Retrieves Available VMRole OS Disks based on Gallery Item from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Available VMRole OS Disks based on Gallery Item from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    $GI | Get-WAPVMRoleOSDisk -Verbose
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [PSCustomObject] $ViewDef,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionID')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualHardDisks' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed VHD URI: $URI"

            $Sections = $ViewDef.ViewDefinition.Sections
            $Categories = $Sections | %{$_.Categories}
            $OSDiskParam = $Categories | %{$_.Parameters} | Where-Object{$_.Type -eq 'OSVirtualHardDisk'}

            $Images = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($I in $Images.value) {
                $Tags = $I.tag
                if ((Compare-Object -ReferenceObject $Tags -DifferenceObject $OSDiskParam.ImageTags).SideIndicator -eq $null) {
                    if ($I.enabled -eq $false) {
                        continue
                    }
                    $I.AddedTime = [datetime] $I.AddedTime
                    $I.ModifiedTime = [datetime] $I.ModifiedTime
                    $I.ReleaseTime = [datetime] $I.ReleaseTime
                    $I.PSObject.TypeNames.Insert(0,'WAP.GI.OSDisk')
                    Write-Output -InputObject $I
                }
            }                
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPVMNetwork {
    <#
    .SYNOPSIS
    Retrieves subscription available VM Networks from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves subscription available VM Networks from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Get-WAPVMNetwork
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionId')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Parameter(ParameterSetName='List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ParameterSetName='Name')]
        [String] $Name,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMNetworks' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed VM Networks URI: $URI"
            
            $VMNets = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
    
            foreach ($N in $VMNets.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $N.Name -ne $Name) {
                    continue
                }
                $N.PSObject.TypeNames.Insert(0,'WAP.VMNetwork')
                Write-Output -InputObject $N
            }
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPVMRoleParameterObject {
    <#
    .SYNOPSIS
    Generates VM Role Parameter Object.

    .DESCRIPTION
    Generates VM Role Parameter Object.

    .PARAMETER VMRole
    VM Role gallery item object acquired via Get-WAPGalleryVMRole

    .PARAMETER OSDisk
    OS Disk object acquired via Get-WAPVMRoleOSDisk

    .PARAMETER VMRoleVMSize
    Select one of the default VMRole sizing profiles ('Small','A7','ExtraSmall','Large','A6','Medium','ExtraLarge')

    .PARAMETER VMNetwork
    VM Network object acquired via Get-WAPVMNetwork

    .PARAMETER Interactive
    Run in interactive mode where you get prompted to provide values with parameters. 
    In non-interactive mode this functions uses the defaults where provided and uses NULL for everything unknown.

    .EXAMPLE
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.domain.tld'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.domain.tld -Port 443 -Name 'MySub'
    $GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    $OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
    $NW = $Subscription | Get-WAPVMNetwork -Name MyNetwork
    $VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW -Interactive

    .EXAMPLE
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.domain.tld'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.domain.tld -Port 443 -Name 'MySub'
    $GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    $OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
    $NW = $Subscription | Get-WAPVMNetwork -Name MyNetwork
    $VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Object] $VMRole,

        [Parameter(Mandatory)]
        [Object] $OSDisk,

        [Parameter(Mandatory)]
        [ValidateSet('Small','A7','ExtraSmall','Large','A6','Medium','ExtraLarge')]
        [String] $VMRoleVMSize,

        [Parameter(Mandatory)]
        [Object] $VMNetwork,

        [Switch] $Interactive
    )
    if (!($VMRole.pstypenames.Contains('MicrosoftCompute.VMRoleGalleryItem'))) {
        throw 'Object bound to VMRole parameter is of the wrong type'
    }
    if (!($OSDisk.pstypenames.Contains('WAP.GI.OSDisk'))) {
        throw 'Object bound to OSDisk parameter is of the wrong type'
    }
    if (!($VMNetwork.pstypenames.Contains('WAP.VMNetwork'))) {
        throw 'Object bound to VMNetwork parameter is of the wrong type'
    }
    $Sections = $VMRole.ViewDef.ViewDefinition.Sections
    $Categories = $Sections | %{$_.Categories}
    $ViewDefParams = $Categories | %{$_.Parameters}
    $Output = [pscustomobject]@{}
    foreach ($P in $ViewDefParams) {
        $p | Out-String | Write-Verbose
        if ($Interactive -and $P.type -eq 'option') {
            $values = ''
            foreach ($v in $P.OptionValues) {
                $Def = ($v | Get-Member -MemberType NoteProperty).Definition.Split(' ')[1].Split('=')
                $Friendly = $Def[1]
                $Value = $Def[0] 
                $values += $value + ','
            }
            $values = $values.TrimEnd(',')
            if ($P.DefaultValue) {
                if(($result = Read-Host "Press enter to accept default value $($P.DefaultValue) for $($P.Name). Valid entries: $values") -eq ''){
                    Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $P.DefaultValue -Force
                }
                else {
                    do {
                        $result = Read-Host "Enter one of the following entries: $values"
                    }
                    while (@($values.Split(',')) -notcontains $result)
                    Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
                }
            }
            else {
                do {
                    $result = Read-Host "Enter one of the following entries: $values"
                }
                while (@($values.Split(',')) -notcontains $result)
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
            }
        }
        elseif ($Interactive -and $P.type -eq 'Credential') {
            do {
                $result = Read-Host "Enter a credential for $($P.Name) in the format domain\username:password or username:password"
            }
            while ($result -notmatch '\w+\\+\w+:+\w+' -and $result -notmatch '\w+:+\w+')
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
        }
        elseif ($P.DefaultValue) {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $P.DefaultValue -Force
        }
        elseif ($P.Type -eq 'OSVirtualHardDisk') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value "$($OSDisk.FamilyName):$($OSDisk.Release)" -Force
        }
        elseif ($P.Type -eq 'VMSize') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $VMRoleVMSize -Force
        }
        elseif ($P.Type -eq 'Credential') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value 'domain\username:password' -Force
        }
        elseif ($P.Type -eq 'Network') {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $($VMNetwork.Name) -Force
        }
        elseif ($Interactive) {
            $result = Read-Host "Enter a value for $($P.Name) of type $($P.Type)"
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
        }
        else {
            Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $null -Force
        }
        
    }
    Write-Output -InputObject $Output
}

function Get-WAPCloudService {
    <#
    .SYNOPSIS
    Retrieves Cloudservice deployed to subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Cloudservice deployed to subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Get-WAPCloudService
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(ParameterSetName = 'List')]
        [Switch] $List,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName,
                   ParameterSetName = 'Name')]
        [Alias('CloudServiceName')]
        [String] $Name,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionId')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed CloudService URI: $URI"

            $CloudServices = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

            [void] $PSBoundParameters.Remove('Name')
            [void] $PSBoundParameters.Remove('List')
            [void] $PSBoundParameters.Remove('Verbose')
            [void] $PSBoundParameters.Remove('Debug')
            [void] $PSBoundParameters.Remove('IgnoreSSL')

            foreach ($C in $CloudServices.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $C.Name -ne $Name) {
                    continue
                }
                $PSBoundParameters.GetEnumerator() | %{
                    Add-Member -InputObject $C -MemberType NoteProperty -Name $_.Key -Value $_.Value
                }
                Add-Member -InputObject $C -MemberType AliasProperty -Name CloudServiceName -Value Name
                $C.PSObject.TypeNames.Insert(0,'WAP.CloudService')
                Write-Output -InputObject $C
            }
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPCloudService {
    <#
    .SYNOPSIS
    Creates Cloudservice for subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Creates Cloudservice for subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | New-WAPCloudService -Name test
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionId')]
        [String] $Subscription,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('CloudServiceName')]
        [String] $Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed CloudService URI: $URI"

            $CloudServiceConfig = @{
                Name = $Name
                Label = $Name
            } | ConvertTo-Json -Compress

            $CloudService = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $CloudServiceConfig -ContentType 'application/json'
            $CloudService.PSObject.Properties.Remove('odata.metadata')
            $CloudService.PSObject.TypeNames.Insert(0,'WAP.CloudService')
            Write-Output -InputObject $CloudService
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPCloudService {
    <#
    .SYNOPSIS
    Deletes Cloudservice from subscription from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Deletes Cloudservice from subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Remove-WAPCloudService -Name test

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Get-WAPCloudService -Name Test | Remove-WAPCloudService -Force
    #>
    [CmdletBinding(SupportsShouldProcess,
                   ConfirmImpact='High')]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Name,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionId')]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $Force,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription
            Write-Verbose "Constructed CloudService URI: $URI"

            $CloudServices = Invoke-RestMethod -Uri $URI -Method Get -Headers $Headers
            foreach ($C in $CloudServices.value) {
                if ($C.Name -ne $Name) {
                    continue
                }
                $RemURI = '{0}:{1}/{2}/CloudServices/{3}?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$Name
                Write-Verbose "Constructed Named CloudService URI: $RemURI"
                if ($Force -or $PSCmdlet.ShouldProcess($Name)) {
                    Invoke-RestMethod -Uri $RemURI -Method Delete -Headers $Headers | Out-Null
                }
            }
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPVMRoleDeployment {
    <#
    .SYNOPSIS
    Deploys VM Role to a Cloudservice using Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Deploys VM Role to a Cloudservice using Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    $Subscription | Remove-WAPCloudService -Name test
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Object] $VMRole,

        [Parameter(Mandatory)]
        [Object] $ParameterObject,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('SubscriptionId')]
        [String] $Subscription,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('Name','VMRoleName')]
        [String] $CloudServiceName
    )
    process {
        if (!($VMRole.pstypenames.Contains('MicrosoftCompute.VMRoleGalleryItem'))) {
            throw 'Object bound to VMRole parameter is of the wrong type'
        }

        $ErrorActionPreference = 'Stop'
        $SUB = New-Object -TypeName psobject -Property $PSBoundParameters
        $SUB.PSObject.TypeNames.Insert(0,'WAP.Subscription')

        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
                        
            Write-Verbose -Message "Testing if Cloudservice $CloudServiceName exists"
            if (!($SUB | Get-WAPCloudService)) {
                Write-Verbose -Message "Creating Cloudservice $CloudServiceName as it does not yet exist"
                $SUB | New-WAPCloudService | Out-Null
                $New = $true
            }
            else {
                $New = $false
            }
            
            if (!$New) {
                Write-Verbose -Message "Testing if VMRole with name $VMRoleName does not already exist"
                if ($SUB | Get-WAPCloudService | Get-WAPVMRole) {
                    throw "There is already a VMRole deployed to the CloudService $CloudServiceName. Because this function mimics portal experience, only one VM Role is allowed to exist per CloudService"
                }  
            } 
            
            #Add ResDefConfig JSON to Dictionary
            $ResDefConfig = New-Object 'System.Collections.Generic.Dictionary[String,Object]'
            $ResDefConfig.Add('Version',$VMRole.version)
            $ResDefConfig.Add('ParameterValues',($ParameterObject | ConvertTo-Json))

            # Set Gallery Item Payload Info
            $GIPayload = @{
                InstanceView = $null
                Substate = $null
                Name = $CloudServiceName
                Label = $CloudServiceName
                ProvisioningState = $null
                ResourceConfiguration = $ResDefConfig
                ResourceDefinition = $VMRole.ResDef
            }

            # Convert Gallery Item Payload Info To JSON
            $GIPayloadJSON = ConvertTo-Json $GIPayload -Depth 10

            # Deploy VM Role to cloudservice
            Write-Verbose 'Constructing Header'
            $Headers = @{
                Authorization = "Bearer $Token"
                'x-ms-principal-id' = $UserId
                Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$CloudServiceName
            Write-Verbose "Constructed VMRole Deploy URI: $URI"

            Write-Verbose "Starting deployment of VMRole $VMRoleName to CloudService $CloudServiceName"
            $Deploy = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $GIPayloadJSON -ContentType 'application/json'
            $Deploy.PSObject.TypeNames.Insert(0,'WAP.VMRole')
            Write-Output $Deploy
        }
        catch {
            if ($New) {
                $SUB | Remove-WAPCloudService -Force
            }
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPVMRole {
    <#
    .SYNOPSIS
    Retrieves Deployed VM Role information from Azure Pack TenantPublic or Tenant API.

    .DESCRIPTION
    Retrieves Deployed VM Role information from Azure Pack TenantPublic or Tenant API.

    .PARAMETER CloudServiceName 
    The name of the cloud service where the VM Role is deployed to.

    .PARAMETER Token
    Bearer token acquired via Get-WAPADFSToken or Get-WAPASPNetToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .EXAMPLE
    Retrieve VM Role information from cloudservice 'Test' using custom api port 443
    $URL = 'https://publictenantapi.mydomain.com'
    $creds = Get-Credential
    $token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    $Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    Get-WAPVMRole -Token $token -UserId $creds.UserName -CloudServiceName 'Test' -PublicTenantAPIUrl $URL -Subscription $Subscription.SubscriptionID -Port 443
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [Alias('Name','VMRoleName')]
        [String] $CloudServiceName,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Token,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $UserId,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $PublicTenantAPIUrl,

        [Parameter(Mandatory,
                   ValueFromPipelineByPropertyName)]
        [String] $Subscription,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                IgnoreSSL
            }
            Write-Verbose 'Constructing Header'
            $Headers = @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $UserId
                    Accept = 'application/json'
            }
            $Headers | Out-String | Write-Debug
            $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription,$CloudServiceName
            Write-Verbose "Constructed VMRole URI: $URI"

            $Roles = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($R in $Roles.value) {
                $R.PSObject.TypeNames.Insert(0,'WAP.VMRole')
                Write-Output -InputObject $R
            }
        }
        catch {
            $_
        }
        finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

Export-ModuleMember *-WAP*