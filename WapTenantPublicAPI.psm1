try {
    Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
}
catch {
    throw $_
}

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

function TestJWTClaimNotExpired {
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [ValidateScript({if ($_.split('.').count -eq 3) {$true}})]
        [String] $Token
    )
    #based on functions by Shriram MSFT found on technet: https://gallery.technet.microsoft.com/JWT-Token-Decode-637cf001
    process {
        try {
            $TokenData = $token.Split('.')[1] |%{
                $data = $_ -as [String]
                $data = $data.Replace('-', '+').Replace('_', '/')
                switch ($data.Length % 4) {
                    0 { break }
                    2 { $data += '==' }
                    3 { $data += '=' }
                    default { throw New-Object ArgumentException('data') }
                }
                [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json
            }
            #JWT Reference Time
            $Ref = [datetime]::SpecifyKind((New-Object -TypeName datetime ('1970',1,1,0,0,0)),'UTC')
            #UTC time right now - Reference time gives amount of seconds to check against
            $CheckSeconds = [System.Math]::Round(([datetime]::UtcNow - $Ref).totalseconds)
            if ($TokenData.exp -gt $CheckSeconds) {
                Write-Output -InputObject $true
            }
            else {
                Write-Output -InputObject $false
            }
        }
        catch {
            throw $_
        }
    }
}

function Get-WAPToken {
    <#
    .SYNOPSIS
    Retrieves a Bearer token from either ADFS or the WAP ASP.Net STS.

    .PARAMETER Url
    The URL of either the ADFS or WAP STS.

    .PARAMETER Port
    The Port on which ADFS or WAP STS is listening. Default for ADFS is 443, for WAP STS 30071.

    .PARAMETER ClientRealm
    The realm name of either the TenantSite (default) or AdminSite.

    .PARAMETER Credential
    Credentials to acquire the bearer token.

    .PARAMETER ADFS
    When enabled the token will be requested from an ADFS STS. When disabled the WAP STS is assumed.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS

    This will return a bearer token from ADFS STS.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.wap.com' -Port 443

    This will return a bearer token from WAP STS using the non default port 443.
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$URL, 

        [int] $Port,

        [ValidateSet('http://azureservices/AdminSite','http://azureservices/TenantSite')]
        [String] $ClientRealm = 'http://azureservices/TenantSite',

        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [Switch] $ADFS,

        [Switch] $IgnoreSSL
    )
    try {
    if ($ADFS -and $Port -eq 0) {
        $Port = 443
    }
    elseif ($Port -eq 0 -and $clientRealm -eq 'http://azureservices/TenantSite') {
        $Port = 30071
    }
    elseif ($Port -eq 0 -and $clientRealm -eq 'http://azureservices/AdminSite') {
        $Port = 30072
    }

    if ($ADFS) {
        Write-Verbose -Message 'Constructing ADFS URL'
        $ConstructedURL = $URL + ":$Port" + '/adfs/services/trust/13/usernamemixed'
    }
    else {
        Write-Verbose -Message 'Constructing ASPNet URL'
        $ConstructedURL = $URL + ":$Port" + '/wstrust/issue/usernamemixed'
    }
    Write-Verbose -Message $ConstructedURL
    $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList $ConstructedURL
    $identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::TransportWithMessageCredential)
    $identityProviderBinding.Security.Message.EstablishSecurityContext = $false
    $identityProviderBinding.Security.Message.ClientCredentialType = 'UserName'
    $identityProviderBinding.Security.Transport.ClientCredentialType = 'None'
 
    $trustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $identityProviderBinding, $identityProviderEndpoint
    $trustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13
 
    if ($IgnoreSSL) {
        Write-Warning -Message 'IgnoreSSL switch defined. Certificate errors will be ignored!'
        $certificateAuthentication = New-Object -TypeName System.ServiceModel.Security.X509ServiceCertificateAuthentication
        $certificateAuthentication.CertificateValidationMode = 'None'
        $trustChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = $certificateAuthentication
    }
    if ($ADFS) {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($credential.Password)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($ptr)
    }
    $trustChannelFactory.Credentials.SupportInteractive = $false
    $trustChannelFactory.Credentials.UserName.UserName = $credential.UserName
    $trustChannelFactory.Credentials.UserName.Password = $credential.GetNetworkCredential().Password
    
    $rst = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityToken -ArgumentList ([System.IdentityModel.Protocols.WSTrust.RequestTypes]::Issue)
    $rst.AppliesTo = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.EndpointReference -ArgumentList $clientRealm
    $rst.TokenType = 'urn:ietf:params:oauth:token-type:jwt'
    $rst.KeyType = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer

    $rstr = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse
 
    $channel = $trustChannelFactory.CreateChannel()
    $token = $channel.Issue($rst, [ref] $rstr)
 
    $tokenString = ([System.IdentityModel.Tokens.GenericXmlSecurityToken]$token).TokenXml.InnerText;
    $token = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenString))
    Write-Output -InputObject $token
    }
    catch {
        throw $_
    }
}

function Get-WAPSubscription {
    <#
    .SYNOPSIS
    Retrieves Tenant User Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Name
    The Name of the subscription to be acquired.

    .PARAMETER Id
    The Id of the subscription to be acquired.

    .PARAMETER List
    A list of all subscriptions the user has access to.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'

    This will return the subscription with name 'MySubscription' if it exists.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.wap.com'
    PS C:\>Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL

    This will return a list of the users subscriptions using the default public tenant api port 30006.
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

        Write-Verbose 'Validating Token not expired'
        if (!(TestJWTClaimNotExpired -Token $Token)) {
            throw 'Token has expired, fetch a new one!'
        }

        Write-Verbose 'Constructing Header'
        $Headers = @{
                Authorization = "Bearer $Token"
                'x-ms-principal-id' = $UserId
                Accept = 'application/json'
        }
        $Headers | Out-String | Write-Debug
        
        $URL = '{0}:{1}/subscriptions/' -f $PublicTenantAPIUrl,$Port        
        Write-Verbose "Constructed Subscription URL: $URL"

        $Subscriptions = Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get
        [void] $PSBoundParameters.Remove('Name')
        [void] $PSBoundParameters.Remove('Id')
        [void] $PSBoundParameters.Remove('List')

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
        throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get the VM Role Gallery Item from.

    .PARAMETER List
    Defaults to list mode. Shows all VM Role Gallery Items.

    .PARAMETER Name
    When Name is specified, only the VM Role Gallery Item with the specified name is returned.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Get-WAPGalleryVMRole

    This will retrieve all VM Role Gallery Items tight to the subscription.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Get-WAPGalleryVMRole -Name 'MyAwesomeVMRole'

    This will retreive only the VM Role Gallery Item with the same name as specified.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>Get-WAPGalleryVMRole -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -SubscriptionId 'b5a9b263-066b-4a8f-87b4-1b7c90a5bcad'

    This will not make use of a subscription object but is entirely specified. All VM Role Gallery Items assigned to this subscription will be returned.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get the OS Disks from.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .PARAMETER ViewDef
    The viewdef comes as a property of the VM Role gallery item.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    PS C:\>$GI | Get-WAPVMRoleOSDisk -Verbose

    This will fetch all compatible and enabled OS disks.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get the VM Networks from.

    .PARAMETER List
    Defaults to list mode. Shows all VM Networks available to the subscription.

    .PARAMETER Name
    When Name is specified, only the VM Network with the specified name is returned.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Get-WAPVMNetwork

    This will fetch all VM Networks available to the subscription.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            throw $_
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
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.domain.tld' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.domain.tld -Port 443 -Name 'MySub'
    PS C:\>$GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    PS C:\>$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
    PS C:\>$NW = $Subscription | Get-WAPVMNetwork -Name MyNetwork
    PS C:\>$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW -Interactive

    This will run in interactive mode. It will prompt to fill in the blanks and accept defaults or provide own values.

    .EXAMPLE
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.domain.tld' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl https://api.domain.tld -Port 443 -Name 'MySub'
    PS C:\>$GI = $Subscription | Get-WAPGalleryVMRole -Name MyVMRole
    PS C:\>$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
    PS C:\>$NW = $Subscription | Get-WAPVMNetwork -Name MyNetwork
    PS C:\>$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
    PS C:\>$VMProps.MissingValue = 'MyValue'

    This will run in non-interactive mode. It will use defaults and assigns NULL if no default is available. Values can be assigned / overwritten.
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
    $Output.PSObject.TypeNames.Insert(0,'WAP.ParameterObject')
    Write-Output -InputObject $Output
}

function Get-WAPCloudService {
    <#
    .SYNOPSIS
    Retrieves Cloudservice deployed to subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get the cloud service from.

    .PARAMETER List
    Defaults to list mode. Shows all cloud services provisioned for the subscription.

    .PARAMETER Name
    When Name is specified, only the cloud service with the specified name is returned.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPAdfsToken -Credential $creds -URL 'https://sts.adfs.com'
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Get-WAPCloudService

    This will retreive all provisioned cloud services for the specified subscription.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to provision the cloud service to.

    .PARAMETER Name
    The name of the cloud service to be provisioned. The name must be unique within the subscription.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | New-WAPCloudService -Name test

    This will provision a cloud service named test.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            [void] $PSBoundParameters.Remove('Name')
            $PSBoundParameters.GetEnumerator() | %{
                    Add-Member -InputObject $CloudService -MemberType NoteProperty -Name $_.Key -Value $_.Value
            }
            $CloudService.PSObject.Properties.Remove('odata.metadata')
            $CloudService.PSObject.TypeNames.Insert(0,'WAP.CloudService')
            Write-Output -InputObject $CloudService
        }
        catch {
            throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get remove the cloud service from.

    .PARAMETER Name
    The name of the cloud service to be removed.

    .PARAMETER Force
    If Force is not specified, removal is treated with confirm impact high.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Remove-WAPCloudService -Name test

    This will remove the cloudservice named test from the subscription. If a VM Role has been deployed to this cloud service, it will be removed as well.
    In this case, the user will be prompted to confirm the remove action as -Force or -Confirm:$false is not specified.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Get-WAPCloudService -Name Test | Remove-WAPCloudService -Force

    This will remove the cloudservice named test from the subscription. If a VM Role has been deployed to this cloud service, it will be removed as well.
    In this case, the user is not prompted to confirm as -Force is specified.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get the VM Role Gallery Item from.

    .PARAMETER CloudServiceName
    The name of the cloud service to provision to. If it does not exist, it will be created.

    .PARAMETER VMRole
    Object acquired with Get-WAPGalleryVMRole.

    .PARAMETER ParameterObject
    Object acquired with New-WAPVMRoleParameterObject.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$GI = $Subscription | Get-WAPGalleryVMRole -Name DomainController
    PS C:\>$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
    PS C:\>$NW = $Subscription | Get-WAPVMNetwork -Name Private
    PS C:\>$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
    PS C:\>$VMProps.DomainName = 'MyNewDomain.local'
    PS C:\>$Subscription | New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -CloudServiceName DCs -Verbose
    
    This will deploy a new VM Role based on the Gallery Item DomainController. It will link the VMs up to the Private network and uses the latest published OS Disk.
    The domain name for the VM Role will be 'MyNewDomain.local' and the VMs will be sided using the Large VM Profile.
    If the cloud service DCs does not yet exists, it will be created. If it does exist, it will be checked if it has the correct name and if no VM Roles have been deployed to it.
    This function mirrors portal functionality and therefore does not allow multiple VM Roles in one cloud service.
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

        if (!($ParameterObject.pstypenames.Contains('WAP.ParameterObject'))) {
            throw 'Object bound to ParameterObject parameter is of the wrong type'
        }

        $ParameterObject | gm -MemberType Properties | %{
            if ($ParameterObject.($_.name) -eq $null) {
                throw "ParameterObject property: $($_.name) is NULL"
            }
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
            throw $_
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

    .PARAMETER Token
    Bearer Token acquired via Get-WAPToken.

    .PARAMETER UserId
    The UserId used to get the Bearer token.

    .PARAMETER PublicTenantAPIUrl
    The URL of either the TenantPublic API or Tenant API.

    .PARAMETER Port
    The Port where the TenantPublic (30006) or Tenant API (30005) is listening on.
    Defaults to 30006.

    .PARAMETER Subscription
    The subscription id to get the VM Role information from.

    .PARAMETER CloudServiceName
    The name of the cloud service to get VM Role information from.

    .PARAMETER IgnoreSSL
    When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .EXAMPLE
    PS C:\>$URL = 'https://publictenantapi.mydomain.com'
    PS C:\>$creds = Get-Credential
    PS C:\>$token = Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
    PS C:\>$Subscription = Get-WAPSubscription -Token $token -UserId $creds.UserName -PublicTenantAPIUrl $URL -Port 443 -Name 'MySubscription'
    PS C:\>$Subscription | Get-WAPCloudService -Name DCs | Get-WAPVMRole | select *

    This will get the VM Role provisioning information for the DCs cloud service deployment.
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

            Write-Verbose 'Validating Token not expired'
            if (!(TestJWTClaimNotExpired -Token $Token)) {
                throw 'Token has expired, fetch a new one!'
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
                Add-Member -InputObject $R -MemberType NoteProperty -Name ParameterValues -Value ($R.ResourceConfiguration.ParameterValues | ConvertFrom-Json)
                Add-Member -InputObject $R -MemberType NoteProperty -Name ScaleOutSettings -Value $R.ResourceDefinition.IntrinsicSettings.ScaleOutSettings
                Add-Member -InputObject $R -MemberType NoteProperty -Name InstanceCount -Value $R.InstanceView.InstanceCount
                Add-Member -InputObject $R -MemberType NoteProperty -Name VMSize -Value $R.InstanceView.ResolvedResourceDefinition.IntrinsicSettings.HardwareProfile.VMSize
                $R.PSObject.TypeNames.Insert(0,'WAP.VMRole')
                Write-Output -InputObject $R
            }
        }
        catch {
            throw $_
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