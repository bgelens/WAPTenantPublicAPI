#requires -version 4
#Set-StrictMode -Version Latest  # // TODO: Bug in Get-WAPVMRoleOSDisk
Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'

$PublicTenantAPIUrl = $null
$Port = $null
$IgnoreSSL = $false
$Token = $null
$Headers = $null
$Subscription = $null
$SQLOffer = $null
$OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
$WebSpace = $null

function IgnoreSSL {
    $Provider = New-Object -TypeName Microsoft.CSharp.CSharpCodeProvider
    $null = $Provider.CreateCompiler()
    $Params = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
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
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $Token
    )
    #based on functions by Shriram MSFT found on technet: https://gallery.technet.microsoft.com/JWT-Token-Decode-637cf001
    process {
        try {
            if ($Token.split('.').count -ne 3) {
                throw 'Invalid token passed, run Get-WAPToken to fetch a new one'
            }
            $TokenData = $token.Split('.')[1] | ForEach-Object -Process {
                $data = $_ -as [String]
                $data = $data.Replace('-', '+').Replace('_', '/')
                switch ($data.Length % 4) {
                    0 { break }
                    2 { $data += '==' }
                    3 { $data += '=' }
                    default { throw New-Object -TypeName ArgumentException -ArgumentList ('data') }
                }
                [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json
            }
            #JWT Reference Time
            $Ref = [datetime]::SpecifyKind((New-Object -TypeName datetime -ArgumentList ('1970',1,1,0,0,0)),'UTC')
            #UTC time right now - Reference time gives amount of seconds to check against
            $CheckSeconds = [System.Math]::Round(([datetime]::UtcNow - $Ref).totalseconds)
            if ($TokenData.exp -gt $CheckSeconds) {
                Write-Output -InputObject $true
            } else {
                Write-Output -InputObject $false
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function PreFlight {
    [CmdletBinding()]
    param (
        [Switch] $IncludeConnection,

        [Switch] $IncludeSubscription,

        [Switch] $IncludeSQLOffer,

        [Switch] $IncludeWebSpace
    )

    Write-Verbose -Message 'Validating Token Acquired'
    if (($null -eq $Token) -or ($null -eq $Headers)) {
        throw 'Token was not acquired, run Get-WAPToken first!'
    }

    Write-Verbose -Message 'Validating Token not expired'
    if (!(TestJWTClaimNotExpired -Token $Token)) {
        throw 'Token has expired, fetch a new one!'
    }

    if ($IncludeConnection) {
        Write-Verbose -Message 'Validating if connection is set'
        if ($null -eq $PublicTenantAPIUrl) {
            throw 'No connection has been made to API yet, run Connect-WAPAPI first!'
        }
    }

    if ($IncludeSubscription) {
        Write-Verbose -Message 'Validating if subscription is selected'
        if ($null -eq $Subscription) {
            throw 'No Subscription has been selected yet, run Select-WAPSubscription first!'
        }
    }

    if ($IncludeSQLOffer) {
        Write-Verbose -Message 'Validating if SQL Offer is selected'
        if ($null -eq $SQLOffer) {
            throw 'No SQL Offer has been selected yet, run Select-WAPSQLOffer first!'
        }
    }

    if ($IncludeWebSpace) {
        Write-Verbose -Message 'Validating if WebSpace is selected'
        if ($null -eq $script:WebSpace) {
            throw 'No WebSpace has been selected yet, run Select-WAPWebSpace first!'
        }
        if ($script:WebSpace.Subscription -ne $script:Subscription.SubscriptionId) {
            throw 'Selected WebSpace is outside of current selected Subscription scope. Either change the selected Subscription or select another WebSpace'
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

    .PARAMETER Credential
        Credentials to acquire the bearer token.

    .PARAMETER ADFS
        When enabled the token will be requested from an ADFS STS. When disabled the WAP STS is assumed.

    .PARAMETER IgnoreSSL
        When using self-signed certificates, SSL validation will be ignored when this switch is enabled.

    .PARAMETER Admin
        When specified, authentication will take place against Admin client realm instead of default Tenant clientrealm.

    .PARAMETER ForOnBehalfOfUser
        When specified, subsequent functions will invoke actions on behalf of the user.

    .PARAMETER UpdateForOnBehalfOfUserOnly
        Don't get a new token, just update the ForOnBehalfUser.

    .EXAMPLE
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS

        This will return a bearer token from ADFS STS.

    .EXAMPLE
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.wap.com' -Port 443

        This will return a bearer token from WAP STS using the non default port 443.

    .EXAMPLE
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.wap.com' -Port 443 -Admin -ForOnBehalfOfUser TenantUser@TenantDomain

        This will return a bearer token from WAP STS using the non default port 443 using the Admin Client realm and targeting TenantUser@TenantDomain

    .EXAMPLE
        PS C:\>Get-WAPToken -Admin -ForOnBehalfOfUser TenantUser@TenantDomain -UpdateForOnBehalfOfUserOnly

        This will update the Admin action targeting onbehalf of TenantUser@TenantDomain without getting a new Admin Token.
    #>
    [CmdletBinding(DefaultParameterSetName='Tenant')]
    [OutputType([void],[System.String])]
    param (
        [Parameter(Mandatory, ParameterSetName='Tenant')]
        [Parameter(Mandatory, ParameterSetName='Admin')]
        [ValidateNotNullOrEmpty()]
        [string] $Url, 

        [Parameter(ParameterSetName='Tenant')]
        [Parameter(ParameterSetName='Admin')]
        [int] $Port,

        [Parameter(Mandatory, ParameterSetName='Tenant')]
        [Parameter(Mandatory, ParameterSetName='Admin')]
        [PSCredential]
        [System.Management.Automation.Credential()] $Credential,

        [Parameter(ParameterSetName='Tenant')]
        [Parameter(ParameterSetName='Admin')]
        [Switch] $ADFS,

        [Parameter(ParameterSetName='Tenant')]
        [Parameter(ParameterSetName='Admin')]
        [Switch] $IgnoreSSL,

        [Parameter(ParameterSetName='Tenant')]
        [Parameter(ParameterSetName='Admin')]
        [Switch] $PassThru,

        [Parameter(Mandatory, ParameterSetName='Admin')]
        [Parameter(Mandatory, ParameterSetName='UpdateForOnBehalfOfUser')]
        [Switch] $Admin,

        [Parameter(ParameterSetName='Admin')]
        [Parameter(Mandatory, ParameterSetName='UpdateForOnBehalfOfUser')]
        [ValidateNotNullOrEmpty()]
        [String] $ForOnBehalfOfUser,

        [Parameter(ParameterSetName='UpdateForOnBehalfOfUser')]
        [Switch] $UpdateForOnBehalfOfUserOnly,

        [Parameter(ParameterSetName='Admin')]
        [Switch] $AdminWindowsAuth
    )

    try {
        $ErrorActionPreference = 'Stop'

        if ($Admin) {
            if ($UpdateForOnBehalfOfUserOnly -and $null -ne $Headers) {
                Set-Variable -Name Headers -Scope 1 -Value @{
                    Authorization = "Bearer $Token"
                    'x-ms-principal-id' = $ForOnBehalfOfUser
                    Accept = 'application/json'
                }
                return
            } elseif ($UpdateForOnBehalfOfUserOnly -and $null -eq $Headers) {
                throw 'Initial authentication did not occur yet. Run Get-WAPToken without UpdateForOnBehalfOfUserOnly switch first'
            }
            $ClientRealm = 'http://azureservices/AdminSite'
            if ($ForOnBehalfOfUser) {
                $MSPrincipalId = $ForOnBehalfOfUser
            } else {
                $MSPrincipalId = $Credential.UserName
            }
        } else {
            $ClientRealm = 'http://azureservices/TenantSite'
            $MSPrincipalId = $Credential.UserName
        }

        if ($ADFS -and $Port -eq 0) {
            $Port = 443
        } elseif ($Port -eq 0 -and $clientRealm -eq 'http://azureservices/TenantSite') {
            $Port = 30071
        } elseif ($Port -eq 0 -and $clientRealm -eq 'http://azureservices/AdminSite') {
            $Port = 30072
        }

        if ($ADFS) {
            Write-Verbose -Message 'Constructing ADFS URL'
            $ConstructedURL = $URL + ":$Port" + '/adfs/services/trust/13/usernamemixed'
            $MessageClientCredentialType = 'UserName'
            $TransportClientCredentialType = 'None'
            $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList $ConstructedURL
            $identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::TransportWithMessageCredential)
        } elseif ($AdminWindowsAuth) {
            $ConstructedURL = $URL + ":$Port" +  '/wstrust/issue/windowstransport'
            $MessageClientCredentialType = 'None'
            $TransportClientCredentialType = 'Windows'
            $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList $ConstructedURL
            $identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::Transport)
        } else {
            Write-Verbose -Message 'Constructing ASPNet URL'
            $ConstructedURL = $URL + ":$Port" + '/wstrust/issue/usernamemixed'
            $MessageClientCredentialType = 'UserName'
            $TransportClientCredentialType = 'None'
            $identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList $ConstructedURL
            $identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::TransportWithMessageCredential)
        }
        Write-Verbose -Message $ConstructedURL
        #$identityProviderEndpoint = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList $ConstructedURL
        #$identityProviderBinding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode]::TransportWithMessageCredential)
        $identityProviderBinding.Security.Message.EstablishSecurityContext = $false
        $identityProviderBinding.Security.Message.ClientCredentialType = $MessageClientCredentialType
        $identityProviderBinding.Security.Transport.ClientCredentialType = $TransportClientCredentialType

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
            $null = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
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

        Set-Variable -Name Headers -Scope 1 -Value @{
            Authorization = "Bearer $Token"
            'x-ms-principal-id' = $MSPrincipalId
            Accept = 'application/json'
        }
        Set-Variable -Name Token -Value $token -Scope 1
        if ($PassThru) {
            Write-Output -InputObject $token
        }
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Connect-WAPAPI {
    <#
    .SYNOPSIS
        Connects to WAPAPI.

    .PARAMETER Url
        The URL of either the WAP Public Tenant API or Tenant API.

    .PARAMETER Port
        The Port on which the API is listening (default to Public Tenant API port 30006).

    .PARAMETER IgnoreSSL
        When using self-signed certificates, SSL validation will be ignored when this switch is enabled.
        All functions relying on the connection will inherit the SSL setting.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL

        This will connect to the WAP Public Tenant API on its default port.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL -Port 443

        This will connect to the either the WAP Public Tenant API or Tenant API on a non default port 443.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Url,

        [Int] $Port = 30006,

        [Switch] $IgnoreSSL
    )
    try {
        if ($IgnoreSSL) {
            Write-Warning -Message 'IgnoreSSL switch defined. Certificate errors will be ignored!'
            #Change Certificate Policy to ignore
            IgnoreSSL
        }
        
        Set-Variable -Name IgnoreSSL -Value $IgnoreSSL -Scope 1

        PreFlight

        $TestURL = '{0}:{1}/subscriptions/' -f $URL,$Port
        Write-Verbose -Message "Constructed Connection URL: $TestURL"

        $Result = Invoke-WebRequest -Uri $TestURL -Headers $Headers -UseBasicParsing -ErrorVariable 'ErrCon'
        if ($Result) {
            Write-Verbose -Message 'Successfully connected'
            Set-Variable -Name PublicTenantAPIUrl -Value $URL -Scope 1
            Set-Variable -Name Port -Value $Port -Scope 1
        } else {
            Write-Verbose -Message 'Connection unsuccessfull' -Verbose
            Set-Variable -Name PublicTenantAPIUrl -Value $null -Scope 1
            Set-Variable -Name Port -Value $null -Scope 1
            throw $ErrCon
        }
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Get-WAPSubscription {
    <#
    .SYNOPSIS
        Retrieves Tenant User Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Name
        The Name of the subscription to be acquired.

    .PARAMETER Id
        The Id of the subscription to be acquired.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription'

        This will return the subscription with name 'MySubscription' if it exists.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription

        This will return a list of the users subscriptions.
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter(Mandatory, ParameterSetName='Id')]
        [ValidateNotNullOrEmpty()]
        [String] $Id,

        [Parameter(ParameterSetName='Current')]
        [Switch] $Current
    )

    try {
        if ($Current) {
            Write-Output -InputObject $Subscription
            break
        }

        if ($IgnoreSSL) {
            Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
            #Change Certificate Policy to ignore
            IgnoreSSL
        }
        PreFlight -IncludeConnection
        
        $URL = '{0}:{1}/subscriptions/' -f $PublicTenantAPIUrl,$Port
        Write-Verbose -Message "Constructed Subscription URL: $URL"

        $Subscriptions = Invoke-RestMethod -Uri $URL -Headers $Headers -Method Get

        foreach ($S in $Subscriptions) {
            if ($PSCmdlet.ParameterSetName -eq 'Name' -and $S.SubscriptionName -ne $Name) {
                continue
            }
            if ($PSCmdlet.ParameterSetName -eq 'Id' -and $S.SubscriptionId -ne $Id) {
                continue
            }
            $S.Created = [datetime]$S.Created
            Add-Member -InputObject $S -MemberType AliasProperty -Name 'Subscription' -Value SubscriptionId
            $S.PSObject.TypeNames.Insert(0,'WAP.Subscription')
            Write-Output -InputObject $S
        }
    } catch {
        Write-Error -ErrorRecord $_
    } finally {
        #Change Certificate Policy to the original
        if ($IgnoreSSL) {
            [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
        }
    }
}

function Select-WAPSubscription {
    <#
    .SYNOPSIS
        Selects User Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Subscription
        The subscription object acquired via Get-WAPSubscription.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription

        This will select the subscription 'MySubscription'.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [PSCustomObject] $Subscription
    )
    try {
        if ($input.count -gt 1) {
            throw 'Only 1 subscription can be selected. If passed from Get-WAPSubscription, make sure only 1 subscription object is passed on the pipeline'
        }

        if (!($Subscription.pstypenames.Contains('WAP.Subscription'))) {
            throw 'Object bound to Subscription parameter is of the wrong type'
        }
        Write-Verbose -Message "Setting current subscription to $($Subscription | Out-String)"
        Set-Variable -Name Subscription -Value $Subscription -Scope 1
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function GetWAPSubscriptionQuota {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('systemcenter','sqlservers')]
        [String] $Servicetype = 'sqlservers'
    )
    if ($Servicetype -eq 'systemcenter') {
        throw 'systemcenter type currently not supported'
    }
    if ($Servicetype -eq 'sqlservers') {
        PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer
        $BaseQuota = (Get-WAPSubscription -Id $Subscription.SubscriptionID | Select-Object -ExpandProperty Services | Where-Object -FilterScript {$_.Type -eq $Servicetype}).BaseQuotaSettings.Value | ConvertFrom-Json
        foreach ($B in $BaseQuota) {
            $B
        }
    }
    
}

function Get-WAPGalleryVMRole {
    <#
    .SYNOPSIS
        Retrieves VM Role Gallery Items asigned to Tenant user Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Name
        When Name is specified, only the VM Role Gallery Item with the specified name is returned.

    .PARAMETER Version
        When Version is specified, only the VM Role Gallery Item with the specified version is returned.
        
    .PARAMETER Publisher
        When Publisher is specified, only the VM Role Gallery Item with the specified Publisher is returned.


    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPGalleryVMRole

        This will retrieve all VM Role Gallery Items tight to the subscription.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPGalleryVMRole -Name 'MyAwesomeVMRole' -version '1.9.21.17'

        This will retreive only the VM Role Gallery Item with the same name as specified.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPGalleryVMRole -Name '*Awesome*' -version '1.9.21.17'

        This will retreive the VM Role Gallery Item(s) with the specified wildcard name and exact version.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPGalleryVMRole -version '1.9.21.17' -Publisher 'AwesomePublisher'

        This will retreive all the VM Role Gallery Item with the specified version and publisher. 
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [ValidateNotNullOrEmpty()]
        [String] $Version,

        [ValidateNotNullOrEmpty()]
        [String] $Publisher
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/Gallery/GalleryItems/$/MicrosoftCompute.VMRoleGalleryItem?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed Gallery Item URI: $URI"

            $GalleryItems = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

            foreach ($G in $GalleryItems.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $G.Name -notlike $Name) {
                    continue
                }
                if ($Version -and $G.Version -ne $Version) {
                    continue
                }
                if ($Publisher -and $G.Publisher -ne $Publisher) {
                    continue
                }
                $GIResDEFUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$G.ResourceDefinitionUrl
                Write-Verbose -Message "Acquiring ResDef from URI: $GIResDEFUri"
                $ResDef = Invoke-RestMethod -Uri $GIResDEFUri -Headers $Headers -Method Get

                $GIViewDefUri = '{0}:{1}/{2}/{3}/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$G.ViewDefinitionUrl
                Write-Verbose -Message "Acquiring ViewDef from URI: $GIResDEFUri"
                $ViewDef = Invoke-RestMethod -Uri $GIViewDefUri -Headers $Headers -Method Get

                Add-Member -InputObject $G -MemberType NoteProperty -Name ResDef -Value $ResDef
                Add-Member -InputObject $G -MemberType NoteProperty -Name ViewDef -Value $ViewDef

                $G.PublishDate = [datetime]$G.PublishDate
                $G.PSObject.TypeNames.Insert(0,$G.'odata.type')
                Write-Output -InputObject $G 
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
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

    .PARAMETER ViewDef
        The viewdef comes as a property of the VM Role gallery item.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$GI = Get-WAPGalleryVMRole -Name MyVMRole
        PS C:\>$GI | Get-WAPVMRoleOSDisk -Verbose
        
        This will fetch all compatible and enabled OS disks.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [PSCustomObject] $ViewDef
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualHardDisks' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VHD URI: $URI"

            $Sections = $ViewDef.ViewDefinition.Sections
            $Categories = $Sections | ForEach-Object -Process {$_.Categories}
            $OSDiskParam = $Categories | ForEach-Object -Process {$_.Parameters} | Where-Object -FilterScript {$_.Type -eq 'OSVirtualHardDisk'}

            $Images = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            Write-Verbose "Images are : $($Images.Value)"
            foreach ($I in $Images.value) {
                $Tags = $I.tag
                # We get all common tags between the library OS Disk tags and the VmRole requried tags.
                $CompareTags = Compare-Object -ReferenceObject $Tags -DifferenceObject $OSDiskParam.ImageTags -IncludeEqual -ExcludeDifferent -PassThru

                if ($null -ne $CompareTags) {
                    # If the common tags match perfectly all the Vmrole required tags, then we have a winner.
                    if ($null -eq (Compare-Object -ReferenceObject $CompareTags -DifferenceObject $OSDiskParam.ImageTags -PassThru)) {
                        if ($I.enabled -eq $false) {
                            continue
                        }
                        $I.AddedTime = [datetime] $I.AddedTime
                        $I.ModifiedTime = [datetime] $I.ModifiedTime
                        $I.ReleaseTime = [datetime] $I.ReleaseTime
                        $I.PSObject.TypeNames.Insert(0,'WAP.GI.OSDisk')
                        Write-Output -InputObject $I
                    } else {
                        continue
                    }
                }
                else
                {
                    continue
                }
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
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

    .PARAMETER Name
        When Name is specified, only the VM Network with the specified name is returned.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPVMNetwork

        This will fetch all VM Networks available to the subscription.
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMNetworks' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VM Networks URI: $URI"
            
            $VMNets = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
    
            foreach ($N in $VMNets.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $N.Name -ne $Name) {
                    continue
                }
                $N.PSObject.TypeNames.Insert(0,'WAP.VMNetwork')
                Write-Output -InputObject $N
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPVMNetworkSubnet {
     <#
    .SYNOPSIS
        Retrieves Subnets provisioned to specified VM Network.

    .PARAMETER VMNetwork
        VM Network object to be inquired. Acquired via Get-WAPVMNetwork.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPVMNetwork -Name testing1234 | Get-WAPVMNetworkSubnet

        This will fetch all subnets available to the testing1234 VM Network.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $VMNetwork
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($VMNetwork.pstypenames.Contains('WAP.VMNetwork'))) {
                throw 'Object bound to VMNetwork parameter is of the wrong type'
            }
            
            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMSubnets?$filter=StampId+eq+guid''{3}''+and+VMNetworkId+eq+guid''{4}''' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$VMNetwork.StampId,$VMNetwork.ID
            Write-Verbose -Message "Constructed VMNetwork Subnets URI: $URI"

            $Subnets = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get -ContentType application/json
    
            foreach ($S in $Subnets.value) {
                $S.PSObject.TypeNames.Insert(0,'WAP.Subnet')
                Write-Output -InputObject $S
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Set-WAPVMNetworkSubnetIPPool {
    <#
    .SYNOPSIS
        Configures IPPool Settings.

    .PARAMETER IPPool
        IPPool object to configure. Acquired via Get-WAPVMNetworkSubnetIPPool.

    .PARAMETER Name
        Configures the Name of the IPPool.

    .PARAMETER Description
        Configures the Description of the IPPool.
        Specify $Null to remove the current description.

    .PARAMETER DNSServers
        Configures the DNS servers of the IPPool.
        Specify an empty array @() when you want to clear the DNS servers from the IPPool.

    .PARAMETER DNSSuffix
        Configures the DNS suffix of the IPPool.
        Specify ([string]::empty) when you want to clear the DNS suffix from the IPPool.

    .PARAMETER DNSSearchSuffixes
        Configures the DNS Search Suffixes for the IPPool.
        Specify an empty array @() when you want to clear the DNS Search suffixes from the IPPool.

    .PARAMETER EnableNetBIOS
        Enables or Disables Netbios over TCP for the IPPool.

    .PARAMETER WINSServers
        Configures the WINS Servers for the IPPool.
        Specify an empty array @() when you want to clear the WINS Servers from the IPPool.

    .PARAMETER IPAddressReservedSet
        Configures reserved IP Addresses for the IPPool.
        Specify $Null to clear the reserved IP Addresses from the IPPool.
        Specify IPaddress-IPaddress to configure a range.
        Specify a comma separated list to configure multiple addresses and / or ranges.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$Subnet = Get-WAPVMNetwork -Name testing1234 | Get-WAPVMNetworkSubnet
        PS C:\>$Subnet | Set-WAPVMNetworkSubnetIPPool -DNSServers 10.10.10.10,10.10.10.11 -DNSSuffix lab.local

        This will configure the Subnet bound to VMNetwork 'testing1234' with DNSServers and a DNSSuffix.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $IPPool,

        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [AllowNull()]
        [String] $Description,

        [String[]] $DNSServers,
        
        [ValidateNotNull()]
        [String] $DNSSuffix,

        [String[]] $DNSSearchSuffixes,

        [Bool] $EnableNetBIOS,

        [String[]] $WINSServers,

        [AllowNull()]
        #Valid input Range: ip1-ip2
        #Valid input multiple: ip1,ip2,ip3-ip4
        [String] $IPAddressReservedSet
    )

    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($IPPool.pstypenames.Contains('WAP.IPPool'))) {
                throw 'Object bound to IPPool parameter is of the wrong type'
            }
            
            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/StaticIPAddressPools(ID=Guid''{3}'',StampId=Guid''{4}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$IPPool.Id,$IPPool.StampId
            Write-Verbose -Message "Constructed VMNetwork Subnet IPPool URI: $URI"

            [Void] $PSBoundParameters.Remove('Verbose')
            [Void] $PSBoundParameters.Remove('Debug')
            [Void] $PSBoundParameters.Remove('Whatif')
            [Void] $PSBoundParameters.Remove('IPPool')

            $Body = $PSBoundParameters | ConvertTo-Json
            if ($PSCmdlet.ShouldProcess($IPPool.Name)) {
                Invoke-RestMethod -Uri $URI -Headers $Headers -Method Put -Body $Body -ContentType application/json | Out-Null
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPVMNetworkSubnetIPPool {
    <#
    .SYNOPSIS
        Creates IPPool for a Subnet.

    .PARAMETER Subnet
        Subnet object to create IPPool for. Acquired via Get-WAPVMNetworkSubnet.

    .PARAMETER Name
        Configures the name for the IPPool.

    .PARAMETER IPAddressRangeStart
        By default this function uses the entire Subnet address space. If this parameter is specified, a custom address range can be specified for the IPPool.
        When specified, IPAddressRangeEnd must be specified as well.

    .PARAMETER IPAddressRangeEnd
        By default this function uses the entire Subnet address space. If this parameter is specified, a custom address range can be specified for the IPPool.
        When specified, IPAddressRangeStart must be specified as well.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$LNet = Get-WAPLogicalNetwork -Name 'PA Network'
        PS C:\>$VMNet = New-WAPVMNetwork -Name Next -LogicalNetwork $LNet -Verbose
        PS C:\>$Subnet = $VMNet | New-WAPVMNetworkSubnet -Name MySubnet -NoIPPool
        PS C:\>$Subnet | New-WAPVMNetworkSubnetIPPool -Name MyIPPool


        This will configure an IPPool bound the 'MySubnet' subnet.
    #>
    [CmdletBinding(DefaultParameterSetName='UnSpecified', SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName='Specified')]
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName='UnSpecified')]
        [ValidateNotNull()]
        [PSCustomObject] $Subnet,

        [Parameter(Mandatory, ParameterSetName='Specified')]
        [Parameter(Mandatory, ParameterSetName='UnSpecified')]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter(Mandatory, ParameterSetName='Specified')]
        [ipaddress] $IPAddressRangeStart,

        [Parameter(Mandatory, ParameterSetName='Specified')]
        [ipaddress] $IPAddressRangeEnd
    )

    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($Subnet.pstypenames.Contains('WAP.Subnet'))) {
                throw 'Object bound to Subnet parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription
            
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/StaticIPAddressPools' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VMNetwork Add Subnet IPPool URI: $URI"

            $Body = @{
                StampId = $Subnet.StampId;
                Name = $Name;
                Subnet = $Subnet.Subnet;
                VMSubnetId = $Subnet.ID;
            }

            if ($PSCmdlet.ParameterSetName -eq 'Specified') {
                $Body += @{
                    IPAddressRangeStart = $IPAddressRangeStart.IPAddressToString;
                    IPAddressRangeEnd = $IPAddressRangeEnd.IPAddressToString;
                }
            }
            $Body = $Body | ConvertTo-Json

            if ($PSCmdlet.ShouldProcess($Name)) {
                $IPPool = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $Body -ContentType application/json
                $IPPool.PSObject.TypeNames.Insert(0,'WAP.IPPool')
                Write-Output -InputObject $IPPool
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPVMNetworkSubnetIPPool {
    <#
    .SYNOPSIS
        Removes an IPPool from a Subnet.

    .PARAMETER IPPool
        IPPool object to remove. Acquired via Get-WAPVMNetworkSubnetIPPool.

    .PARAMETER Force
        When specified, confirmation prompt will not presented.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $IPPool,

        [Switch] $Force
    )

    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($IPPool.pstypenames.Contains('WAP.IPPool'))) {
                throw 'Object bound to IPPool parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription
            
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/StaticIPAddressPools(ID=Guid''{3}'',StampId=Guid''{4}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$IPPool.ID,$IPPool.StampId
            Write-Verbose -Message "Constructed VMNetwork Remove Subnet IPPool URI: $URI"

            if ($Force -or $PSCmdlet.ShouldProcess($IPPool.Name)) {
                Invoke-RestMethod -Uri $URI -Headers $Headers -Method Delete
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPVMNetworkSubnet {
    <#
    .SYNOPSIS
        Removes a Subnet from a VMNetwork.

    .PARAMETER IPPool
        Subnet object to remove. Acquired via Get-WAPVMNetworkSubnet.

    .PARAMETER Force
        When specified, confirmation prompt will not presented.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $Subnet,

        [Switch] $Force
    )

    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($Subnet.pstypenames.Contains('WAP.Subnet'))) {
                throw 'Object bound to Subnet parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription
            
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMSubnets(ID=Guid''{3}'',StampId=Guid''{4}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$Subnet.ID,$Subnet.StampId
            Write-Verbose -Message "Constructed VMNetwork Subnets URI: $URI"

            if ($Force -or $PSCmdlet.ShouldProcess($Subnet.Name)) {
                Invoke-RestMethod -Uri $URI -Headers $Headers -Method Delete
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }

}

function Get-WAPVMNetworkSubnetIPPool {
    <#
    .SYNOPSIS
        Gets an IPPool from a Subnet.

    .PARAMETER Subnet
        Subnet object to get IPPool from. Acquired via Get-WAPVMNetworkSubnet.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $Subnet
    )

    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($Subnet.pstypenames.Contains('WAP.Subnet'))) {
                throw 'Object bound to Subnet parameter is of the wrong type'
            }
            
            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/StaticIPAddressPools?$filter=StampId+eq+guid''{3}''+and+VMSubnetId+eq+guid''{4}''' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$Subnet.StampId,$Subnet.ID
            Write-Verbose -Message "Constructed VMNetwork Subnet IPPool URI: $URI"

            $IPPools = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($I in $IPPools.value) {
                $I.PSObject.Properties.Remove('odata.metadata')
                $I.PSObject.TypeNames.Insert(0,'WAP.IPPool')
                Write-Output -InputObject $I
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPVMNetworkSubnet {
    <#
    .SYNOPSIS
        Creates a Subnet for a VMNetwork.

    .PARAMETER VMNetwork

    .PARAMETER Name

    .PARAMETER NetworkAddress

    .PARAMETER NoIPPool

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $VMNetwork,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({if ($_.split('/').count -ne 2){$false} else {$true}})]
        [String] $NetworkAddress,

        [Switch] $NoIPPool
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($VMNetwork.pstypenames.Contains('WAP.VMNetwork'))) {
                throw 'Object bound to VMNetwork parameter is of the wrong type'
            }

            if ($VMNetwork.IsolationType -ne 'WindowsNetworkVirtualization') {
                throw 'New subnets can only be created on Network Virtualization enabled networks'
            }
            
            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMSubnets' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VMNetwork Add Subnet URI: $URI"

            $Body = @{
                Name = $Name + 'IPPool';
                StampId = $VMNetwork.StampId;
                Subnet = $NetworkAddress;
                VMNetworkId = $VMNetwork.ID;
            } | ConvertTo-Json

            if ($PSCmdlet.ShouldProcess($Name)) {
                $Subnet = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $Body -ContentType application/json
                $Subnet.PSObject.Properties.Remove('odata.metadata')
                $Subnet.PSObject.TypeNames.Insert(0,'WAP.Subnet')
                if (!$NoIPPool) {
                    $IPPool = $Subnet | New-WAPVMNetworkSubnetIPPool  -Name ($name + '-' + $Subscription.SubscriptionId)
                    Add-Member -InputObject $Subnet -MemberType NoteProperty -Name IPPool -Value $IPPool
                }
                Write-Output -InputObject $Subnet
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPLogicalNetwork {
    <#
    .SYNOPSIS
        Retrieves subscription available Logical Networks from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Name
        When Name is specified, only the VM Network with the specified name is returned.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPLogicalNetwork

        This will fetch all Logical Networks available to the subscription.
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Switch] $OnlyNetworkVirtualizationCapable
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/LogicalNetworks' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VMM Logical Networks URI: $URI"
            
            $LogicalNWs = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($L in $LogicalNWs.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $L.Name -ne $Name) {
                    continue
                }
                if ($OnlyNetworkVirtualizationCapable -and $L.NetworkVirtualizationEnabled -eq $false) {
                    continue
                }
                $L.PSObject.TypeNames.Insert(0,'WAP.LogicalNetwork')
                Write-Output -InputObject $L
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPVMNetwork {
    <#
    .SYNOPSIS
        Creates new VM Networks for the currently selected subscription.

    .PARAMETER Name
        A VM Network will be created using this name.

    .PARAMETER LogicalNetwork
        Logical Network Object to bind VM Network to.

    .PARAMETER AddressFamily
        VM Network can either be IPv4 (Default) or IPv6.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>New-WAPVMNetwork -Name MyNetwork

        This will create a new VM Network with name MyNetwork.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $LogicalNetwork,

        [ValidateNotNullOrEmpty()]
        [String] $Description
    )
    process {
        try {
            # // For now, this function can only create VM Networks of type NVGRE.
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($LogicalNetwork.pstypenames.Contains('WAP.LogicalNetwork'))) {
                throw 'Object bound to LogicalNetwork parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMNetworks' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VM Networks URI: $URI"

            $Body = @{
                Name = $Name
                StampId = $LogicalNetwork.StampId
                LogicalNetworkId = $LogicalNetwork.ID
            }
            
            if ($Description) {
                [void] $Body.Add('Description',$Description)
            }
            $Body = $Body | ConvertTo-Json

            if ($PSCmdlet.ShouldProcess($Name)) {
                $VMNet = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $Body -ContentType 'application/json'
                $VMNet.PSObject.Properties.Remove('odata.metadata')
                $VMNet.PSObject.TypeNames.Insert(0,'WAP.VMNetwork')
                Write-Output -InputObject $VMNet
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Grant-WAPVMNetworkAccess {
    <#
    .SYNOPSIS
        Grants VM Network access to other subscriptions.

    .PARAMETER VMNetwork
        VM Network object to grant access to. Acquired via Get-WAPVMNetwork.

    .PARAMETER GrantTo
        UserRole ID to to assign and share your network with.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$vnet = Get-WAPVMNetwork -Name MyNetwork
        PS C:\>$vnet | Grant-WAPVMNetworkAccess -GrantTo 'b.gelens@mydomain.local_87153e0d-450b-447c-8916-f51fa49b41d6'
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $VMNetwork,

        [Parameter(Mandatory)]
        [String] $GrantTo
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($VMNetwork.pstypenames.Contains('WAP.VMNetwork'))) {
                throw 'Object bound to LogicalNetwork parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription
            $Body = @{
                ID = $VMNetwork.ID
                StampId = $VMNetwork.StampId
                "GrantedToList@odata.type" = "Collection(VMM.UserAndRole)"
                GrantedToList = @(
                    @{
                        RoleName = $GrantTo
                    }
                )
            } | ConvertTo-Json
            Write-Verbose -Message "Sending Body: $($Body | Out-String)"
            $GrantURI = '{0}:{1}/{2}/services/systemcenter/vmm/VMNetworks(ID=guid''{3}'',StampId=guid''{4}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$VMNetwork.ID,$VMNetwork.StampId
            Write-Verbose -Message "Constructed Grant access VM Network URI: $GrantURI"

            if ($PSCmdlet.ShouldProcess($VMNetwork.Name)) {
                Invoke-RestMethod -Uri $GrantURI -Method Put -Headers $Headers -Body $Body -ContentType application/json | Out-Null
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPVMNetwork {
    <#
    .SYNOPSIS
        Removes VM Networks for the currently selected subscription.

    .PARAMETER VMNetwork
        VM Network object to be removed. Acquired via Get-WAPVMNetwork.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPVMNetwork -Name MyNetwork | Remove-WAPVMNetwork

        This will remove the VM Network with name MyNetwork.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [OutputType([Void])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $VMNetwork,

        [Switch] $RunAsynchronously,

        [Switch] $Force
    )
    #// TODO: for now, only support pipeline VMNetwork. Later support Name/ID?
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($VMNetwork.pstypenames.Contains('WAP.VMNetwork'))) {
                throw 'Object bound to LogicalNetwork parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $RemURI = '{0}:{1}/{2}/services/systemcenter/vmm/VMNetworks(ID=guid''{3}'',StampId=guid''{4}'')?RunAsynchronously=' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$VMNetwork.ID,$VMNetwork.StampId
            if ($RunAsynchronously) {
                $RemURI = $RemURI + '1'
            } else {
                $RemURI = $RemURI + '0'
            }
            Write-Verbose -Message "Constructed Remove VM Network URI: $RemURI"

            if ($Force -or $PSCmdlet.ShouldProcess($VMNetwork.Name)) {
                Invoke-RestMethod -Uri $RemURI -Method Delete -Headers $Headers | Out-Null
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
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
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$GI = Get-WAPGalleryVMRole -Name MyVMRole
        PS C:\>$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
        PS C:\>$NW = Get-WAPVMNetwork -Name MyNetwork
        PS C:\>$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW -Interactive

        This will run in interactive mode. It will prompt to fill in the blanks and accept defaults or provide own values.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$GI = Get-WAPGalleryVMRole -Name MyVMRole
        PS C:\>$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
        PS C:\>$NW = Get-WAPVMNetwork -Name MyNetwork
        PS C:\>$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
        PS C:\>$VMProps.MissingValue = 'MyValue'

        This will run in non-interactive mode. It will use defaults and assigns NULL if no default is available. Values can be assigned / overwritten.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject] $VMRole,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject] $OSDisk,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject] $VMRoleVMSize,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject] $VMNetwork,

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
    if (!($VMRoleVMSize.pstypenames.Contains('WAP.VMRoleSizeProfile'))) {
        throw 'Object bound to VMRoleVMSize parameter is of the wrong type'
    }
    if ($PSCmdlet.ShouldProcess($null,'Generating new ParameterObject')) {
        $Sections = $VMRole.ViewDef.ViewDefinition.Sections
        $Categories = $Sections | ForEach-Object -Process {$_.Categories}
        $ViewDefParams = $Categories | ForEach-Object -Process {$_.Parameters}
        $Output = [pscustomobject]@{}
        foreach ($P in $ViewDefParams) {
            $p | Out-String | Write-Verbose
            if ($Interactive -and $P.type -eq 'option') {
                $values = ''
                foreach ($v in $P.OptionValues) {
                    $Def = ($v | Get-Member -MemberType NoteProperty).Definition.Split(' ')[1].Split('=')
                    #$Friendly = $Def[1]
                    $Value = $Def[0] 
                    $values += $value + ','
                }
                $values = $values.TrimEnd(',')
                if ($P.DefaultValue) {
                    if(($result = Read-Host -Prompt "Press enter to accept default value $($P.DefaultValue) for $($P.Name). Valid entries: $values") -eq ''){
                        Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $P.DefaultValue -Force
                    } else {
                        do {
                            $result = Read-Host -Prompt "Enter one of the following entries: $values"
                        } while (@($values.Split(',')) -notcontains $result)
                        Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
                    }
                } else {
                    do {
                        $result = Read-Host -Prompt "Enter one of the following entries: $values"
                    } while (@($values.Split(',')) -notcontains $result)
                    Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
                }
            } elseif ($Interactive -and $P.type -eq 'Credential') {
                do {
                    $result = Read-Host -Prompt "Enter a credential for $($P.Name) in the format domain\username:password or username:password"
                } while ($result -notmatch '\w+\\+\w+:+\w+' -and $result -notmatch '\w+:+\w+')
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
            } elseif ($P.Type -eq 'OSVirtualHardDisk') {
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value "$($OSDisk.FamilyName):$($OSDisk.Release)" -Force
            } elseif ($P.Type -eq 'VMSize') {
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $VMRoleVMSize.Name -Force
            } elseif ($P.Type -eq 'Credential') {
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value 'domain\username:password' -Force
            } elseif ($P.Type -eq 'Network') {
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $($VMNetwork.Name) -Force
            } elseif ($P.DefaultValue) {
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $P.DefaultValue -Force
            } elseif ($Interactive) {
                $result = Read-Host -Prompt "Enter a value for $($P.Name) of type $($P.Type)"
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $result -Force
            } else {
                Add-Member -InputObject $Output -MemberType NoteProperty -Name $P.Name -Value $null -Force
            }
        }
        $Output.PSObject.TypeNames.Insert(0,'WAP.ParameterObject')
        Write-Output -InputObject $Output
    }  
}

function Get-WAPCloudService {
    <#
    .SYNOPSIS
        Retrieves Cloudservice deployed to subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Name
        When Name is specified, only the cloud service with the specified name is returned.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPCloudService

        This will retreive all provisioned cloud services for the specified subscription.
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Name')]
        [Alias('CloudServiceName')]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed CloudService URI: $URI"

            $CloudServices = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($C in $CloudServices.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $C.Name -ne $Name) {
                    continue
                }
                Add-Member -InputObject $C -MemberType AliasProperty -Name CloudServiceName -Value Name
                $C.PSObject.TypeNames.Insert(0,'WAP.CloudService')
                Write-Output -InputObject $C
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
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

    .PARAMETER Name
        The name of the cloud service to be provisioned. The name must be unique within the subscription.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>New-WAPCloudService -Name test

        This will provision a cloud service named test.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('CloudServiceName')]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            if ($PSCmdlet.ShouldProcess($Name)) {
                $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
                Write-Verbose -Message "Constructed CloudService URI: $URI"

                $CloudServiceConfig = @{
                    Name = $Name
                    Label = $Name
                } | ConvertTo-Json -Compress

                $CloudService = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $CloudServiceConfig -ContentType 'application/json'
                $CloudService.PSObject.Properties.Remove('odata.metadata')
                $CloudService.PSObject.TypeNames.Insert(0,'WAP.CloudService')
                Write-Output -InputObject $CloudService
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
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

    .PARAMETER Name
        The name of the cloud service to be removed.

    .PARAMETER Force
        If Force is not specified, removal is treated with confirm impact high.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Remove-WAPCloudService -Name test

        This will remove the cloudservice named test from the subscription. If a VM Role has been deployed to this cloud service, it will be removed as well.
        In this case, the user will be prompted to confirm the remove action as -Force or -Confirm:$false is not specified.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPCloudService -Name Test | Remove-WAPCloudService -Force

        This will remove the cloudservice named test from the subscription. If a VM Role has been deployed to this cloud service, it will be removed as well.
        In this case, the user is not prompted to confirm as -Force is specified.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Switch] $Force
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/CloudServices?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed CloudService URI: $URI"

            $CloudServices = Invoke-RestMethod -Uri $URI -Method Get -Headers $Headers
            foreach ($C in $CloudServices.value) {
                if ($C.Name -ne $Name) {
                    continue
                }
                $RemURI = '{0}:{1}/{2}/CloudServices/{3}?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$Name
                Write-Verbose -Message "Constructed Named CloudService URI: $RemURI"
                if ($Force -or $PSCmdlet.ShouldProcess($Name)) {
                    Invoke-RestMethod -Uri $RemURI -Method Delete -Headers $Headers | Out-Null
                }
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
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

    .PARAMETER CloudServiceName
        The name of the cloud service to provision to. If it does not exist, it will be created.

    .PARAMETER VMRole
        Object acquired with Get-WAPGalleryVMRole.

    .PARAMETER ParameterObject
        Object acquired with New-WAPVMRoleParameterObject.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>$GI = Get-WAPGalleryVMRole -Name DomainController
        PS C:\>$OSDisk = $GI | Get-WAPVMRoleOSDisk | Sort-Object -Property AddedTime -Descending | Select-Object -First 1
        PS C:\>$NW = Get-WAPVMNetwork -Name Private
        PS C:\>$VMProps = New-WAPVMRoleParameterObject -VMRole $GI -OSDisk $OSDisk -VMRoleVMSize Large -VMNetwork $NW
        PS C:\>$VMProps.DomainName = 'MyNewDomain.local'
        PS C:\>New-WAPVMRoleDeployment -VMRole $GI -ParameterObject $VMProps -CloudServiceName DCs -Verbose
    
        This will deploy a new VM Role based on the Gallery Item DomainController. It will link the VMs up to the Private network and uses the latest published OS Disk.
        The domain name for the VM Role will be 'MyNewDomain.local' and the VMs will be sided using the Large VM Profile.
        If the cloud service DCs does not yet exists, it will be created. If it does exist, it will be checked if it has the correct name and if no VM Roles have been deployed to it.
        This function mirrors portal functionality and therefore does not allow multiple VM Roles in one cloud service.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject] $VMRole,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject] $ParameterObject,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Name','VMRoleName')]
        [ValidateNotNullOrEmpty()]
        [String] $CloudServiceName
    )
    process {
        $ErrorActionPreference = 'Stop'
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($VMRole.pstypenames.Contains('MicrosoftCompute.VMRoleGalleryItem'))) {
                throw 'Object bound to VMRole parameter is of the wrong type'
            }

            if (!($ParameterObject.pstypenames.Contains('WAP.ParameterObject'))) {
                throw 'Object bound to ParameterObject parameter is of the wrong type'
            }

            $ParameterObject | Get-Member -MemberType Properties | ForEach-Object -Process {
                if ($null -eq $ParameterObject.($_.name)) {
                    throw "ParameterObject property: $($_.name) is NULL"
                }
            }

            PreFlight -IncludeConnection -IncludeSubscription

            if ($PSCmdlet.ShouldProcess($CloudServiceName)) {
                Write-Verbose -Message "Testing if Cloudservice $CloudServiceName exists"

                if (!(Get-WAPCloudService -Name $CloudServiceName)) {
                    Write-Verbose -Message "Creating Cloudservice $CloudServiceName as it does not yet exist"
                    New-WAPCloudService -Name $CloudServiceName | Out-Null
                    $New = $true
                } else {
                    $New = $false
                }
                
                if (!$New) {
                    Write-Verbose -Message "Testing if VMRole does not already exist within cloud service"
                    if (Get-WAPCloudService -Name $CloudServiceName | Get-WAPVMRole) {
                        throw "There is already a VMRole deployed to the CloudService $CloudServiceName. Because this function mimics portal experience, only one VM Role is allowed to exist per CloudService"
                    }  
                } 
                
                #Add ResDefConfig JSON to Dictionary
                $ResDefConfig = New-Object -TypeName 'System.Collections.Generic.Dictionary[String,Object]'
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
                $GIPayloadJSON = ConvertTo-Json -InputObject $GIPayload -Depth 10

                # Deploy VM Role to cloudservice
                $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles/?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$CloudServiceName
                Write-Verbose -Message "Constructed VMRole Deploy URI: $URI"

                Write-Verbose -Message "Starting deployment of VMRole $VMRoleName to CloudService $CloudServiceName"
                $Deploy = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $GIPayloadJSON -ContentType 'application/json'
                $Deploy.PSObject.TypeNames.Insert(0,'WAP.VMRole')
                Write-Output -InputObject $Deploy
            }            
        } catch {
            if ($New) {
                Get-WAPCloudService -Name $CloudServiceName | Remove-WAPCloudService -Force
            }
            Write-Error -ErrorRecord $_
        } finally {
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

    .PARAMETER CloudServiceName
        The name of the cloud service to get VM Role information from.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPCloudService -Name DCs | Get-WAPVMRole | select *

        This will get the VM Role provisioning information for the DCs cloud service deployment.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Name','VMRoleName')]
        [ValidateNotNullOrEmpty()]
        [String] $CloudServiceName
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$CloudServiceName
            Write-Verbose -Message "Constructed VMRole URI: $URI"

            $Roles = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($R in $Roles.value) {
                Add-Member -InputObject $R -MemberType NoteProperty -Name ParameterValues -Value ($R.ResourceConfiguration.ParameterValues | ConvertFrom-Json)
                Add-Member -InputObject $R -MemberType NoteProperty -Name ScaleOutSettings -Value $R.ResourceDefinition.IntrinsicSettings.ScaleOutSettings
                Add-Member -InputObject $R -MemberType NoteProperty -Name InstanceCount -Value $R.InstanceView.InstanceCount
                Add-Member -InputObject $R -MemberType NoteProperty -Name VMSize -Value $R.InstanceView.ResolvedResourceDefinition.IntrinsicSettings.HardwareProfile.VMSize
                $R.PSObject.TypeNames.Insert(0,'WAP.VMRole')
                Write-Output -InputObject $R
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPVMRoleVM {
    <#
    .SYNOPSIS
        Retrieves Deployed VM(s) information for the named CloudService from Azure Pack TenantPublic or Tenant API.

    .PARAMETER CloudServiceName
        The name of the cloud service to get VM information from.

    .PARAMETER ComputerName
        When ComputerName is specified, only the VM with the specified ComputerName is returned.

    .PARAMETER VMMEnhanced
        A switch to enhance VM Role VM data with selected data from VMM (OwnerUserName, CreationTime, DeploymentErrorInfo and VMStatus in VMM).
        This switch requires two additional URI requests, so this CmdLet might be slower when used in larger environments and hence is optional.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPCloudService -Name DCs | Get-WAPVMroleVM -VMMEnhanced | select *

        This will get the VM information and enhanced VMM information for the DCs cloud service deployment.
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Name','VMRoleName')]
        [ValidateNotNullOrEmpty()]
        [String] $CloudServiceName,

        [Parameter(ParameterSetName='ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String] $ComputerName,

        [Switch] $VMMEnhanced
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            # Note we copy the WAPack Tenant Portal behaviour where the $CloudServiceName and $VMRoleName are identical and there is only 1 VMRole per CloudService
            $URI = '{0}:{1}/{2}/CloudServices/{3}/Resources/MicrosoftCompute/VMRoles/{3}/VMs?api-version=2013-03' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$CloudServiceName
            Write-Verbose -Message "Constructed VMRole URI: $URI"

            $VMs = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

            $StampId=(Get-WAPCloud).StampId

            foreach ($V in $VMs.value) {
                if ($PSCmdlet.ParameterSetName -eq 'ComputerName' -and $V.ComputerName -ne $ComputerName) {
                    continue
                }
                Add-Member -InputObject $V -MemberType NoteProperty -Name StampId -Value $StampId
                Add-Member -InputObject $V -MemberType NoteProperty -Name IPAddress -Value $V.ConnectToAddresses.IPAddress
                Add-Member -InputObject $V -MemberType NoteProperty -Name NetworkName -Value $V.ConnectToAddresses.NetworkName
                Add-Member -InputObject $V -MemberType NoteProperty -Name ParentCloudServiceName -Value $CloudServiceName
                if ($VMMEnhanced) {
                    $VMMURI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualMachines(ID=guid''{{{3}}}'',StampId=guid''{{{4}}}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$V.Id,$StampId
                    Write-Verbose -Message "Constructed VMM URI: $VMMURI"
                    
                    $VMMVM = Invoke-RestMethod -Uri $VMMURI -Headers $Headers -Method Get                    

                    Add-Member -InputObject $V -MemberType NoteProperty -Name VMMOwnerUserName -Value $VMMVM.Owner.UserName
                    Add-Member -InputObject $V -MemberType NoteProperty -Name VMMCreationTime -Value ([datetime]$VMMVM.CreationTime)
                    Add-Member -InputObject $V -MemberType NoteProperty -Name VMMDeploymentErrorInfo -Value $VMMVM.DeploymentErrorInfo
                    Add-Member -InputObject $V -MemberType NoteProperty -Name VMMStatus -Value $VMMVM.Status
                }
                $V.PSObject.TypeNames.Insert(0,'WAP.VM')
                Write-Output -InputObject $V
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPVM {
    <#
    .SYNOPSIS
        Retrieves Deployed VM(s).

    .PARAMETER ComputerName
        When ComputerName is specified, only the VM with the specified ComputerName is returned.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPVM

        This will get the VM information
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(ParameterSetName='ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String] $ComputerName
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualMachines()?$expand=VirtualNetworkAdapters,VirtualDVDDrives,VirtualDiskDrives,VirtualHardDisks' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VM URI: $URI"

            $VMs = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

            foreach ($V in $VMs.value) {
                if ($PSCmdlet.ParameterSetName -eq 'ComputerName' -and $V.ComputerName -ne $ComputerName) {
                    continue
                }
                Add-Member -InputObject $V -MemberType AliasProperty -Name RuntimeState -Value VirtualMachineState
                $NICs = $V | Select-Object -ExpandProperty virtualnetworkadapters
                $IPAddress = @()
                $ConnectToAddresses = @()
                foreach ($N in $NICs) {
                    if ($null -ne $N.IPv4Addresses) {
                        foreach ($IP in $N.IPv4Addresses) {
                            $IPAddress += $IP
                            $ConnectToAddresses += [PSCustomObject]@{
                                IPAddress = $IP
                                NetworkName = $N.VMNetworkName
                                Port = '3389'
                            }
                        } 
                    }
                    if ($null -ne $N.IPv6Addresses) {
                        foreach ($IP in $N.IPv6Addresses) {
                            $IPAddress += $IP
                            $ConnectToAddresses += [PSCustomObject]@{
                                IPAddress = $IP
                                NetworkName = $N.VMNetworkName
                                Port = '3389'
                            }
                        }
                    }
                }
                Add-Member -InputObject $V -MemberType NoteProperty -Name IPAddress -Value $IPAddress
                Add-Member -InputObject $V -MemberType NoteProperty -Name ConnectToAddresses -Value $ConnectToAddresses
                $V.PSObject.TypeNames.Insert(0,'WAP.VM')
                Write-Output -InputObject $V
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Start-WAPVM {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $VM
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            # VMRoleVM and normal VM now have same typename but need different URL
            if (!($VM.pstypenames.Contains('WAP.VM'))) {
                throw 'Object bound to VM parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $Body = @{
                Operation = 'Start'
            } | ConvertTo-Json

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualMachines(ID=guid''{3}'',StampId=guid''{4}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$VM.ID,$VM.StampId
            Write-Verbose -Message "Constructed VM Start URI: $URI"

            Invoke-RestMethod -Uri $URI -Headers $Headers -Method Put -Body $Body -ContentType application/json | Out-Null
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Stop-WAPVM {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [OutputType([void])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()][PSCustomObject] $VM,

        [Switch] $RunAsynchronously,

        [Switch] $TurnOff,

        [Switch] $Force
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            if (!($VM.pstypenames.Contains('WAP.VM'))) {
                throw 'Object bound to VM parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription

            if ($TurnOff) {
                $operation = 'Stop'
            } else {
                $operation = 'Shutdown'
            }

            $Body = @{
                Operation = $operation
            } | ConvertTo-Json
            
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualMachines(ID=guid''{3}'',StampId=guid''{4}'')' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$VM.ID,$VM.StampId
            if ($RunAsynchronously) {
                $URI = $URI + '?RunAsynchronously=1'
            }

            Write-Verbose -Message "Constructed VM Start URI: $URI"
            if ($Force -or $PSCmdlet.ShouldProcess($VM.ComputerName)) {
                Invoke-RestMethod -Uri $URI -Headers $Headers -Method Put -Body $Body -ContentType application/json | Out-Null
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPCloud {
    <#
    .SYNOPSIS
        Retrieves VMM Cloud information for the selected Subscription from Azure Pack TenantPublic or Tenant API.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPCloud

        This will get the VMM Cloud information (CloudId, CloudName and StampId) for the selected subscription
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (

    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription
            
            $VMMURIClouds = '{0}:{1}/{2}/services/systemcenter/vmm/Clouds' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VMMCloud URI: $VMMURIClouds"
            
            $VMMClouds = Invoke-RestMethod -Uri $VMMURIClouds -Headers $Headers -Method Get
            
            # Note that technically only 1 cloud can be returned per subscription in Windows Azure Pack, foreach > just to be sure
            foreach ($C in $VMMClouds.value) {
                $C.PSObject.TypeNames.Insert(0,'VMM.Clouds')
                Write-Output -InputObject $C
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Connect-WAPVMRDP {
    <#
    .SYNOPSIS
        Launches MSTSC connecting to VM using VM available information.

    .PARAMETER VM
        A VM Object returned by Get-WAPVMRoleVM.

    .PARAMETER IPv6
        IPv4 connection is used by default. If IPv6 is desired instead, use this switch.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPCloudService -Name DCs | Get-WAPVMRoleVM | Connect-WAPVMRDP

        This will launch MSTSC for each VM deployed in the VM Role DCs.
    #>
    [CmdletBinding()]
    [OutputType([void],[System.String])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $VM,

        [Switch] $IPv6
    )
    process {
        try {
            if (!($VM.pstypenames.Contains('WAP.VM'))) {
                throw 'Object bound to VM parameter is of the wrong type'
            }
            if ($null -eq $VM.ConnectToAddresses) {
                throw 'Unable to find VM Connection Information'
            }
            if ($IPv6) {
                $ConnectionParameters = $vm.ConnectToAddresses | Where-Object -FilterScript {([ipaddress]$_.ipaddress).IsIPv6LinkLocal -or ([ipaddress]$_.ipaddress).IsIPv6SiteLocal}
            } else {
                $ConnectionParameters = $vm.ConnectToAddresses | Where-Object -FilterScript {(!([ipaddress]$_.ipaddress).IsIPv6LinkLocal) -and (!([ipaddress]$_.ipaddress).IsIPv6SiteLocal)}
            }
            if ($ConnectionParameters -is [array]) {
                Write-Warning -Message 'Multiple connection posibilities, choose the desired one:'
                do {
                    for ($i = 0; $i -lt $ConnectionParameters.count; $i++) {
                        "$i`: $($ConnectionParameters[$i].IPAddress) $($ConnectionParameters[$i].Port)"
                    }
                    $Choice = Read-Host -Prompt 'Select desired connection:'
                } until ($null -ne $ConnectionParameters[$Choice])
                $ConnectionParameters = $ConnectionParameters[$Choice]
            }
            if ($null -eq $ConnectionParameters) {
                throw 'No valid connection parameters where discovered'
            }
            Start-Process -FilePath "$($env:SystemRoot)\system32\mstsc.exe" -ArgumentList "/V:$($ConnectionParameters.IPAddress):$($ConnectionParameters.Port)" -WindowStyle Normal | Out-Null
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Get-WAPVMRoleVMSize {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription
            
            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMRoleSizeProfiles' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VMRoleSizeProfiles URI: $URI"
            $Profiles = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

            foreach ($P in $Profiles.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $P.Name -ne $Name) {
                    continue
                }
                $P.PSObject.TypeNames.Insert(0,'WAP.VMRoleSizeProfile')
                Write-Output -InputObject $P
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
    
}

function Get-WAPVMTemplate {
    <#
    .SYNOPSIS
        Retrieves VM Template Items asigned to Tenant user Subscription from Azure Pack TenantPublic or Tenant API.

    .PARAMETER Name
        When Name is specified, only the VM Template Item with the specified name is returned.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPVMTemplate

        This will retrieve all VM Template Items tight to the subscription.

    .EXAMPLE
        PS C:\>$URL = 'https://publictenantapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-WAPToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-WAPAPI -URL $URL
        PS C:\>Get-WAPSubscription -Name 'MySubscription' | Select-WAPSubscription
        PS C:\>Get-WAPVMTemplate -Name 'MyAwesomeVMTemplate'

        This will retreive only the VM Template Item with the same name as specified.
    #>
    [CmdletBinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VMTemplates' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId
            Write-Verbose -Message "Constructed VMTemplate Item URI: $URI"

            $TemplateItems = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($T in $TemplateItems.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $T.Name -ne $Name) {
                    continue
                }
                $T.PSObject.TypeNames.Insert(0,'WAP.VMTemplate')
                Write-Output -InputObject $T 
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPVM {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.PSTypeName('WAP.VMTemplate')] $Template,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSTypeName('VMM.Clouds')] $Cloud,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSTypeName('WAP.VMNetwork')] $VMNetwork,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter(Mandatory)]
        [PSCredential] $Credential,

        [Switch] $RunAsynchronously,

        [Switch] $StartVM
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            $URI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualMachines?RunAsynchronously=' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId
            if ($RunAsynchronously) {
                $URI = $URI + '1'
            } else {
                $URI = $URI + '0'
            }
            Write-Verbose -Message "Constructed VM Deploy URI: $URI"
            #https://msdn.microsoft.com/en-us/library/jj643289.aspx
            #https://msdn.microsoft.com/en-us/library/dn470013.aspx
            
            $Body = @{
                StampId = $Template.StampId
                Name = $Name
                CloudId = $Cloud.Id
                VMTemplateId = $Template.ID
                ComputerName = $Name
                LocalAdminUserName = $Credential.UserName
                LocalAdminPassword = $Credential.GetNetworkCredential().Password
                NewVirtualNetworkAdapterInput = @(
                    @{
                        VMNetworkName  = $VMNetwork.Name
                    }
                )
            }

            if ($StartVM) {
                [void] $Body.Add('StartVM',$true)
            } else {
                [void] $Body.Add('StartVM',$false)
            }

            
            $Body = $Body | ConvertTo-Json -Depth 100

            Write-Verbose -Message "Constructed body: $($Body | Out-String)"

            if ($PSCmdlet.ShouldProcess($Name)) {
                $VM = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $Body -ContentType application/json
                $VM.PSObject.TypeNames.Insert(0,'WAP.VM')
                Write-Output -InputObject $VM
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPVM {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.VM')] $VM,

        [Switch] $Force,

        [Switch] $RunAsynchronously
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $RemURI = '{0}:{1}/{2}/services/systemcenter/vmm/VirtualMachines(ID=guid''{3}'',StampId=guid''{4}'')?RunAsynchronously=' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$VM.ID,$VM.StampId
            if ($RunAsynchronously) {
                $RemURI = $RemURI + '1'
            } else {
                $RemURI = $RemURI + '0'
            }
            Write-Verbose -Message "Constructed Remove VM URI: $RemURI"

            if ($Force -or $PSCmdlet.ShouldProcess($VM.Name)) {
                if ($VM.Status -eq 'Running') {
                    $VM | Stop-WAPVM -TurnOff -Force
                }
                Invoke-RestMethod -Uri $RemURI -Method Delete -Headers $Headers | Out-Null
            }

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

#region Admin functions
function Get-WAPAdminSubscription {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Id')]
        [ValidateNotNullOrEmpty()]
        [String] $SubscriptionId
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection

            if ($SubscriptionId) {
                $URI = '{0}:{1}/subscriptions/{2}' -f $PublicTenantAPIUrl,$Port,$SubscriptionId
            } else {
                $URI = '{0}:{1}/subscriptions' -f $PublicTenantAPIUrl,$Port
            }
            Write-Verbose -Message "Constructed Subscription URI: $URI"
            $Subscriptions = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

            if ($SubscriptionId) {
                $Subscriptions.PSObject.TypeNames.Insert(0,'WAP.AdminSubscription')
                Write-Output -InputObject $Subscriptions
            } else {
                foreach ($S in $Subscriptions.Items) {
                    $S.PSObject.TypeNames.Insert(0,'WAP.AdminSubscription')
                    Write-Output -InputObject $S
                }
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPAdminCloud {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/VMM/Microsoft.Management.Odata.svc/Clouds()' -f $script:PublicTenantAPIUrl,$script:Port
            Write-Verbose -Message "Constructed Cloud URI: $URI"

            $Clouds = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($C in $Clouds.Value) {
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $C.Name -ne $Name) {
                    continue
                }
                $C.PSObject.TypeNames.Insert(0,'WAP.AdminCloud')
                Write-Output -InputObject $C
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}
#endregion Admin functions

#region SQL DB
function Get-WAPSQLDatabase {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer
            
            $URI = '{0}:{1}/{2}/services/sqlservers/databases' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed SQL Database URI: $URI"
            $Databases = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get
            foreach ($D in $Databases) {
                if ($D.Edition -ne $SQLOffer.Edition) {
                    continue
                }
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $D.Name -ne $Name) {
                    continue
                }
                $D.PSObject.TypeNames.Insert(0,'WAP.SQLDatabase')
                Write-Output -InputObject $D
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
    
}

function Get-WAPSQLOffer {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory, ParameterSetName='Named',ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Switch] $Current
    )
    process {
        try {
            if ($Current) {
                Write-Output -InputObject $SQLOffer
                break
            }

            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/sqlservers' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed SQL Offer URI: $URI"

            $Offers = (Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get).QuotaSettings.value | ConvertFrom-Json
            foreach ($O in $Offers) {
                Write-Verbose -Message "Processing: $O"
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $O.displayName -ne $Name) {
                    continue
                }
                $O = $O | Add-Member -MemberType AliasProperty -Name Edition -Value displayName -PassThru
                $O.PSObject.TypeNames.Insert(0,'WAP.SQLOffer')
                Write-Output -InputObject $O
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
    
}

function Select-WAPSQLOffer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject] $Offer
    )
    try {
        if ($input.count -gt 1) {
            throw 'Only 1 Offer can be selected. If passed from Get-WAPSQLOffer, make sure only 1 offer object is passed on the pipeline'
        }

        if (!($Offer.pstypenames.Contains('WAP.SQLOffer'))) {
            throw 'Object bound to Offer parameter is of the wrong type'
        }
        Write-Verbose -Message "Setting current Offer to $($Offer | Out-String)"
        Set-Variable -Name SQLOffer -Value $Offer -Scope 1
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Test-WAPSQLDatabaseNameAvailable {
    [OutputType([Bool])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer

            $URI = '{0}:{1}/{2}/services/sqlservers/databases?Validate=True' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed SQL Database URI: $URI"

            $DBCheck = @{
                Name = $Name
                SubscriptionId = $null
                BaseSizeMB = 0
                MaxSizeMB = 0
                Edition = $null
                Collation = $null
                IsContained = $null
            } | ConvertTo-Json -Compress

            Write-Verbose -Message "Constructed Body: $($DBCheck | Out-String)"

            $Test = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $DBCheck -ContentType 'application/json'
            if ($Test) {
                Write-Output -InputObject $true
            }
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Continue
            Write-Output -InputObject $false
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPSQLDatabase {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter(Mandatory, ParameterSetName='SQLAuth')]
        [PSCredential] 
        [System.Management.Automation.CredentialAttribute()] $Credential,

        [ValidateSet('SQL_Latin1_General_CP1_CI_AS','Latin1_General_CI_AI','Latin1_General_CI_AS','Latin1_General_CS_AI')]
        [String] $Collation = 'SQL_Latin1_General_CP1_CI_AS',

        [Parameter(ParameterSetName='WindowsAuth')]
        [Switch] $WindowsAuthentication,

        [Parameter(ParameterSetName='WindowsAuth')]
        [ValidateNotNullOrEmpty()]
        [String] $WindowsAccount
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer

            $URI = '{0}:{1}/{2}/services/sqlservers/databases' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId
            Write-Verbose -Message "Constructed SQL Database URI: $URI"

            $Quota = GetWAPSubscriptionQuota -Servicetype sqlservers | Where-Object -FilterScript {$_.groupName -eq $SQLOffer.groupName}

            $DBConfig = @{
                Name = $Name
                BaseSizeMB = $Quota.resourceSize
                MaxSizeMB = $Quota.resourceSize
                Edition = $SQLOffer.Edition
                Collation = $Collation
                SubscriptionId = $Subscription.SubscriptionID
                IsContained = $true
            } 
            if ($WindowsAuthentication) {
                if ($Quota.supportedAuthenticationModes -eq 3) {
                    $DBConfig.Add('AuthenticationMode','Windows')
                    $DBConfig.Add('AdminLogon',$WindowsAccount)
                } else {
                    throw "SQL Offer $($SQLOffer.Edition) does not support Windows Authentication"
                }
            } else {
                $DBConfig.Add('Password', $Credential.GetNetworkCredential().Password)
                $DBConfig.Add('AdminLogon', $Credential.UserName)
            }
            $DBConfig = $DBConfig | ConvertTo-Json -Compress

            Write-Verbose -Message "Constructed Body: $($DBConfig | Out-String)"

            if ($PSCmdlet.ShouldProcess($Name)) {
                $DB = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Post -Body $DBConfig -ContentType 'application/json'
                $DB.PSObject.TypeNames.Insert(0,'WAP.SQLDatabase')
                Write-Output -InputObject $DB
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Reset-WAPSQLDatabaseAdmin {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $Database,

        [PSCredential] 
        [System.Management.Automation.CredentialAttribute()] $Credential
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer
            
            if ($Database.AuthenticationMode -eq 1) {
                throw "Database authentication for $($Database.Name) is of type Windows and cannot be reset"
            }

            $URI = '{0}:{1}/{2}/services/sqlservers/databases/{3}' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$Database.Name
            Write-Verbose -Message "Constructed SQL Database URI: $URI"

            if (-not $Credential) {
                $Credential = Get-Credential -UserName $Database.AdminLogon -Message 'Reset your password'
            }

            $DBConfig = @{
                Name = $Database.Name
                BaseSizeMB = $Database.BaseSizeMB
                MaxSizeMB = $Database.MaxSizeMB
                Edition = $null
                Collation = $null
                SubscriptionId = $Subscription.SubscriptionID
                IsContained = $null
                AdminLogon = $Database.AdminLogon
                Password = $Credential.GetNetworkCredential().Password
            } | ConvertTo-Json -Compress

            Write-Verbose -Message "Constructed Body: $($DBConfig | Out-String)"

            if ($PSCmdlet.ShouldProcess($Database.Name)) {
                $DB = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Put -Body $DBConfig -ContentType 'application/json'
                $DB.PSObject.TypeNames.Insert(0,'WAP.SQLDatabase')
                Write-Output -InputObject $DB
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Resize-WAPSQLDatabase {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject] $Database,

        #Dynamic param?
        [Parameter(Mandatory)]
        [uint16] $SizeMB
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            if (!($Database.pstypenames.Contains('WAP.SQLDatabase'))) {
                throw 'Object bound to Database parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer
            
            if ($SizeMB -lt $Database.BaseSizeMB) {
                throw "Value specified $SizeMB is less then the minimum size of the database $($Database.BaseSizeMB)"
            }
            
            if ($SizeMB -gt $Database.Quota) {
                throw "Value specified $SizeMB is greater then the maximum size of the database $($Database.Quota)"
            }

            if ($PSCmdlet.ShouldProcess($Database.Name)) {
                $URI = '{0}:{1}/{2}/services/sqlservers/databases/{3}' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$Database.Name
                Write-Verbose -Message "Constructed SQL Database URI: $URI"

                $DBConfig = @{
                    Name = $Database.Name
                    BaseSizeMB = $Database.BaseSizeMB
                    MaxSizeMB = $SizeMB
                    Edition = $null
                    AdminLogon = $null
                    Collation = $null
                    Password = $null
                    SubscriptionId = $Subscription.SubscriptionID
                    IsContained = $null
                } | ConvertTo-Json -Compress

                Write-Verbose -Message "Constructed Body: $($DBConfig | Out-String)"

                $DB = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Put -Body $DBConfig -ContentType 'application/json'
                $DB.PSObject.TypeNames.Insert(0,'WAP.SQLDatabase')
                Write-Output -InputObject $DB
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPSQLDatabase {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSCustomobject] $Database,

        [Switch] $Force
    )
    process {
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            if (!($Database.pstypenames.Contains('WAP.SQLDatabase'))) {
                throw 'Object bound to Database parameter is of the wrong type'
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeSQLOffer

            $URI = '{0}:{1}/{2}/services/sqlservers/databases/{3}' -f $PublicTenantAPIUrl,$Port,$Subscription.SubscriptionId,$Database.Name
            Write-Verbose -Message "Constructed Database URI: $URI"

            if ($Force -or $PSCmdlet.ShouldProcess($Database.Name)) {
                Invoke-RestMethod -Uri $URI -Headers $Headers -Method Delete
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
            }
        }
    }
}
#endregion SQL DB

#region Websites
function Get-WAPWebSpace {
    [cmdletbinding()]
    [OutputType([PSCustomObject])]
    param (
        # // TODO: Add Name param and logic
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/WebSpaces' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId
            Write-Verbose -Message "Constructed WebSpace URI: $URI"

            $Spaces = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($S in $Spaces) {
                $S.PSObject.TypeNames.Insert(0,'WAP.WebSpace')
                Write-Output -InputObject $S
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Select-WAPWebSpace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [PSCustomObject] $WebSpace
    )
    try {
        if ($input.count -gt 1) {
            throw 'Only 1 WebSpace can be selected. If passed from Get-WAPWebSpace, make sure only 1 WebSpace object is passed on the pipeline'
        }

        if (!($WebSpace.pstypenames.Contains('WAP.WebSpace'))) {
            throw 'Object bound to WebSpace parameter is of the wrong type'
        }
        Write-Verbose -Message "Setting current WebSpace to $($WebSpace | Out-String)"
        Set-Variable -Name WebSpace -Value $WebSpace -Scope 1
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Test-WAPWebSiteNameAvailable {
    [cmdletbinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            PreFlight -IncludeConnection -IncludeSubscription

            $URI = '{0}:{1}/{2}/services/WebSpaces?ishostnameavailable={3}' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$Name
            Write-Verbose -Message "Constructed WebSite Name validation URI: $URI"

            Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPWebSite {
    [cmdletbinding(DefaultParameterSetName='List')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace
            
            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            $WebSites = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($W in $WebSites) {
                if ($PSCmdlet.ParameterSetName -eq 'Name' -and $W.Name -ne $Name) {
                    continue
                } else {
                    $W.PSObject.TypeNames.Insert(0,'WAP.WebSite')
                    Write-Output -InputObject $W
                }
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPWebSite {
    [cmdletbinding()]
    [outputtype([pscustomobject])]
    param (
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,
        
        [ValidateSet('SharedFree','SharedBasic','Dedicated')]
        [string] $Mode = 'SharedFree'
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace
            
            if (!(Test-WAPWebSiteNameAvailable -Name $Name)) {
                throw ('WebSite Name {0} is not available' -f $Name)
            }

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            $WebSiteConfig = @{
                Name = $Name
                ComputeMode = if ($Mode -eq 'SharedFree' -or $Mode -eq 'SharedBasic') {[int64]0} else {[int64]1}
                'WebspaceToCreate.GeoRegion' = $script:WebSpace.GeoRegion
                'WebspaceToCreate.Name' = $script:WebSpace.Name
                'WebspaceToCreate.Plan' = 'VirtualDedicatedPlan'
            } 
            if ($Mode -eq 'SharedFree') {
                $WebSiteConfig.Add('SiteMode','Limited')
            } elseif ($Mode -eq 'SharedBasic') {
                $WebSiteConfig.Add('SiteMode','Basic')
            }
            
            $WebSiteConfig = $WebSiteConfig | ConvertTo-Json -Compress

            Write-Verbose -Message "Constructed Body: $($WebSiteConfig | Out-String)"

            $W = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Post -Body $WebSiteConfig -ContentType 'application/json'
            $W.PSObject.TypeNames.Insert(0,'WAP.WebSite')
            Write-Output -InputObject $W
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPWebSite {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website,

        [Switch] $Force
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}?skipDnsRegistration=true' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            if ($Force -or $PSCmdlet.ShouldProcess($Website.Name)) {
                Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Delete
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPWebSiteConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}/config' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            $W = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            $W.PSObject.TypeNames.Insert(0,'WAP.WebSiteConfiguration')
            Write-Output -InputObject $W
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPWebSitePublishingXML {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website,
 
        [string] $OutFile
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}/publishxml' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            $XML = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get

            if ($OutFile) {
                $XML | Out-File -FilePath $OutFile -Force
            }
            Write-Output -InputObject $XML
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Restart-WAPWebSite {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}/restart' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Post
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPWebSiteGitRepository {
    [cmdletbinding()]
    [outputtype([system.string])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}/repository' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get -ContentType 'application/json'
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function New-WAPWebSiteGitRepository {
    [cmdletbinding()]
    [outputtype([void],[System.String])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website,

        [switch] $PassThru
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}/repository' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            $null = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Post -ContentType 'application/json'
            if ($PassThru) {
                $Website | Get-WAPWebSiteGitRepository
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Remove-WAPWebSiteGitRepository {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website,

        [Switch] $Force
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = '{0}:{1}/{2}/services/WebSpaces/{3}/sites/{4}/repository' -f $script:PublicTenantAPIUrl,$script:Port,$script:Subscription.SubscriptionId,$script:WebSpace.Name,$Website.Name
            Write-Verbose -Message "Constructed WebSite URI: $URI"

            if ($Force -or $PSCmdlet.ShouldProcess($Website.Name)) {
                Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Delete
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Get-WAPWebSitePublishingInfo {
    [cmdletbinding()]
    [outputtype([pscustomobject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.WebSite')] $Website
    )
    process {
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            PreFlight -IncludeConnection -IncludeSubscription -IncludeWebSpace

            $URI = $Website.SelfLink + '?propertiesToInclude=RepositoryUri,PublishingUsername,PublishingPassword,Metadata,ScmType'
            Write-Verbose -Message "Constructed WebSite URI: $URI"
            
            (Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get).SiteProperties.Properties

        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

#endregion

Export-ModuleMember -Function *-WAP*
Export-ModuleMember -Variable Token,Headers,PublicTenantAPIUrl,Port,IgnoreSSL,Subscription 

